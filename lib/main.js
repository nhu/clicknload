const http = require('http');
const url = require('url');
const queryString = require('querystring');
const { StringDecoder } = require('string_decoder');
const vm = require('vm');
const crypto = require('crypto');
const argv = require('yargs')
    .default('port', 9666)
    .default('host', '127.0.0.1')
    .alias('p', 'port')
    .alias('h', 'host')
    .argv;


class LinkCollection {
    constructor(name, urls) {
        this.name = name;
        this.urls = urls;
    }
}

class CollectorSession {
    constructor() {
        this.collections = [];
    }

    add(collection) {
        this.collections.push(collection);
    }
    
    clear() {
        this.collections.splice(0);
    }
}

class ClickNLoadServer {

    constructor(port, host) {
        this._port = port;
        this._host = host;
        this._httpServer = undefined;
        this._collectorSession = new CollectorSession();
    }

    start() {
        this._httpServer = http.createServer();
        this._httpServer.on('request', (request, response) => this._handleRequest(request, response));
        this._httpServer.listen(this._port, this._host);
        console.log(`Server is listening on ${this._host} on port ${this._port}`);
    }

    _handleRequest(request, response) {
        console.log(`Incoming request... (Method: ${request.method}, Url: ${request.url} )`);
        const routes = this._createRoutes();
        const route = routes.find((x) => x.path === request.url && x.method === request.method);
        if(route == undefined){
            console.log(`No route found for ${request.url} using ${request.method} verb`);
            response.writeHead(404);
            response.end();
        }
        else {
            console.log(`Route found for ${request.url} using ${request.method} verb`);
            route.handler(request, response);
        }
    }

    _createRoutes() {
        const routes = [];
        routes.push({ path: '/', method: 'GET', handler: this._aliveRouteHandler.bind(this) });
        routes.push({ path: '/jdcheck.js', method: 'GET', handler: this._checkRouteHandler.bind(this) });
        routes.push({ path: '/crossdomain.xml', method: 'GET', handler: this._crossDomainRouteHandler.bind(this) });
        routes.push({ path: '/flash/add', method: 'POST', handler: this._flashAddRouteHandler.bind(this) });
        routes.push({ path: '/flash/addcrypted2', method: 'POST', handler: this._flashAddCrypted2RouteHandler.bind(this) });
        routes.push({ path: '/collector', method: 'GET', handler: this._collectorRouteHandler.bind(this) });
        return routes;
    }

    _aliveRouteHandler(request, response) {
        response.writeHead(200);
        response.end('JDownloader');
    }

    _checkRouteHandler(request, response) {
        response.writeHead(200);
        response.end("jdownloader=true; var version='17461';");
    }

    _crossDomainRouteHandler(request, response) {
        response.writeHead(200);
        response.end('<?xml version="1.0" ?><!DOCTYPE cross-domain-policy SYSTEM "http://www.adobe.com/xml/dtds/cross-domain-policy.dtd"> <cross-domain-policy> <allow-access-from domain="*" secure="false" /> </cross-domain-policy>');
    }

    _flashAddRouteHandler(request, response) {
        response.writeHead(200);
        response.end();
    }

    _flashAddCrypted2RouteHandler(request, response) {
        let body = '';
        request.on('data', (chunk) => { body += chunk.toString(); });
        request.on('end', () => { 
            const parameters = this._parseBody(body);
            const key = this._evalDecryptionKey(parameters.jk);
            const plainContent = this._decryptContent(key, parameters.crypted); 
            const urls = plainContent.split('\n');
            const collection = new LinkCollection(parameters.source, urls);
            this._collectorSession.add(collection);
            console.log(`Created new collection ${collection.name} with ${collection.urls.length} urls`);
            response.writeHead(200);
            response.end();
        });
    }

    _collectorRouteHandler(request, response) {
        let content = "";
        this._collectorSession.collections.forEach((x) => {
            content += `<h1>${x.name}</h1></br>${x.urls.join('</br>')}<hr/>`;
        });
        response.writeHead(200, { 
            "Content-Type": "text/html",
            "Content-Disposition": "inline",
        });
        response.end(content);
    }

    _parseBody(content) {
        const body = {};
        const segments = content.split('&');
        segments.forEach((x) => {
            const pair = x.split('=');
            body[pair[0]] = queryString.unescape(pair[1]);
        });
        return body;
    }

    _decryptContent(key, encrypted) {
        const stringDecoder = new StringDecoder('utf8');
        const decodedKey = stringDecoder.end(Buffer.from(key, 'hex'));
        const initialVector = decodedKey;
        const decipher = crypto.createDecipheriv('AES-128-CBC', decodedKey, initialVector);
        decipher.setAutoPadding(false); 
        let decrypted = decipher.update(encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }

    _evalDecryptionKey(jkJavascriptFunctionString) {
        jkJavascriptFunctionString = jkJavascriptFunctionString.replace(/\+/g, ' ');
        const sandbox = { key: undefined }; 
        const context = new vm.createContext(sandbox);
        const script = new vm.Script( `${jkJavascriptFunctionString}; key = f();`);
        script.runInContext(context);
        return sandbox.key;
    }

}

const server = new ClickNLoadServer(argv.port, argv.host);
server.start();