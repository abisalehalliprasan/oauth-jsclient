
/**
 * @namespace OAuth2Client
 */

var queryString = require('querystring');
var Tokens = require('csrf');
var csrf = new Tokens();
var popsicle = require('popsicle');
var EventEmitter = require("events").EventEmitter;
var Token = require("./access-token/Token");
var AuthResponse = require("./response/AuthResponse");



/**
 * @constructor
 * @param {string} config.environment
 * @param {string} config.appSecret
 * @param {string} config.appKey
 * @param {string} [config.cachePrefix]
 */
function OAuth2Client(config) {

    this.environment = config.environment;
    this.clientId = config.clientId;
    this.clientSecret = config.clientSecret;
    this.redirectUri = config.redirectUri;
    this.token = new Token(config);

    EventEmitter.call(this);

    this.events = {
        beforeUserInfo: 'beforeUserInfo',
        userInfoSuccess: 'userInfoSuccess',
        beforeLogin: 'beforeLogin',
        loginSuccess: 'loginSuccess',
        loginError: 'loginError',
        beforeRefresh: 'beforeRefresh',
        refreshSuccess: 'refreshSuccess',
        refreshError: 'refreshError',
        beforeLogout: 'beforeLogout',
        logoutSuccess: 'logoutSuccess',
        logoutError: 'logoutError'
    };

}


OAuth2Client.cacheId = 'cacheID';
OAuth2Client.authorizeEndpoint = 'https://appcenter.intuit.com/connect/oauth2';
OAuth2Client.tokenEndpoint = 'https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer';
OAuth2Client.revokeEndpoint = 'https://developer.api.intuit.com/v2/oauth2/tokens/revoke';
OAuth2Client.userinfo_endpoint = 'https://accounts.platform.intuit.com/v1/openid_connect/userinfo';
OAuth2Client.environment = {
    sandbox:'https://sandbox-quickbooks.api.intuit.com',
    production:'https://quickbooks.api.intuit.com'
}
OAuth2Client.scopes = {
    Accounting: 'com.intuit.quickbooks.accounting',
    Payment: 'com.intuit.quickbooks.payment',
    Profile: 'profile',
    Email:  'email',
    Phone: 'phone',
    Address: 'address',
    OpenId: 'openid'
}

/**
 * Event Emitter
 * @type {EventEmitter}
 */
OAuth2Client.prototype = Object.create(EventEmitter.prototype);



/**
 * Redirect  User to Authorization Page
 * @param params
 * @returns {string} authorize Uri
 */
OAuth2Client.prototype.authorizeUri = function(params) {

    params = params || {};

    return OAuth2Client.authorizeEndpoint + '?' + queryString.stringify({
        'response_type': 'code',
        'redirect_uri': this.redirectUri ,
        'client_id': this.clientId,
        'scope': (Array.isArray(params.scope)) ? params.scope.join(' ') : params.scope,
        'state': params.state || csrf.create(csrf.secretSync())
    });
};


/**
 * Parse the redirectURI
 * @param {string} uri
 * @returns {Object} Parse the callback URI
 */
OAuth2Client.prototype.parseRedirectUri = function(uri) {

    var query = queryString.parse(uri.split('?').reverse()[0]);
    this.getToken().realmId = (query['realmId'] ? query['realmId'] : '');
    return query;
};


/**
 * Create Token { exchange code for bearer_token }
 * @param options
 * @returns {Promise<any>}
 */
OAuth2Client.prototype.createToken = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};
        this.emit(this.events.beforeLogin);
        var body = {};
        if (params.code) {

            body.grant_type = 'authorization_code';
            body.code = params.code;
            body.redirect_uri = params.redirectUri || this.redirectUri;
        }

        var request = {
            url: OAuth2Client.tokenEndpoint,
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + this.authHeader(),
                'Content-Type': AuthResponse._urlencodedContentType,
                'Accept': AuthResponse._jsonContentType
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.emit(this.events.loginSuccess, authResponse);
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.emit(this.events.loginError, e);
        throw e;

    }.bind(this));

};

/**
 * Refresh Token { Refresh access_token }
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuth2Client.prototype.refresh = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};
        this.emit(this.events.beforeRefresh);

        var body = {};

        body.grant_type = 'refresh_token';
        body.refresh_token = params.refresh_token || this.getToken().refresh_token;

        var request = {
            url: OAuth2Client.tokenEndpoint,
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + this.authHeader(),
                'Content-Type': AuthResponse._urlencodedContentType,
                'Accept': AuthResponse._jsonContentType
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.emit(this.events.refreshSuccess, authResponse);
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.emit(this.events.refreshError, e);
        throw e;

    }.bind(this));

};

/**
 * Revoke Token { revoke access/refresh_token }
 * @param {Object} params.access_token (optional)
 * @param {Object} params.refresh_token (optional)
 * @returns {Promise<AuthResponse>}
 */
OAuth2Client.prototype.revoke = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};

        this.emit(this.events.beforeLogout);

        var body = {};

        body.token = params.access_token || params.refresh_token || (this.getToken().isAccessTokenValid() ? this.getToken().access_token : this.getToken().refresh_token);

        var request = {
            url: OAuth2Client.revokeEndpoint,
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + this.authHeader(),
                'Accept': AuthResponse._jsonContentType,
                'Content-Type': AuthResponse._jsonContentType
            }
        };

        resolve(this.getTokenRequest(request));


    }.bind(this))).then(function(authResponse) {

        return authResponse;

    }.bind(this)).catch(function(e) {

        this.emit(this.events.logoutError, e);
        throw e;

    }.bind(this));

};

/**
 * Get User Info  { Get User Info }
 * @param {Object} params
 * @returns {Promise<AuthResponse>}
 */
OAuth2Client.prototype.getUserInfo = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};

        this.emit(this.events.beforeUserInfo);

        var request = {
            url: OAuth2Client.userinfo_endpoint,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + this.token.access_token,
                'Accept': AuthResponse._jsonContentType
            }
        };

        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        this.emit(this.events.userInfoSuccess, res);
        return authResponse;

    }.bind(this)).catch(function(e) {

        this.emit(this.events.logoutError, e);
        throw e;

    }.bind(this));

};

/**
 * Get Token Request
 * @param {Object} request
 * @returns {Promise<AuthResponse>}
 */
OAuth2Client.prototype.getTokenRequest = function(request) {

    var authResponse = new AuthResponse({token:this.token});

    return (new Promise(function(resolve) {

        resolve(this.loadResponse(request));

    }.bind(this))).then(function(response) {

        authResponse.processResponse(response);

        if (!authResponse.valid()) throw new Error('Response has an Error');

        return authResponse;

    }.bind(this)).catch(function(e) {

        if (!e.authResponse) e = this.createError(e, authResponse);
        this.emit(this.events.requestError, e);
        throw e;

    }.bind(this));

};


/**
 * Make HTTP Request using Popsicle Client
 * @param request
 * @returns {*}
 */
OAuth2Client.prototype.loadResponse = function (request) {

    return popsicle.get(request).then(function (response) {
        return response;
    });
};

/**
 * Wrap the exception with more information
 * @param {Error|IApiError} e
 * @param {AuthResponse} authResponse
 * @return {Error|IApiError}
 */
OAuth2Client.prototype.createError = function(e, authResponse) {

    e.authResponse = authResponse;
    e.originalMessage = e.message;
    e.error =  ('error' in authResponse.getJson() ? authResponse.getJson().error : '');
    e.error_description = ('error_description' in authResponse.getJson() ? authResponse.getJson().error_description : '');
    e.intuit_tid = authResponse.headers()['intuit_tid'];

    return e;

};

/**
 * isAccessToken Valid () { TTL of access_token }
 * @returns {boolean}
 * @private
 */
OAuth2Client.prototype._isAccessTokenValid = function() {
    return (this.token.expires_in > Date.now());
};

/**
 * GetToken
 * @returns {Token}
 */
OAuth2Client.prototype.getToken = function() {
    return this.token;
};

/**
 * Get AuthHeader
 * @returns {string} authHeader
 */
OAuth2Client.prototype.authHeader = function() {
    var apiKey = this.clientId + ':' + this.clientSecret;
    return (typeof btoa == 'function') ? btoa(apiKey) : new Buffer(apiKey).toString('base64');
};



module.exports = OAuth2Client;