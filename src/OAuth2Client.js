
/**
 * @namespace OAuth2Client
 */

var queryString = require('querystring');
var Tokens = require('csrf');
var csrf = new Tokens();
var atob = require('atob');
var popsicle = require('popsicle');
var EventEmitter = require("events").EventEmitter;
var oauthSignature = require('oauth-signature');
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
        migrateSuccess: 'migrateSuccess',
        beforeMigrate: 'beforeMigrate',
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
OAuth2Client.migrate_sandbox = 'https://developer-sandbox.api.intuit.com/v2/oauth2/tokens/migrate';
OAuth2Client.migrate_production = 'https://developer.api.intuit.com/v2/oauth2/tokens/migrate';
OAuth2Client.environment = {sandbox:'https://sandbox-quickbooks.api.intuit.com', production:'https://quickbooks.api.intuit.com'};
OAuth2Client.jwks_uri = 'https://oauth.platform.intuit.com/op/v1/jwks';
OAuth2Client.scopes = {
    Accounting: 'com.intuit.quickbooks.accounting',
    Payment: 'com.intuit.quickbooks.payment',
    Profile: 'profile',
    Email:  'email',
    Phone: 'phone',
    Address: 'address',
    OpenId: 'openid'
}
OAuth2Client.user_agent = 'Intuit-OAuthClient-JS';

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
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
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
OAuth2Client.prototype.refresh = function() {

    return (new Promise(function(resolve) {

        if(!this.token.refreshToken()) throw new Error('The Refresh token is missing');
        if(!this.token.isRefreshTokenValid()) throw new Error('The Refresh token is invalid, please Authorize again.');

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
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
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

        e = this.createError(e);
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

        /**
         * Check if the tokens exist and are valid
         */
        if(!this.token.refresh_token()) throw new Error('The Refresh token is missing');
        if(!this.token.isRefreshTokenValid()) throw new Error('The Refresh token is invalid, please Authorize again.');

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
                'Content-Type': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
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
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
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

OAuth2Client.prototype.makeApiCall = function(paramas)  {

    return (new Promise(function(resolve) {

        params = params || {};

        this.emit(this.events.beforeAPICall);

        var url = this.environment.toLowerCase() == 'sandbox' ? OAuth2Client.migrate_sandbox : OAuth2Client.migrate_production;

        url += 'v3/company/'+ this.getToken().realmId +'/companyinfo/'+ this.getToken().realmId +'?minorversion=24';

        var request = {
            url: url,
            method: 'GET',
            headers: {
                'Authorization': 'Bearer ' + this.token.access_token,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
            }
        };

        resolve (this.getTokenRequest(request));



    }.bind(this))).then(function(response) {

        var authResponse = response.json ? response : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.emit(this.events.refreshSuccess, authResponse);
        return authResponse;

    }.bind(this)).catch(function(e) {

        e = this.createError(e);
        throw e;

    }.bind(this));

};


OAuth2Client.prototype.migrate = function(params) {

    return (new Promise(function(resolve) {

        params = params || {};

        this.emit(this.events.beforeMigrate);

        var url = this.environment.toLowerCase() == 'sandbox' ? OAuth2Client.migrate_sandbox : OAuth2Client.migrate_production;

        var authHeader = this.generateOauth1Sign(objectAssign({}, {method: 'POST', url: url}, params));


        var body = {
            'scope':(Array.isArray(params.scope)) ? params.scope.join(' ') : params.scope,
            'redirect_uri':this.redirect_uri,
            'client_id': this.clientId,
            'client_secret': this.clientSecret
        };

        var request = {
            url: url,
            method: 'POST',
            body: body,
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'OAuth ' + authHeader,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
            }
        };



        resolve(this.getTokenRequest(request));

    }.bind(this))).then(function(res) {

        var authResponse = res.json ? res : null;
        var json = authResponse && authResponse.getJson() || res;
        this.token.setToken(json);
        this.emit(this.events.migrateSuccess, authResponse);
        return authResponse;
    }.bind(this)).catch(function(e) {

        this.emit(this.events.logoutError, e);
        throw e;

    }.bind(this));


};


OAuth2Client.prototype.generateOauth1Sign = function(params) {


    var timestamp = Math.round(new Date().getTime()/1000);

    var parameters = {
        oauth_consumer_key : params.consumer_key,
        oauth_token : params.access_token,
        oauth_signature_method : 'HMAC-SHA1',
        oauth_timestamp : timestamp,
        oauth_nonce : 'nonce',
        oauth_version : '1.0'
    };

    var encodedSignature = oauthSignature.generate (params.method, params.uri, parameters, params.consumer_secret, params.access_secret);
    parameters ['oauth_signature'] = encodedSignature;
    var keys = Object.keys(parameters);
    var authHeader = '';
    for (key in parameters) {
        // Add this for Accounting API minorversion url query parameter
        if (key === 'minorversion') {
            continue;
        }
        if (key === keys[keys.length-1]) {
            authHeader += key + '=' + '"'+parameters[key]+'"';
        }
        else {
            authHeader += key + '=' + '"'+parameters[key]+'",';
        }
    }
    return authHeader;

};

OAuth2Client.prototype.validateIdToken = function(params) {

    return (new Promise(function(resolve) {

        if(!this.getToken().id_token) throw new Error('The bearer token does not have id_token');

        var id_token = this.getToken().id_token || params.id_token;

        params = params || {};


        // Decode ID Token
        var token_parts = id_token.split('.')
        var id_token_header = JSON.parse(atob(token_parts[0]))
        var id_token_payload = JSON.parse(atob(token_parts[1]))
        var id_token_signature = atob(token_parts[2])


        // Step 1 : First check if the issuer is as mentioned in "issuer"
        if(id_token_payload.iss != 'https://oauth.platform.intuit.com/op/v1') {

            console.log("Step 1 fail");
            return false;
        }

        // Step 2 : check if the aud field in idToken is same as application's clientId
        if(id_token_payload.aud != this.clientId) {
            console.log("Step 2 fail");
            return false;
        }

        // Step 3 : ensure the timestamp has not elapsed
        if(id_token_payload.exp < Date.now() / 1000) {
            console.log("Step 3 fail");
            return false;
        }

        var request = {
            url: OAuth2Client.jwks_uri,
            method: 'GET',
            headers: {
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': OAuth2Client.user_agent
            }
        };

        resolve(this.getKeyFromJWKsURI(id_token, id_token_header.kid, request));

    }.bind(this))).then(function(res) {

        return res;

    }.bind(this)).catch(function(e) {

        this.emit(this.events.logoutError, e);
        throw e;

    }.bind(this));
}

OAuth2Client.prototype.getKeyFromJWKsURI = function(id_token, kid, request) {

    console.log("Step getKeyFromJWKsURI pass");

    return (new Promise(function(resolve) {

        resolve(this.loadResponsegFromJWKsURI(request));

    }.bind(this))).then(function(response) {

        console.log('The response  are :'+ JSON.stringify(response));
        if(response.status != "200") {
            console.log('The true   are :');
            throw new Error('Invalid response from JWKsURI');
        }

        var key = JSON.parse(response.body).keys[0];

        console.log('The keys are :' + JSON.stringify(JSON.parse(response.body)));
        //
        var cert = this.getPublicKey(key['n'], key['e'])
        // Validate the RSA encryption
        return require("jsonwebtoken").verify(id_token, cert);

    }.bind(this)).catch(function(e) {


        e = this.createError(e);
        this.emit(this.events.requestError, e);
        throw e;

    }.bind(this));

}


OAuth2Client.prototype.getPublicKey = function(modulus, exponent) {
    console.log("Step getPublicKey pass");
    var getPem = require('rsa-pem-from-mod-exp');
    var pem = getPem(modulus, exponent);
    return pem
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

OAuth2Client.prototype.loadResponsegFromJWKsURI = function (request) {

    console.log("Step loadResponsegFromJWKsURI pass");
    return popsicle.get(request).then(function (response) {
        console.log("response on popsicle"+JSON.stringify(response));
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

    if(!authResponse){

        e.error = e.originalMessage;
        e.error = e.originalMessage;
        return e;
    }

    e.authResponse = authResponse ? authResponse : null;
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