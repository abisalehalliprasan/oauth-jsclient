'use strict';

const nock = require('nock');
const { expect } = require('chai');

const OAuthClientTest = require('../src/OAuthClient');
const AuthResponse = require('../src/response/AuthResponse');
const expectedAccessToken = require('./mocks/bearer-token.json');
const expectedTokenResponse = require("./mocks/tokenResponse.json");
const expectedUserInfo = require("./mocks/userInfo.json");
const expectedMakeAPICall = require("./mocks/makeAPICallResponse.json");


const oauthClient = new OAuthClientTest({
    clientId: 'clientID',
    clientSecret: 'clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
});


describe('Tests for OAuthClient', () => {
    let scope;
    let result;
    before(() => {
        scope = nock('http://intuit.org').persist()
            .post('/oauth2/v1/tokens/bearer')
            .reply(200, expectedAccessToken);
    });

    before(async () => {
        var  body = {};
        result = await oauthClient.loadResponse({
            url: 'http://intuit.org/oauth2/v1/tokens/bearer',
            body: body,
            method: 'POST',
            headers: {
                'Authorization': 'Basic ' + oauthClient.authHeader(),
                'Content-Type': AuthResponse._urlencodedContentType,
                'Accept': AuthResponse._jsonContentType,
                'User-Agent': oauthClient.user_agent
            }
        });
    });

    it('Creates a new access token instance', () => {
        const accessToken = oauthClient.getToken();
        expect(accessToken).to.have.property('realmId');
        expect(accessToken).to.have.property('token_type');
        expect(accessToken).to.have.property('refresh_token');
        expect(accessToken).to.have.property('expires_in');
        expect(accessToken).to.have.property('x_refresh_token_expires_in');
        expect(accessToken).to.have.property('id_token');
        expect(accessToken).to.have.property('latency');
    });


    describe('Get the authorizationURI', () => {
        it('When Scope is passed', () => {
            var actualAuthUri = oauthClient.authorizeUri({scope:'testScope',state:'testState'});
            var expectedAuthUri = 'https://appcenter.intuit.com/connect/oauth2?client_id=clientID&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=testScope&state=testState';
            expect(actualAuthUri).to.be.equal(expectedAuthUri);
        });

        it('When NO Scope is passed', () => {
            try {
               oauthClient.authorizeUri();

            } catch (e) {
                expect(e.message).to.equal('Provide the scopes');
            }
        });
        it('When Scope is passed as an array', () => {
            var actualAuthUri = oauthClient.authorizeUri({scope:[OAuthClientTest.scopes.Accounting,OAuthClientTest.scopes.Payment,OAuthClientTest.scopes.OpenId],state:'testState'});
            var expectedAuthUri = 'https://appcenter.intuit.com/connect/oauth2?client_id=clientID&redirect_uri=http%3A%2F%2Flocalhost%3A8000%2Fcallback&response_type=code&scope=com.intuit.quickbooks.accounting%20com.intuit.quickbooks.payment%20openid&state=testState';
            expect(actualAuthUri).to.be.equal(expectedAuthUri);
        });
    });

    // Create bearer tokens
    describe('Create Bearer Token', () => {

        before(() => {

            scope = nock('https://oauth.platform.intuit.com').persist()
                .post('/oauth2/v1/tokens/bearer')
                .reply(200, expectedTokenResponse, {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Provide the uri to get the tokens', () => {
            var parseRedirect = 'http://localhost:8000/callback?state=testState&code=Q011535008931rqveFweqmueq0GlOHhLPAFMp3NI2KJm5gbMMx';
            return oauthClient.createToken(parseRedirect)
                .then(function(authResponse) {
                    expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
                });
        });

        it('When NO uri is provided', () => {
            return oauthClient.createToken()
                .then(function(authResponse) {
                    expect(authResponse.getToken().access_token).to.be.equal(expectedAccessToken.access_token);
                })
                .catch(function(e) {
                    expect(e.message).to.equal('Provide the Uri');
                });
        });
    });

    // Refresh bearer tokens
    describe('Refresh Bearer Token', () => {
        before(() => {
            var refreshAccessToken = require("./mocks/refreshResponse.json");
            scope = nock('https://oauth.platform.intuit.com').persist()
                .post('/oauth2/v1/tokens/bearer')
                .reply(200,refreshAccessToken , {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Refresh the existing tokens', () => {
            return oauthClient.refresh()
                .then(function(authResponse) {
                    expect(authResponse.getToken().refresh_token).to.be.equal(expectedAccessToken.refresh_token);
                });
        });

        it('Refresh : refresh token is missing', () => {
            oauthClient.getToken().refresh_token = null;
            return oauthClient.refresh()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is missing');
                });
        });

        it('Refresh : refresh token is invalid', () => {
            oauthClient.getToken().refresh_token = 'sample_refresh_token';
            oauthClient.getToken().x_refresh_token_expires_in = '300';
            return oauthClient.refresh()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is invalid, please Authorize again.');
                });
        });
    });

    // Revoke bearer tokens
    describe('Revoke Bearer Token', () => {
        before(() => {
            scope = nock('https://developer.api.intuit.com').persist()
                .post('/v2/oauth2/tokens/revoke')
                .reply(200, '' , {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Revoke the existing tokens', () => {
            oauthClient.getToken().x_refresh_token_expires_in = '4535995551112';
            return oauthClient.revoke()
                .then(function(authResponse) {
                    expect(authResponse.getToken().refresh_token).to.be.equal(expectedAccessToken.refresh_token);
                });
        });

        it('Revoke : refresh token is missing', () => {
            oauthClient.getToken().refresh_token = null;
            return oauthClient.revoke()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is missing');
                });
        });

        it('Revoke : refresh token is invalid', () => {
            oauthClient.getToken().refresh_token = 'sample_refresh_token';
            oauthClient.getToken().x_refresh_token_expires_in = '300';
            return oauthClient.revoke()
                .catch(function(e) {
                    expect(e.message).to.equal('The Refresh token is invalid, please Authorize again.');
                });
        });
    });

    // Get User Info ( OpenID )
    describe('Get User Info ( OpenID )', () => {
        before(() => {
            scope = nock('https://accounts.platform.intuit.com').persist()
                .get('/v1/openid_connect/userinfo')
                .reply(200, expectedUserInfo , {
                    "content-type":"application/json",
                    "content-length":"1636",
                    "connection":"close",
                    "server":"nginx",
                    "intuit_tid":"12345-123-1234-12345",
                    "cache-control":"no-cache, no-store",
                    "pragma":"no-cache"
                });
        });

        it('Get User Info', () => {
            return oauthClient.getUserInfo()
                .then(function(authResponse) {
                    expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedUserInfo));
                });
        });
    });

    // make API Call
    describe('Make API Call ', () => {
        describe('', () => {
            before(() => {
                scope = nock('https://sandbox-quickbooks.api.intuit.com').persist()
                    .get('/v3/company/12345/companyinfo/12345')
                    .reply(200, expectedMakeAPICall , {
                        "content-type":"application/json",
                        "content-length":"1636",
                        "connection":"close",
                        "server":"nginx",
                        "intuit_tid":"12345-123-1234-12345",
                        "cache-control":"no-cache, no-store",
                        "pragma":"no-cache"
                    });
            });
            it('Make API Call in Sanbox Environment', () => {
                oauthClient.getToken().realmId = '12345';
                return oauthClient.makeApiCall()
                    .then(function(authResponse) {
                        expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedMakeAPICall));
                    });
            });
        });

        describe('', () => {
            before(() => {
                scope = nock('https://quickbooks.api.intuit.com').persist()
                    .get('/v3/company/12345/companyinfo/12345')
                    .reply(200, expectedMakeAPICall , {
                        "content-type":"application/json",
                        "content-length":"1636",
                        "connection":"close",
                        "server":"nginx",
                        "intuit_tid":"12345-123-1234-12345",
                        "cache-control":"no-cache, no-store",
                        "pragma":"no-cache"
                    });
            });
            it('Make API Call in Production Environment', () => {
                oauthClient.environment = 'production';
                oauthClient.getToken().realmId = '12345';
                return oauthClient.makeApiCall()
                    .then(function(authResponse) {
                        expect(JSON.stringify(authResponse.getJson())).to.be.equal(JSON.stringify(expectedMakeAPICall));
                    });
            });
        });
    });

    // Check Access Token Validity
    describe('Check Access-Token Validity', () => {
        it('access-token is valid', () => {
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.true;
        });
        it('access-token is not valid', () => {
            oauthClient.getToken().expires_in = null;
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.false;
        });
    });

    // Get Token
    describe('Get Token', () => {
        it('get token instance', () => {
            var token = oauthClient.getToken();
            expect(token).to.be.a('Object');
        });
        it('accesstoken is not valid', () => {
            oauthClient.getToken().expires_in = null;
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.false;
        });
    });

    // Get Auth Header
    describe('Get Auth Header', () => {
        it('Auth Header is valid', () => {
            var authHeader = oauthClient.authHeader();
            console.log('The auth header is :'+authHeader);
            expect(authHeader).to.be.equal('Y2xpZW50SUQ6Y2xpZW50U2VjcmV0');
        });
        it('accesstoken is not valid', () => {
            oauthClient.getToken().expires_in = null;
            var validity = oauthClient.isAccessTokenValid();
            expect(validity).to.be.false;
        });
    });
});


