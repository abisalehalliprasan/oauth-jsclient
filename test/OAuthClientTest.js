'use strict';

const qs = require('query-string');
const nock = require('nock');
const Chance = require('chance');
const accessTokenMixin = require('chance-access-token');
const { expect } = require('chai');

const OAuthClientTest = require('../src/OAuthClient.js');

const chance = new Chance();
chance.mixin({ accessToken: accessTokenMixin });

const oauth2 = OAuthClientTest({
    clientId: 'clientID',
    clientSecret: 'clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
});

describe('on access token creation', () => {
    it('creates a new access token instance', () => {
        const accessTokenResponse = chance.accessToken();

        const accessToken = oauth2.token.getToken();

        expect(accessToken).to.have.property('token');
        expect(accessToken).to.have.property('refresh');
        expect(accessToken).to.have.property('revoke');
        expect(accessToken).to.have.property('expired');
    });
});
