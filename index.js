'use strict';


var OAuth2Client = require("./src/OAuth2Client");


/**
 * Create a new OAuth2 client
 * @type {OAuth2Client}
 */
// var intuitClient = new OAuth2Client({});
//window.location.assign(intuitClient.code.getUri());


/**
 * Creaste a new oAuth2
 * Use the same client to generate authUri for both auth flow and openID
 */
var oauthClient = new OAuth2Client({
    clientId: 'Q0U5kTPRgklmWD0WS8x5L4JMv2IDC2nxXNJzdXdlQ8LDrmNhAi',
    clientSecret: 'flP1yvrvteJurDydgoImGvm9wOcifMureLe30L21',
    environment: OAuth2Client.environment.sandbox,
    redirectUri: 'http://localhost:8000/callback'
});

var authUri = oauthClient.authorizeUri({scope:[OAuth2Client.scopes.OpenId,OAuth2Client.scopes.Accounting],state:'fhasdffffffssiahf'});

console.log('The authorize URI is :'+authUri);


/**
 * Parse the redirect URL for authCode and exchange them for tokens
 */
// // //
// var callback = 'http://localhost:8000/callback?state=fhasdffffffssiahf&code=Q011535008931rqveFweqmueq0GlOHhLPAFMp3NI2KJm5gbMMx';
// var parseRedirect = oauthClient.parseRedirectUri(callback);
//
// console.log('the parse redirect URI = '+ JSON.stringify(parseRedirect));
//
//
//
//
// oauthClient.createToken(parseRedirect)
//     .then(function(response) {
//         console.log('The response in promise is  '+ JSON.stringify(response));
//     }).then(validate)
//     // .then(checkAuth)
//     .catch(function(e) {
//         console.error(e);
//     });


// function checkAuth() {
//     // console.log('The validity is :'+ oauthClient.token1().access_token);
//     // console.log('The validity is :'+ oauthClient.token1().isaccessTokenValid());
//     // console.log('The validity is :'+ oauthClient._isAccessTokenValid());
//     // console.log('the token obj = '+ JSON.stringify(oauthClient.getToken()));
//
// }

function validate() {

    oauthClient.validateIdToken()
        .then(function(response){
            console.log('The message is empty'+JSON.stringify(response));
        })
        .catch(function(e) {
            console.log('The error is '+e.message);
        });
};

