[![Build Status](https://travis-ci.com/abisalehalliprasan/oauth-jsclient.svg?branch=master)](https://travis-ci.com/abisalehalliprasan/oauth-jsclient)
[![Coverage Status](https://coveralls.io/repos/github/abisalehalliprasan/oauth-jsclient/badge.svg?branch=master)](https://coveralls.io/github/abisalehalliprasan/oauth-jsclient?branch=master)


# Intuit OAuth2.0 NodeJS Library 

This client library is meant to work with Intuit's [OAuth2.0](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0) and [OpenID Connect](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/openid-connect) implementations which conforms to the specifications.


## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
  - [Using NodeJS](#using-nodejs)
- [Usage](#usage)
  - [Authorization Code flow](#authorization-code-flow)
- [Sample](#sample)  
- [Helpers](#helpers)
  - [Is Access Token valid](#is-accesstoken-valid)
  - [Refresh Access_Token](#refresh-access_token)
  - [Revoke Access Token](#revoke-access_token)
  - [Getter / Setter for Token](#getter-/-setter-for-token )
  - [Auth Response](#auth-response)
  - [Error Logging](#error-logging)
- [Contributing](#contributing)
- [Authors](#authors)
  - [Contributors](#contributors)
- [Changelog](#changelog)
- [License](#license)


# Requirements

The node client library is tested against the `Node`  >= `7.0.0`

# Installation

Its very simple to use the Library. Follow below instructions to use the library in the below environments:

## Using NodeJS

1. Install the NPM package:

    ```sh
    npm install intuit-jsclient --save
    ```

2. Require the Library:

    ```js
    var OAuthClient = require('intuit-jsclient');
    var oauthClient = new OAuthClient({
        clientId: '<Enter your clientId>',
        clientSecret: '<Enter your clientSecret>',
        environment: 'sandbox' || 'production',
        redirectUri: '<Enter your callback URL>'
    });
    ```
    ** `redirectUri` would look like: `http://localhost:8000/callback`

***

# Usage

We assume that you have a basic understanding about OAuth2.0. If not please read [API Documentation](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0) for clear understanding

## Authorization Code Flow 

The Authorization Code flow is made up of two parts :   
 
**Step 1.** Redirect user to `oauthClient.authorizeUri(options)`.  
**Step 2.** Parse response uri and get access-token using the function `oauthClient.createToken(req.url)` which returns a [Promise](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise).


### Step 1
```javascript

// Instance of client
var oauthClient = new OAuthClient({
    clientId: '<Enter your clientId>',
    clientSecret: '<Enter your clientSecret>',
    environment: 'sandbox',
    redirectUri: '<http://localhost:8000/callback>'
});

// AuthorizationUri
var authUri = oauthClient.authorizeUri({scope:[OAuthClient.scopes.Accounting,OAuthClient.scopes.OpenId],state:'testState'});


// To redirect to the authorizeUri using the browser's window object
window.location.assign(authUri); // or .replace()

OR

// Redirect example using Express (see http://expressjs.com/api.html#res.redirect)
res.redirect(authUri);

```

### Step 2
```javascript

// Parse the redirect URL for authCode and exchange them for tokens
var parseRedirect = req.url;

// Exchange the auth code retrieved from the **req.url** on the redirectUri
oauthClient.createToken(parseRedirect)
    .then(function(authResponse) {
        console.log('The Token is  '+ JSON.stringify(authResponse.getJson()));
    })
    .catch(function(e) {
        console.error("The error message is :"+e.originalMessage);
        console.error(e.intuit_tid);
    });

```

# Sample
For more clarity, we suggest you take a look at the sample application below :  
[sample](https://github.intuit.com/abisalehalliprasan/oauth-jsclient/tree/master/sample)


## Helpers

### Is AccessToken Valid

You can check if the access token associated with the `oauthClient` is valid or not using the helper method. 

```javascript

if(oauthClient.isAccessTokenValid()) {
    console.log("The access_token is valid");
} 

if(!oauthClient.isAccessTokenValid()){
    
    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });
    
}

```
** Note: If the access_token is not valid, you can call the client's `refresh()` method to refresh the tokens for you as shown below

### Refresh access_token

Access tokens are valid for 3600 seconds (one hour), after which time you need to get a fresh one using the latest refresh_token returned to you from the previous request. When you request a fresh access_token, always use the refresh token returned in the most recent token_endpoint response. Your previous refresh tokens expire 24 hours after you receive a new one. 

```javascript

    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });
```

### Revoke access_token

When you no longer need the access_token, you could use the below helper method to revoke the tokens. You can also optionally pass the `access_token` or `refresh_token` to this helper method : 

```javascript

oauthClient.revoke(params)
        .then(function(authResponse) {
            console.log('Tokens revoked : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error("The error message is :"+e.originalMessage);
            console.error(e.intuit_tid);
        });

```

### Getter / Setter for Token 

You can call the below methods to set and get the tokens using the `oauthClient` instance:

```javascript

// To Set the tokens explicitly 
oauthClient.getToken().setToken({
    "token_type": "bearer",
    "expires_in": 3600,
    "refresh_token":"<refresh_token>",
    "x_refresh_token_expires_in":15552000,
    "access_token":"<access_token>"
});

// To get the tokens 
oauthClient.getToken().getToken();

`OR`

oauthClient.token.getToken();

```

### Auth-Response 

The response provided by the client is a wrapped response of the below items which is what we call authResponse, lets see how it looks like:

```text

    1. response             // response from `HTTP Client` used by library
    2. token                // instance of `Token` Object    
    3. body                 // res.body in `text`  
    4. json                 // res.body in `JSON`
    5. intuit_tid           // `intuit-tid` from response headers

```

A sample `AuthResponse` object would look similar to :

```json
{  
      "token":{  
         "realmId":"<realmId>",
         "token_type":"bearer",
         "access_token":"<access_token>",
         "refresh_token":"<refresh_token>",
         "expires_in":3600,
         "x_refresh_token_expires_in":8726400,
         "id_token":"<id_token>",
         "latency":60000
      },
      "response":{  
         "url":"https://oauth.platform.intuit.com/oauth2/v1/tokens/bearer",
         "headers":{  
            "content-type":"application/json;charset=UTF-8",
            "content-length":"61",
            "connection":"close",
            "server":"nginx",
            "strict-transport-security":"max-age=15552000",
            "intuit_tid":"1234-1234-1234-123",
            "cache-control":"no-cache, no-store",
            "pragma":"no-cache"
         },
         "body":"{\"id_token\":\"<id_token>\",\"expires_in\":3600,\"token_type\":\"bearer\",\"x_refresh_token_expires_in\":8726400,\"refresh_token\":\"<refresh_token>\",\"access_token\":\"<access_token>\"}",
         "status":200,
         "statusText":"OK"
      },
      "body":"{\"id_token\":\"<id_token>\",\"expires_in\":3600,\"token_type\":\"bearer\",\"x_refresh_token_expires_in\":8726400,\"refresh_token\":\"<refresh_token>\",\"access_token\":\"<access_token>\"}",
      "json":{
        "access_token": "<access_token>",
        "refresh_token": "<refresh_token>",
        "token_type": "bearer",
        "expires_in": "3600",
        "x_refresh_token_expires_in": "8726400",
        "id_token": "<id_token>"
      },
      "intuit_tid":"4245c696-3710-1548-d1e0-d85918e22ebe"
}

```
You can use the below helper methods to make full use of the Auth Response Object :

```javascript
oauthClient.createToken(parseRedirect)
    .then(function(authResponse) {
        console.log('The Token in JSON is  '+ JSON.stringify(authResponse.getJson()));
        var status = authResponse.status();
        var body = authResponse.text();
        var jsonResponse = authResponse.getJson();
        var intuit_tid = authResponse.get_intuit_tid();
    });

```




### Error Logging

Whenever there is an error, the library throws an exception and you can use the below helper methods to retrieve more information :

```javascript

oauthClient.createToken(parseRedirect)
        .catch(function(error) {
            console.log(error);
        });


/**
* This is how the Error Object Looks : 
{  
   "originalMessage":"Response has an Error",
   "error":"invalid_grant",
   "error_description":"Token invalid",
   "intuit_tid":"4245c696-3710-1548-d1e0-d85918e22ebe"
}
*/
```

## FAQ

[FAQ](https://github.intuit.com/abisalehalliprasan/oauth-jsclient/wiki/FAQ)

## Contributing

TODO

## Authors

[AKBP](https://github.com/anilkumarbp)


## License


Simple OAuth 2.0 is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)





