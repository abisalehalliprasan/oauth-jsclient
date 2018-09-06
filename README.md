[![Build Status](https://travis-ci.com/abisalehalliprasan/oauth-jsclient.svg?branch=master)](https://travis-ci.com/abisalehalliprasan/oauth-jsclient)
[![Coverage Status](https://coveralls.io/repos/github/abisalehalliprasan/oauth-jsclient/badge.svg?branch=master)](https://coveralls.io/github/abisalehalliprasan/oauth-jsclient?branch=master)


# Intuit OAuth2.0 Client Library 


# Installation

Its very simple to use the Library. Follow below instructions to use the library in the below environments:

## If you are using NodeJS

1. Install the NPM package:

    ```sh
    npm install intuit-jsclient --save
    ```

2. Require the Library:

    ```js
    var OAuthClient = require('intuit-jsclient');
    var oauthClient = new OAuthClient({
        clientId: 'Enter your clientId',
        clientSecret: 'Enter your clientSecret',
        environment: 'sandbox' || 'production',
        redirectUri: 'Enter your callback URL'
    });
    ```
    ** `redirectUri` would look like: http://localhost:8000/callback 

***

# Usage

We assume that you have a basic understanding about OAuth2.0. If not please read [API Documentation](https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/oauth-2.0) for clear understanding

## Authorize using Code Flow 

The Authorization Code flow is made up of two parts :  
 
At first your application asks the user the permission to access their data. If the user approves the OAuth2 server sends an `authorization code` to the client.     

In the second part, the client would exchange the `authorization code` along with its client secret to the oauth server in order to get the `access_token`. 

Step 1. Redirect user to `oauthClient.authorizeUri(options)`.  
Step 2. Parse response uri and get access-token using the function `oauthClient.createToken(req.url)` which returns a Promise.

** Note: This is how it would look like ( for example purposes )
`options` = `{scope:[OAuthClient.scopes.Accounting,OAuthClient.scopes.OpenId],state:'testState'}` // pass the scopes and state is optional parameter  
`req.url` = `http://localhost:8000/callback?state=testState&code=Q011536133983coxxxxxxxxxxxxxLNXB74IM09lF1UMmKmIh&realmId=sample_realmId` 
            

### Step 1
```javascript

// Instance of client
var oauthClient = new OAuthClient({
    clientId: 'Enter your clientId',
    clientSecret: 'Enter your clientSecret',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
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

For more clarity, we suggest you take a look at the sample application below :  
[sample - usage of intuit-jsclient library](https://github.intuit.com/abisalehalliprasan/oauth-jsclient/tree/master/sample)


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
    "refresh_token":"enter_refresh_token",
    "x_refresh_token_expires_in":15552000,
    "access_token":"enter_access_token"
});

// To get the tokens 
oauthClient.getToken().getToken();

`OR`

oauthClient.token.getToken();

```

### Auth-Response 

The response provided by the client is a wrapped response of the below items :

```text

    1. response 
    2. body 
    3. json 
    4. intuit_tid

```
You can use the below helper methods to make full use of the Auth Response Object :


### Error Logging

Whenever there is an error, the library throws an exception and you can use the below helper methods to retreieve more informaiton :

```javascript

oauthClient.createToken(parseRedirect)
        .catch(function(e) {
            console.log('The intuit from the error is :' + e.intuit_tid);
            console.log('The error message is :' + e.error);
            console.log('The error description is :' + e.error_description);
        });

```


## Contributing

TODO

## Authors

TODO

### Contributors

TODO


## Changelog

TODO

## License

Simple OAuth 2.0 is licensed under the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)





