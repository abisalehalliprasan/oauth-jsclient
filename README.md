# Intuit OAuth2.0 Client Library 


# Installation

Its very simple to use the Library. Follow below instructions to use the library in the below environments:

## If you are using NodeJS

1. Install the NPM package:

    ```sh
    npm install intuit-oauthclient --save
    ```

2. Require the Library:

    ```js
    var oauthClient = new OAuth2Client({
        clientId: 'Enter your clientId',
        clientSecret: 'Enter your clientSecret',
        environment: OAuth2Client.environment.sandbox || OAuth2Client.environment.production,
        redirectUri: 'http://localhost:8000/callback'
    });
    ```

## If you are using Browser ( TODO : Evaluate if this is possible )

### Get the code

- Using CDN
    - https://cdn.rawgit.com/intuit/oauth-jsclient/master/build/oauthclient.js
    - https://cdnjs.cloudflare.com/ajax/libs/es6-promise/3.2.2/es6-promise.js

- Download everything manually:
    - [ZIP file with source code](https://github.com/intuit/oauth-jsclient/archive/master.zip)
    - [ES6 Promise](https://github.com/jakearchibald/es6-promise), direct download: [es6-promise.js](https://raw.githubusercontent.com/jakearchibald/es6-promise/master/dist/es6-promise.js)
    
- Use Bower, all dependencies will be downloaded to `bower_components` directory:

    ```sh
    bower install intuit-oauthclient --save
    ```

### Add scripts to HTML page

```html
<script type="text/javascript" src="path-to-scripts/es6-promise/promise.js"></script>
<script type="text/javascript" src="path-to-scripts/oauth-jsclient/master/build/oauthclient.js"></script>
<script type="text/javascript">

    var oauthClient = new OAuthClient({
        clientId: 'Enter your clientId',
        clientSecret: 'Enter your clientSecret',
        environment: OAuth2Client.environment.sandbox || OAuth2Client.environment.production,
        redirectUri: 'http://localhost:8000/callback'
    });

</script>
```



## Authorize using Code Flow 

The Authorization Code flow is made up from two parts. At first your application asks to
the user the permission to access their data. If the user approves the OAuth2 server sends
to the client an authorization code. In the second part, the client POST the authorization code
along with its client secret to the oauth server in order to get the access token.

```javascript
// Instance of client
var oauthClient = new OAuthClient({
    clientId: 'Q0U5kTPRgklmWD0WS8x5L4JMv2IDC2nxXNJzdXdlQ8LDrmNhAi',
    clientSecret: 'flP1yvrvteJurDydgoImGvm9wOcifMureLe30L21',
    environment: OAuthClient.environment.sandbox,
    redirectUri: 'http://localhost:8000/callback',
    cachePrefix: 'intuit-test'
});

// Authorization oauth2 URI
var authUri = oauthClient.redirect({scope:[OAuth2Client.scopes.Accounting,OAuth2Client.scopes.OpenId,],state:'Optional State Paramter'});

// to redirect to the authorizeUri using the browser's window object
window.location.assign(authUri); // or .replace()



// to redirect using NodeJS Express Router
res.redirect(authUri);


/**
 * Parse the redirect URL for authCode and exchange them for tokens
 */
//

var parseRedirect = oauthClient.parseRedirectUri(window.location.href || window.location.hash);


oauthClient.createToken(parseRedirect)
    .then(function(authResponse) {
        console.log('The Access Token is : ' + JSON.stringify(authResponse.json()));
    })
    .catch(function(e) {
        console.error(e.intuit_tid);
    });

```

## Helpers

### Is AccessToken Valid

You can check if the access token associated with the `oauthClient` is valid or not using the helper method. You can also optionally pass the `access_token` to this helper method :

```javascript

if(!oauthClient._isAccessTokenValid()){
    
    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error(e.intuit_tid);
        });
    
}

```

### Revoke access_token

When you no longer need the access_token, you could use the below helper method to revoke the tokens. You can also optionally pass the `access_token` or `refresh_token` to this helper method : 

```javascript

oauthClient.revoke(params)
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error(e.intuit_tid);
        });

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





