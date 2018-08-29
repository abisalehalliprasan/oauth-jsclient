# Intuit OAuth2.0 Client Library 


# Installation

Its very simple to use the Library. Follow below instructions to use the library in the below environments:

## If you are using NodeJS

1. Install the NPM package:

    ```sh
    npm install intuit-nodejsclient --save
    ```

2. Require the Library:

    ```js
    var oauthClient = new OAuthClient({
        clientId: 'Enter your clientId',
        clientSecret: 'Enter your clientSecret',
        environment: 'sandbox' || 'production',
        redirectUri: 'Enter your callback URL'
    });
    ```
    ** `redirectUri` would look like: http://localhost:8000/callback 



## Authorize using Code Flow 

The Authorization Code flow is made up from two parts. At first your application asks to
the user the permission to access their data. If the user approves the OAuth2 server sends
to the client an authorization code. In the second part, the client POST the authorization code
along with its client secret to the oauth server in order to get the access token.

```javascript
// Instance of client
var oauthClient = new OAuthClient({
    clientId: 'QhhG548GdwrhbfhU5kWD0WS8xGBYKJFI6259hD37hD45zdXdlQ',
    clientSecret: 'gfNLNj68BDNGfbsfgwDweTpG6873DqgheiflP1yvrvm9wOcifMureLe30L2teJurDydgoImGv1',
    environment: 'sandbox',
    redirectUri: 'http://localhost:8000/callback'
});

// Authorization oauth2 URI
var authUri = oauthClient.redirect({scope:[OAuthClient.scopes.Accounting,OAuthClient.scopes.OpenId,],state:'Optional State Paramter'});

// To redirect to the authorizeUri using the browser's window object
window.location.assign(authUri); // or .replace()

OR

// To redirect using NodeJS Express Router
res.redirect(authUri);


// Parse the redirect URL for authCode and exchange them for tokens
var parseRedirect = oauthClient.parseRedirectUri(req.url);


oauthClient.createToken(parseRedirect)
    .then(function(authResponse) {
        console.log('The Access Token is : ' + JSON.stringify(authResponse.json()));
    })
    .catch(function(e) {
        console.error(e.intuit_tid);
    });

```

For more clarity, we suggest you take a look at the sample application below :  
[sample - usage of intuit-nodejsclient library](https://github.intuit.com/abisalehalliprasan/oauth-jsclient/tree/master/sample)


## Helpers

### Is AccessToken Valid

You can check if the access token associated with the `oauthClient` is valid or not using the helper method. You can also optionally pass the `access_token` to this helper method :

```javascript

if(!oauthClient.isAccessTokenValid()){
    
    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error(e.intuit_tid);
        });
    
}

```
### Refresh access_token

Access tokens are valid for 3600 seconds (one hour), after which time you need to get a fresh one using the latest refresh_token returned to you from the previous request. When you request a fresh access token, always use the refresh token returned in the most recent token_endpoint response. Your previous refresh tokens expire 24 hours after you receive a new one. 

```javascript

    oauthClient.refresh()
        .then(function(authResponse) {
            console.log('Tokens refreshed : ' + JSON.stringify(authResponse.json()));
        })
        .catch(function(e) {
            console.error(e.intuit_tid);
        });
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

### Getter / Setter for Token 

You can call the below methods to set and get the tokens:

```javascript

// To Set the tokens explicitly 
oauthClient.getToken().setToken({
    "token_type": "bearer",
    "expires_in": 3600,
    "refresh_token":"L311478109728uVoOkDSUCl4s8FDRvjHR6kUKz0RHe3WtZQuBq",
    "x_refresh_token_expires_in":15552000,
    "access_token":"eyJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiZGlyIn0..KM1_Fezsm6BUSaqqfTedaA.dBUCZWiVmjH8CdpXeh_pmaM3kJlJkLEqJlfmavwGQDThcf94fbj9nBZkjEPLvBcQznJnEmltCIvsTGX0ue_w45h7yn1zBoOb-1QIYVE0E5TI9z4tMUgQNeUkD1w-X8ECVraeOEecKaqSW32Oae0yfKhDFbwQZnptbPzIDaqiduiM_qEFcbAzT-7-znVd09lE3BTpdMF9MYqWdI5wPqbP8okMI0l8aa-UVFDH9wtli80zhHb7GgI1eudqRQc0sS9zWWb"
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





