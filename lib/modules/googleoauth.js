var oauthModule = require('./oauth')
  , OAuth = require('oauth').OAuth
  , extractHostname = require('../utils').extractHostname
  , util = require('util');

var googleoauth = module.exports =
oauthModule.submodule('googleoauth')
  .configurable({
       scope: 'array of desired google api scopes'
     , consumerKey: 'consumerKey'
     , consumerSecret: 'consumerSecret'
  })
  .definit( function () {
    this.oauth = new OAuth(
      "https://www.google.com/accounts/OAuthGetRequestToken",
      "https://www.google.com/accounts/OAuthGetAccessToken",
      this.consumerKey(),
      this.consumerSecret(),
      "1.0",  null, "HMAC-SHA1");
  })
  .entryPath('/auth/google-oauth')
  .callbackPath('/auth/google-oauth/callback')
  .authorizePath('/accounts/OAuthAuthorizeToken')
  .redirectToProviderAuth( function (res, token) {
    res.writeHead(303, { 'Location': 'https://www.google.com' + this.authorizePath() + '?oauth_token=' + token });
    res.end();
  })
  .convertErr( function (data) {
//    var errJson = JSON.parse(data.data)
//      , errMsg = errJson.message;
    //var errMsg = data.data;
    return new Error("Google sent back an error: " + util.inspect(data));
  })
  .getRequestToken( function (req, res) {

    // Automatic hostname detection + assignment
    if (!this._myHostname || this._alwaysDetectHostname) {
      this.myHostname(extractHostname(req));
    }

    var p = this.Promise();
    this.oauth.getOAuthRequestToken({ scope: this.scope().join('+'), oauth_callback: this._myHostname + this._callbackPath }, function (err, token, tokenSecret, params) {
      if (err && !~(err.data.indexOf('Invalid / expired Token'))) {
        return p.fail(err);
      }
      p.fulfill(token, tokenSecret);
    });
    return p;
  })
	.fetchOAuthUser( function (accessToken, accessTokenSecret, params) {
    var promise = this.Promise();
		url = "http://www.google.com/reader/api/0/user-info"
    this.oauth.get(url, accessToken, accessTokenSecret, function (err, data) {
      if (err) return promise.fail(err);
      var oauthUser = JSON.parse(data);
      promise.fulfill(oauthUser);
    });
    return promise;
  });
