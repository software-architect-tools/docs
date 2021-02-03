const express = require('express')
const passport = require('passport');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const flash = require('connect-flash');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const cachedSigninPage = fs.readFileSync(path.resolve(__dirname,'..', 'layouts/signin.html'), 'utf8')

const authConfig = {
  authType: process.env.AUTH_TYPE,
  clientId: process.env.OAUTH2_CLIENT_ID,
  clientSecret: process.env.OAUTH2_CLIENT_SECRET,
  callbackUrl: process.env.OAUTH2_CALLBACK_URL,
  scopes: process.env.OAUTH2_SCOPES,
  expressAuthRoute: process.env.OAUTH2_EXPRESS_AUTH_ROUTE || '/auth' ,
  expressCallbackRoute: process.env.OAUTH2_EXPRESS_CALLBACK_ROUTE || '/auth/callback',
  expressAuthErrorRoute: '/auth/failed'
}

if(typeof process.env.OAUTH2_ALLOWED_USERS !== 'undefined'){
  authConfig.allowedUsers = process.env.OAUTH2_ALLOWED_USERS.replace(/ /g,"").split(",");
}

//get custom strategy
var Oauth2Strategy;

switch(authConfig.authType){
  case 'google':
    Oauth2Strategy = require('passport-google-oauth').OAuth2Strategy;
  break;
  case 'facebook':
    Oauth2Strategy = require('passport-facebook').Strategy;
  break;
  default:
    throw new Error("Unsuported Oauth2 Strategy:"+authConfig.authType);
}


passport.serializeUser(function(user, done) {
  // done(null, user.id);
  done(null, user);
});

passport.deserializeUser(function(obj, done) {
  // Users.findById(obj, done);
  done(null, obj);
});


// Catch unhandled promise rejections and passing them to Express's error handler
// https://medium.com/@Abazhenov/using-async-await-in-express-with-node-8-b8af872c0016
const asyncMiddleware = fn =>
  (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next)
  }

module.exports = function (app) {

  app.use(session({
    secret: uuidv4(),
    resave: false,
    saveUninitialized: false
  }));    
  // 
  app.use(passport.initialize());
  app.use(passport.session());
  app.use(flash());

  passport.use(new Oauth2Strategy({
      clientID: authConfig.clientId,
      clientSecret: authConfig.clientSecret,
      callbackURL: authConfig.callbackUrl
    },
    function(accessToken, refreshToken, profile, done) {
      // here user profile id or email to query in some database
      // User.findOrCreate({ googleId: profile.id }, function (err, user) {
      //   return done(err, user);
      // });
      //just simple comparation is implemented
      var email = profile.emails[0].value;
      if(authConfig.allowedUsers.includes(email)){
        return done(null, profile);        
      }else{
        return done(null, false, { message: `User ${email} is not allowed` }); 
      }
      
    }
  ));
  
  app.get(authConfig.expressAuthErrorRoute, function(req, res) {    
    var errorMessage = req.flash('error');
    if(typeof errorMessage === 'undefined' || errorMessage == ""){
      errorMessage = "Internal Error. Please contact your administrator.";      
    }    
    res.type('text/html');
    res.send(cachedSigninPage.replace("@showErrorMessage","inline").replace("@errorMessage",errorMessage));
  });  

  app.get(authConfig.expressAuthRoute,
    passport.authenticate(authConfig.authType, { scope: [authConfig.scopes] }));

  //todo: handle errors in failureRedirect page.   
  app.get(authConfig.expressCallbackRoute,
    passport.authenticate(authConfig.authType, { failureRedirect: authConfig.expressAuthErrorRoute, failureFlash:true }),
    function(req, res) {
      // Authenticated successfully
      res.redirect('/');
    });
    

  // Simple route middleware to ensure user is authenticated.
  function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
      return next();
    }
    res.type('text/html');
    res.send(cachedSigninPage.replace("@showErrorMessage","none"));
  }

  app.use(ensureAuthenticated);

}
