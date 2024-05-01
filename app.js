var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');
var session = require('express-session');
var passport = require('passport');
var qs = require('querystring');
var { Strategy } = require('passport-openidconnect');
require('dotenv').config();


const {CLIENT_ID, CLIENT_SECRET, PORT, SESSION_SECRET, OKTA_DOMAIN} = process.env

let logoutURL = `http://${OKTA_DOMAIN}/oauth2/v1/logout`
let id_token

var indexRouter = require('./routes/index');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');


// set up browsing session
app.use(session({
  secret: `${SESSION_SECRET}`,
  resave: false,
  saveUninitialized: true
}));

// set up oidc passport for SSO
app.use(passport.initialize());
app.use(passport.session());


// passport configuration
passport.use('oidc', new Strategy({
  issuer: `https://${OKTA_DOMAIN}`,
  authorizationURL: `https://${OKTA_DOMAIN}/oauth2/v1/authorize`,
  tokenURL: `https://${OKTA_DOMAIN}/oauth2/v1/token`,
  userInfoURL: `https://${OKTA_DOMAIN}/oauth2/v1/userinfo`,
  clientID: `${CLIENT_ID}`,
  clientSecret: `${CLIENT_SECRET}`,
  callbackURL: `http://localhost:${PORT}/authorization-code/callback`,
  scope: 'openid profile'
}, (issuer, profile, context, idToken, accessToken, refreshToken, params, done) => {
  console.log(`OIDC response: ${JSON.stringify({
    issuer, profile, context, idToken,
    accessToken, refreshToken, params
  }, null, 2)}\n*****`);
  id_token = idToken;
  console.log('\n\n\n')
  console.log("id token is: " + id_token)
  console.log('\n\n\n')
  return done(null, profile);
}));

passport.serializeUser((user, next) => {
  next(null, user);
});

passport.deserializeUser((obj, next) => {
  next(null, obj);
});




// handles logistic
app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// set up routing for the app
app.use('/', indexRouter);

app.use('/login', passport.authenticate('oidc'));

app.post('/logout', (req, res, next) => {
   req.logout(err => {
      if (err) { return next(err); }
      let params = {
         id_token_hint: id_token,
         post_logout_redirect_uri: `http://localhost:${PORT}/`
      }
      console.log('\n\n\n')
      console.log("Logout URL is: " + logoutURL + '?' + qs.stringify(params));
      console.log('\n\n\n')
      res.redirect(logoutURL + '?' + qs.stringify(params));
   });
});

app.use('/authorization-code/callback',
  passport.authenticate('oidc', { failureMessage: true, failWithError: true }),
  (req, res) => {
    console.log("authetication callback successful")
    res.redirect('/profile');
  }
);

app.use('/profile', (req, res) => {
  console.log(req.isAuthenticated());
  res.render('profile', { authenticated: req.isAuthenticated(), user: req.user });
});


// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
