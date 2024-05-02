var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', {authenticated: req.isAuthenticated(), title: "My app, with SSO integration from Okta"});
});

module.exports = router;
