var passport = require('passport');

module.exports = function(app) {
  app.get('/sso', function(req,res, next) {
    if (req.isAuthenticated()) {
      if (/^http/.test(req.query.targetUrl)) return res.send(400, "url must be relative");
      // Here we'd redirect to req.query.targetUrl like following
      // res.redirect(req.query.targetUrl);
      // But in this case we'll go to User anyway
      res.redirect('/user?targetUrl=' + req.query.targetUrl);
    } else {
      console.log("Authenticating with Auth0 for SSO");
      passport.authenticate('auth0', {
        state: req.query.targetUrl
      })(req, res, next);
    }
  });
}
