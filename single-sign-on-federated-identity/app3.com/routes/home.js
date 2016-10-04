var passport = require('passport');

module.exports = function(app) {
  app.get('/',
    passport.authenticate('auth0', {}),
    function(req, res) {
      res.redirect('/user');
    });
}
