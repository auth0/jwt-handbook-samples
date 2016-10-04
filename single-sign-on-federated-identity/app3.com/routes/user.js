var login = require('./middlewares/login');

module.exports = function(app) {
  app.get('/user',
    login.required,
    function(req, res) {
      res.render('user', {
        user: req.user,
        url: req.query.targetUrl
      });
    });
}
