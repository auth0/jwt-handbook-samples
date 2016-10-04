exports.required = function(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  next();
}
