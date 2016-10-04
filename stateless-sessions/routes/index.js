var express = require('express');
var jwt = require('jsonwebtoken');
var router = express.Router();

function getToken(req) {
  if (req.headers.authorization && 
      req.headers.authorization.split(' ')[0] === 'Bearer') {
        return req.headers.authorization.split(' ')[1];
  }
  return null;
}

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index');
});

router.get('/shop', function(req, res, next) {
  res.render('shop');
});

router.post('/secured/add-item', function(req, res, next) {
  var token = getToken(req);
  if(!token) {
    res.sendStatus(500);
    return;
  }

  var decoded = jwt.decode(token, { complete: true });
  if(!decoded.payload.items) {
    decoded.payload.items = [];
  }
  decoded.payload.items.push(req.body.item);
  var encoded = jwt.sign(
    decoded.payload,
    new Buffer(process.env.AUTH0_CLIENT_SECRET, 'base64'),
    { header: decoded.header });

  res.json({
    'id_token': encoded
  });
});

router.get('/show-cart', function(req, res, next) {
  res.render('show-cart');
});

module.exports = router;
