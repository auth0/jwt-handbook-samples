'use strict';

const express = require('express');
const expressJwt = require('express-jwt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const dotenv = require('dotenv');
const boom = require('express-boom');
const jwksClient = require('jwks-rsa');

const items = require('./static/items.json');

dotenv.config();

const cartVerifyJwtOptions = {
    algorithms: ['HS256'],
    maxAge: '1h'
};

const cartSignJwtOptions = {
    algorithm: 'HS256',
    expiresIn: '1h'
};

const idTokenVerifyJwtOptions = {
    algorithms: ['RS256']
};

const jwksOpts = {
  cache: true,
  rateLimit: true,
  jwksUri: `${process.env.AUTH0_API_ISSUER}.well-known/jwks.json`
};
const jwks = jwksClient(jwksOpts);

const app = express();
app.use(boom());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));

app.use('/protected', expressJwt({
    secret: jwksClient.expressJwtSecret(jwksOpts),
    issuer: process.env.AUTH0_API_ISSUER,
    audience: process.env.AUTH0_API_AUDIENCE,
    requestProperty: 'accessToken',
    getToken: req => {
        return req.cookies['access_token'];
    }
}));

app.use(express.static('static'));

app.post('/auth', (req, res) => {
    res.cookie('access_token', req.body.access_token, {
        httpOnly: true,
        maxAge: req.body.expires_in * 1000
    });
    res.cookie('id_token', req.body.id_token, {
        maxAge: req.body.expires_in * 1000
    });
    res.redirect('/');
});

app.get('/logout', (req, res) => {
    res.clearCookie('access_token');
    res.clearCookie('id_token');
    res.redirect('/');
});

function validateId(itemId) {
    const valid = items.map(i => i.id);
    return valid.indexOf(itemId) !== -1;
}

function idValidator(req, res, next) {
    if(validateId(parseInt(req.query.id))) {
        next();
    } else {
        res.boom.badRequest("Invalid item ID");
    }
}

function cartValidator(req, res, next) {
    if(!req.cookies.cart) {
        req.cart = { items: [] };
    } else {
        try {
            req.cart = { 
                items: jwt.verify(req.cookies.cart, 
                                  process.env.AUTH0_CART_SECRET,
                                  cartVerifyJwtOptions).items
            };
        } catch(e) {
            req.cart = { items: [] }; 
        }
    }

    next();
}

app.get('/protected/add_item', idValidator, cartValidator, (req, res) => {    
    req.cart.items.push(parseInt(req.query.id));

    const newCart = jwt.sign(req.cart, 
                             process.env.AUTH0_CART_SECRET, 
                             cartSignJwtOptions);

    res.cookie('cart', newCart, {
        maxAge: 1000 * 60 * 60
    });

    res.end();

    console.log(`Item ID ${req.query.id} added to cart.`);
});

function cartToString(cart) {
    return cart.items.map(
        id => items.find(item => item.id === id).name).join(', ');
}

app.get('/protected/purchase', cartValidator, (req, res) => {
    const idToken = jwt.decode(req.cookies['id_token'], { complete: true });
    jwks.getSigningKey(idToken.header.kid, (error, key) => {
        const profile = jwt.verify(req.cookies['id_token'], 
                                   key.publicKey, 
                                   idTokenVerifyJwtOptions);
        const buyMessage = 
            `User ${profile.name} bought: ${cartToString(req.cart)}`;
        console.log(buyMessage);
        res.send(buyMessage);
    });    
});

app.listen(3000);
