const jwt = require('jsonwebtoken');
const RefreshToken = require('../models/refresh_token');

// Environment variables
require('dotenv').config();

const check_tokens = async (req, res, next) => {
    var all_cookies = req.headers.cookie;
    var auth_token;
    var req_user;
    // Find and verify the auth and refresh token
    if (all_cookies) {
        all_cookies = all_cookies.split('; ');
        for (var x = 0; x < all_cookies.length; x++) {
            const tmp = all_cookies[x].split('=');
            if (tmp[0] == process.env.ACCESS_NAME) {
                console.log('AUTH token found');
                auth_token = tmp[1];
            }
        }
    }
    if (auth_token == null) {
        console.log('AUTH token not found');
        return res.redirect('/login');
    }
    jwt.verify(auth_token, process.env.ACCESS_SECRET, (err, user) => {
        if (err) { // Token is invalid (either tampered or (more likely) expired)
            console.log('Unable to verify AUTH token');
            return res.redirect('/login');
        } else {
            console.log('Verified AUTH token');
            req_user = user;
        }
    });
    const refresh_token = await RefreshToken.findOne({email: req_user.email});
    if (!refresh_token) {
        console.log('REFRESH token not found');
        return res.redirect('/login');
    } else {
        console.log('Verified REFRESH token');
    }
    // Refresh the auth token with a new token (refresh expiresIn value)
    const new_auth_token = jwt.sign({email: req_user.email}, 
        process.env.ACCESS_SECRET,
        {expiresIn: 1000 * 60 * 60 * 24}
    );
    console.log('Refreshed AUTH token');
    res.cookie(process.env.ACCESS_NAME, new_auth_token);
    // Save the user object as part of req
    req.user = req_user;
    return next();
};

// Automatically login the user if tokens are valid
const auto_login = async (req, res, next) => {
    var all_cookies = req.headers.cookie;
    var auth_token;
    var req_user;
    // Find and verify the auth and refresh token
    if (all_cookies) {
        all_cookies = all_cookies.split('; ');
        for (var x = 0; x < all_cookies.length; x++) {
            const tmp = all_cookies[x].split('=');
            if (tmp[0] == process.env.ACCESS_NAME) {
                console.log('AUTH token found');
                auth_token = tmp[1];
            }
        }
    }
    if (auth_token == null) {
        console.log('AUTH token not found');
        return next();
    }
    jwt.verify(auth_token, process.env.ACCESS_SECRET, (err, user) => {
        if (err) { // Token is invalid (either tampered or (more likely) expired)
            console.log('Cannot verify AUTH token');
            return next();
        } else {
            console.log('Verified AUTH token');
            req_user = user;
        }
    });
    const refresh_token = await RefreshToken.findOne({email: req_user.email});
    if (!refresh_token) {
        console.log('REFRESH token not found');
        return next();
    } else {
        console.log('Verified REFRESH token');
    }
    req.user = req_user;
    res.redirect('/dashboard');
};

module.exports = {check_tokens, auto_login};