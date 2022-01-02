const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const { check, validationResult } = require('express-validator');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const User = require('./models/user');

// Access file to define environment vars
require('dotenv').config();

// Mongoose connections
mongoose.connect(process.env.DB_NAME);
var db = mongoose.connection;
db.on('error', () => {
    console.log('DB Connection Error.');
});
db.once('open', () => {
    console.log('DB Connection Successful.');
})

// Configurations for express app
var app = express();
app.use(express.json());
app.set('view engine', 'ejs');
const urlEncodedParser = bodyParser.urlencoded({ extended: false });

// Refresh token DB (temporary)
let refresh_token_db = [];

// TODO: MIDDLE WARE (done)
const check_auth_token = (req, res, next) => {
    var all_cookies = req.headers.cookie
    var token = null;
    if (all_cookies) {
        all_cookies = all_cookies.split('; ');
        for (var x = 0; x < all_cookies.length; x++) {
            const tmp = all_cookies[x].split('=');
            console.log(tmp);
            if (tmp[0] == process.env.ACCESS_NAME) {
                console.log('Found the Auth JWT')
                token = tmp[1];
            }
        }
    }
    if (token == null) {
        // User is no longer authenciated, must log back in
        console.log('User access token Auth DNE.');
        return res.redirect('/login');
    }
    // We defined the access token in /login to be a JWT that has our user object 
    // (only user email to be more specific)
    jwt.verify(token, process.env.ACCESS_SECRET, (err, user) => {
        if (err) {
            console.log('Cannot verify user Auth JWT.', err);
            return res.redirect('/login');
        } else { // User has a valid token
            console.log('User has valid JWT');
            req.user = user;
            next();
        }
    });
}

const check_refresh_token = (req, res, next) => {
    var all_cookies = req.headers.cookie
    var token = null;
    if (all_cookies) {
        all_cookies = all_cookies.split('; ');
        for (var x = 0; x < all_cookies.length; x++) {
            const tmp = all_cookies[x].split('=');
            console.log(tmp);
            if (tmp[0] == process.env.REFRESH_NAME) {
                console.log('Found the Refresh JWT')
                token = tmp[1];
            }
        }
    }
    if (refresh_token == null) {
        // User is no longer authenciated, must log back in
        console.log('User access token Refresh DNE.');
        return res.redirect('/login');
    }
    // User is not logged in, so we must deny all access tokens related to this user
    if (!refresh_token_db.includes(refresh_token)) {
        console.log('User Refresh token not in RT_DB');
        return res.redirect('/login');
    }
    // We defined the access token in /login to be a JWT that has our user object 
    // (only user email to be more specific)
    jwt.verify(token, process.env.REFRESH_SECRET, (err, user) => {
        if (err) {
            console.log('Cannot verify user Refresh JWT.', err);
            return res.redirect('/login');
        } else { // User has a valid token
            console.log('User has valid JWT');
            next();
        }
    });
};

// Checks refresh and auth tokens
const check_tokens = (req, res, next) => {
    var all_cookies = req.headers.cookie;
    var refresh_token = null;
    var auth_token = null;
    if (all_cookies) {
        all_cookies = all_cookies.split('; ');
        for (var x = 0; x < all_cookies.length; x++) {
            const tmp = all_cookies[x].split('=');
            console.log(tmp);
            if (tmp[0] == process.env.REFRESH_NAME) {
                console.log('Found the Refresh JWT')
                refresh_token = tmp[1];
            }
            if (tmp[0] == process.env.ACCESS_NAME) {
                console.log('Found the Auth JWT')
                auth_token = tmp[1];
            }
        }
    }
    if (refresh_token == null) {
        onsole.log('User refresh token DNE.');
        return res.redirect('/login');
    }
    if (auth_token == null) {
        // User is no longer authenciated, must log back in for access token to be valid
        console.log('User access token DNE.');
        return res.redirect('/login');
    }
    // User is not logged in, so we must deny all access tokens related to this user
    if (!refresh_token_db.includes(refresh_token)) {
        console.log('User Refresh token not in RT_DB');
        return res.redirect('/login');
    }
    jwt.verify(refresh_token, process.env.REFRESH_SECRET, (err, user) => {
        if (err) {
            console.log('Cannot verify user Refresh JWT.', err);
            return res.redirect('/login');
        } else { // User has a valid token
            console.log('User has valid JWT');
            // next();
        }
    });
    jwt.verify(auth_token, process.env.ACCESS_SECRET, (err, user) => {
        if (err) {
            console.log('Cannot verify user Auth JWT.', err);
            return res.redirect('/login');
        } else { // User has a valid token
            console.log('User has valid JWT');
            req.user = user;
            next();
        }
    });
};

app.get('/', (req, res) => {
    res.render('main');
});

app.get('/sign_up', (req, res) => {
    res.render('sign_up');
});

app.post('/sign_up', urlEncodedParser, [
    // req.body validators
    check('email', 'Email is not valid.')
        .exists()
        .isEmail()
        .normalizeEmail(),
    check('password', 'Password must be atleast 8 characters long.')
        .exists()
        .isLength({ min: 8})
], async (req, res) => {
    // Function to render correct page and print statement
    const err_render = (redirect_to, json_arg, log) => {
        res.render(redirect_to, json_arg);
        console.log(log);
    };

    // Array of all errors we encounter
    const vald_errs = validationResult(req).array();
    if (vald_errs.length != 0) {
        return err_render('sign_up', {
            vald_errs: vald_errs
        }, 'Sign Up Error: Failed validation.');
    }

    // Create new instance of user with hashed password
    const salt = await bcrypt.genSalt(10);
    const new_pwd = await bcrypt.hash(req.body.password, salt);
    const new_user = new User({
        email: req.body.email,
        password: new_pwd,
        preferences: [0,0,0,0,0]
    });
    
    try {
        const user = await User.findOne({ email: req.body.email });
        if (!user) { // No account exists with the provided email
            /*
                TODO: LOGIN SESSION LOGIC
            */
            new_user.save();
            const auth_token = jwt.sign({ email: new_user.email }, 
                process.env.ACCESS_SECRET,
                {
                    httpOnly: true, 
                    secure: true, 
                    maxAge: 1000 * 60 * 60 * 24
                }
            );
            const refresh_token = jwt.sign({ email: new_user.email }, process.env.REFRESH_SECRET);
            console.log('User given new auth and refresh token');
            refresh_token_db.push(refresh_token);
            res.cookie(process.env.ACCESS_NAME, auth_token);
            res.cookie(process.env.REFRESH_NAME, refresh_token)
            return res.send('success');
        } else { // Account exists with provided email
            return err_render('sign_up', {
                error: 'Sign up error: An account already exists with the provided email.'
            }, 'Sign Up Error: Email Conflict.');
        }
    } catch (err) {
        // Error message in event of server/connection error
        return err_render('sign_up', {
            error: 'Server error: Please try at a different time.'
        }, `Server error: ${err}.`);
    }
});

app.get('/login', (req, res) => {
    res.render('login');
});

app.post('/login', urlEncodedParser, [
    check('email', 'Email is not valid.')
        .exists()
        .isEmail()
        .normalizeEmail(),
    check('password', 'Password must be atleast 8 characters long.')
        .exists()
        .isLength({ min: 8})
], async (req, res) => {
    // Function to render correct page and print statement
    const err_render = (redirect_to, json_arg, log) => {
        res.render(redirect_to, json_arg);
        console.log(log);
    };

    // Array of all errors we encounter
    const vald_errs = validationResult(req).array();
    if (vald_errs.length != 0) {
        return err_render('login', {
            vald_errs: vald_errs
        }, 'Sign Up Error: Failed validation.');
    }

    try {
        const user = await User.findOne({ email: req.body.email });

        if (!user) { // No account exists with that email
            return err_render('login', { 
                incorrect: 'No account exists with the provided email.' 
            }, 'Failed login due to incorrect email.');
        } else { // Account does exist
            const validPassword = await bcrypt.compare(req.body.password, user.password);
            if (validPassword) {
                const auth_token = jwt.sign({ email: user.email }, 
                    process.env.ACCESS_SECRET,
                    {
                        expiresIn: 1000 * 60 * 60 * 24
                    }
                );
                const refresh_token = jwt.sign({ email: user.email }, process.env.REFRESH_SECRET);
                console.log('User given new auth and refresh token');
                refresh_token_db.push(refresh_token);
                res.cookie(process.env.ACCESS_NAME, auth_token);
                res.cookie(process.env.REFRESH_NAME, refresh_token)
                return res.send('success');
            } else {
                return err_render('login', { 
                    incorrect: 'Incorrect Password.' 
                }, 'Failed login due to incorrect password.');
            }
        }
    } catch (err) {
        return err_render('sign_up', {
            error: 'Server error: Please try at a different time.'
        }, `Server error: ${err}.`);
    }
});

/*
app.get('/cookies', (req, res) => {
    res.send(req.headers.cookie.split(';'));
    var token = req.headers.cookie.split('=')[1];
    jwt.verify(token, process.env.ACCESS_SECRET, (err, user) => {
        if (err) {
            console.log('Cannot verify user JWT.', err);
            res.send('err');
        } else { // User has a valid token
            res.send(user);
        }
    });
})
*/

app.get('/home', check_tokens, (req, res) => {
    console.log('@home');
    res.send('Home');
});

app.get('/logout', (req, res) => {
    res.send('Logged out');
    var all_cookies = req.headers.cookie
    var token = null;
    if (all_cookies) {
        all_cookies = all_cookies.split('; ');
        for (var x = 0; x < all_cookies.length; x++) {
            const tmp = all_cookies[x].split('=');
            console.log(tmp);
            if (tmp[0] == process.env.REFRESH_NAME) {
                console.log('Found the Refresh JWT')
                token = tmp[1];
            }
        }
    }
    if (token == null) {
        // User is no longer authenciated, must log back in
        console.log('User access token Refresh DNE.');
        return res.send('Success');
    }
    // User is not logged in, so we must deny all access tokens related to this user
    if (refresh_token_db.includes(refresh_token)) {
        refresh_token_db = refresh_token_db.filter(function(el) {
            el != refresh_token;
        })
        console.log('Removed user refresh token from DB');
    }
    res.send('Success');
})

app.get('/user_settings', (req, res) => {
    res.send('User Setting');
});

app.get('/map_route', (req, res) => {
    res.send('Map');
});

app.listen(process.env.PORT, () => {
    console.log('App listening on port', process.env.PORT + '.');
});
