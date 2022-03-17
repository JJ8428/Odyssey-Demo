const axios = require('axios');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const express = require('express');
const geohash = require('geohash').GeoHash;
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const scheduler = require('node-schedule');
const {check, validationResult} = require('express-validator');

// Models for MongoDB
const User = require('./models/user');
const RefreshToken = require('./models/refresh_token');

// Environment variables
require('dotenv').config();

// Connect to DB
mongoose.connect(process.env.DB_NAME);
var db = mongoose.connection;
db.on('error', () => {
    console.log('DB Connection Error');
});
db.once('open', () => {
    console.log('DB Connection Successful');
});

// Remove expired refresh tokens from DB at 6 AM daily
var rule = new scheduler.RecurrenceRule();
rule.hour = 6;
rule.minute = 00;
rule.second = 00;
rule.dayOfWeek = new scheduler.Range(0, 6);
scheduler.scheduleJob(rule, async () => {
    await RefreshToken.deleteMany({createdAt:{$lt:new Date(Date.now() - 1000*60*60*24)}});
});

// Configure express app
var app = express();
app.use(express.json());
app.set('view engine', 'ejs');
const urlEncodedParser = bodyParser.urlencoded({extended: false});

// Middleware
const {check_tokens, auto_login} = require('./middleware/authMiddleware');

// Helper
const indepth_nearby_places = require('./helper/indepth_nearby_places');


app.get('/', (req, res) => {
    return res.render('main');
});

app.get('/sign_up', (req, res) => {
    return res.render('sign_up');
});

app.post('/sign_up', urlEncodedParser, [
    // req.body validators
    check('email', 'Email is not valid.')
        .exists()
        .isEmail()
        .normalizeEmail(),
    check('password', 'Password must be atleast 8 characters long.')
        .exists()
        .isLength({min: 8})
], async (req, res) => {
    // Array of all errors we encounter
    const vald_errs = validationResult(req).array();
    if (vald_errs.length != 0) {
        console.log('Sign Up Error: Failed validation check');
        return res.json({vald_errs: vald_errs});
    }
    // Create new instance of user schema with hashed password
    const salt = await bcrypt.genSalt(10);
    const new_pwd = await bcrypt.hash(req.body.password, salt);
    const new_user = new User({
        email: req.body.email,
        password: new_pwd,
    });
    try {
        // Check if there exists a user with same email already
        const user = await User.findOne({email: req.body.email});
        if (!user) { // No account exists with the provided email
            // Save user in user DB, generate the auth and refresh token, and login user
            console.log('Creating new User schema, giving new auth token saving refresh token in DB');
            new_user.save();
            const auth_token = jwt.sign({email: new_user.email}, 
                process.env.ACCESS_SECRET,
                {expiresIn: 1000*60*60*24}
            );
            const refresh_token = new RefreshToken({email: new_user.email});
            refresh_token.save();
            res.cookie(process.env.ACCESS_NAME, auth_token);
            return res.send('SUCCESS');
        } else { // Error due to email provided for new account already being used for another account
            console.log('Sign up error: Given email already in use');
            return res.json({error: 'Sign Up Error: An account already exists with the provided email.'});
        }
    } catch (err) { // Error due to servor connection issue
        console.log('Server error:', err);
        return res.json({error: 'Server Error: Please try at a different time.'});
    }
});

app.get('/login', auto_login, (req, res) => {
    return res.render('login');
});

app.post('/login', urlEncodedParser, [
    check('email', 'Email is not valid.')
        .exists()
        .isEmail()
        .normalizeEmail(),
    check('password', 'Password must be atleast 8 characters long.')
        .exists()
        .isLength({min: 8})
], async (req, res) => {
    // Array of all errors we encounter
    const vald_errs = validationResult(req).array();
    if (vald_errs.length != 0) {
        console.log('Sign up error: Failed validation');
        return res.json({vald_errs: vald_errs});
    }
    try {
        // Check if an account exists
        const user = await User.findOne({email: req.body.email});
        if (!user) { // No account exists with that email
            console.log('Failed login due to incorrect email');
            return res.json({error: 'Login Error: No account exists with the provided email.'});
        } else { // Account does exist
            const validPassword = await bcrypt.compare(req.body.password, user.password);
            if (validPassword) {
                console.log('Giving user new auth, saving new refresh token in DB');
                const auth_token = jwt.sign({email: user.email}, 
                    process.env.ACCESS_SECRET,
                    {expiresIn: 1000*60*60*24}
                );
                await RefreshToken.deleteOne({email: user.email});
                const refresh_token = new RefreshToken({email: user.email});
                refresh_token.save();
                res.cookie(process.env.ACCESS_NAME, auth_token);
                return res.send('SUCCESS');
            } else {
                console.log('Failed login due to incorrect password');
                return res.json({error: 'Login Error: Incorrect Password.'});
            }
        }
    } catch (err) {
        console.log('Server error on sign up', err);
        return res.json({error: 'Server Error: Please try at a different time'});
    }
});

app.get('/dashboard', check_tokens, (req, res) => {
    return res.render('dashboard', {email: req.user.email});
});

app.delete('/logout', check_tokens, (req, res) => {
    console.log('Logging out user by deleting refresh and auth tokens');
    RefreshToken.deleteOne({email: req.user.email});
    res.clearCookie(process.env.ACCESS_NAME);
    return res.send('SUCCESS');
});

app.get('/user_settings', check_tokens, (req, res) => {
    return res.render('user_settings', {email: req.user.email});
});

app.post('/update_user', check_tokens, urlEncodedParser, [
    // req.body validators
    check('password', 'Password must be atleast 8 characters long.')
        .exists()
        .isLength({min: 8})
], async (req, res) => {
    const vald_errs = validationResult(req).array();
    if (vald_errs.length != 0) {
        console.log('Sign up error: Failed validation');
        return res.json({vald_errs: vald_errs});
    }
    console.log('Updated user password');
    const salt = await bcrypt.genSalt(10);
    const new_pwd = await bcrypt.hash(req.body.password, salt);
    var this_user = await User.findOne({email: req.user.email});
    this_user.password = new_pwd;
    this_user.save();
    return res.send('SUCCESS');    
});

app.delete('/delete_user', check_tokens, (req, res) => {
    console.log('Deleting the user:', req.user.email);
    User.deleteOne({email: req.user.email}).then(resp => {
        console.log('Deleting user:', req.user.email, resp);
    });
    RefreshToken.deleteMany({email: req.user.email}).then(resp => {
        console.log('Deleting refresh token of user:', req.user.email, resp);
    })
    return res.send('SUCCESS');
});

app.get('/find_events/:lat/:lng/:radius/:keywords?', check_tokens, (req, res) => {
    // ticketmaster uses geohash
    const geoPoint = geohash.encodeGeoHash(req.params.lat, req.params.lng).substring(0, 9);
    // Create the query url
    var event_url = `https://app.ticketmaster.com/discovery/v2/events?apikey=${process.env.TICKETMASTER_APIKEY}\
    &radius=${req.params.radius}\
    &unit=miles&\
    geoPoint=${geoPoint}`;
    event_url = event_url.replace(/\s/g, '');
    if (req.params.keywords) {
        event_url += `&keyword=${req.params.keywords}`;
    }
    // Send request to ticketmaster and parse results accordingly
    axios.get(event_url).then(resp => {
        if (resp.status != 200) {
            console.log('Bad response from ticketmaster');
            return res.send('FAILURE');
        }
        var app_res = {
            events: []
        };
        // ._embedded will not appear if there are no events
        if (resp.data._embedded) {
            resp.data._embedded.events.filter(el => !(el.dates.start.dateTBD || el.dates.start.dateTBA || el.dates.start.timeTBA)).forEach(el => {
                var event_info = {
                    name: el.name,
                    tm_url: el.url,
                    event_id: el.id,
                    event_dates: {
                        localDate: el.dates.start.localDate,
                        localTime: el.dates.start.localTime,
                        dateTime: el.dates.start.dateTime,
                        timezone: el.dates.timezone
                    },
                    location: {
                        city: el._embedded.venues[0].city.name,
                        state: el._embedded.venues[0].state,
                        address: el._embedded.venues[0].address.line1,
                        geometry: {
                            lat: parseFloat(el._embedded.venues[0].location.latitude), 
                            lng: parseFloat(el._embedded.venues[0].location.longitude) 
                        }
                    },
                };
                if (el.classifications[0].genre) {
                    event_info.genre = el.classifications[0].genre.name;
                }
                if (el.classifications[0].subGenre) {
                    event_info.subgenre = el.classifications[0].genre.name;
                }
                if (el.priceRanges) {
                    event_info.price = el.priceRanges[0];
                }
                app_res.events.push(event_info);
            });
        }
        return res.json(app_res);
    }).catch(err => {
        // Most likely a connection error
        console.log('Unable to send request to Ticketmaster API', err);
        return res.send('FAILURE');
    })
});

app.get('/find_nearby_places/:lat/:lng/:radius/:subtypes/:keywords?', check_tokens, (req, res) => {
    const location = `${req.params.lat},${req.params.lng}`;
    var selected_types = req.params.subtypes.split(',');
    var base_urls = [];
    selected_types.forEach(el => {
        var this_url = `https://maps.googleapis.com/maps/api/place/nearbysearch/json?`;
        if (req.params.keywords) {
            this_url += `keyword=${req.params.keywords.replace(' ', '%2C')}&`;
        }
        this_url += `type=${el}\
        &location=${location}\
        &radius=${req.params.radius*1609.344}\ 
        &key=${process.env.GOOGLE_APIKEY}`;
        this_url = this_url.replace(/\s/g, '');
        base_urls.push(this_url);
    });
    // Run recursive function with array of URLs generated above
    indepth_nearby_places(base_urls, [], [], process.env.GOOGLE_MAX_PAGE_CHAIN, (output) => {
        return res.send(output);
    });
});

// Get more details of a particular place
const fields = ['formatted_address', 'geometry', 'international_phone_number', 'name', 'opening_hours', 'photos' ,'price_level', 'rating', 'types', 'vicinity', 'website'].join('%2C');
app.get('/find_place_details/:place_id', check_tokens, (req, res) => {
    const detail_url = `https://maps.googleapis.com/maps/api/place/details/json?place_id=${req.params.place_id}&fields=${fields}&key=${process.env.GOOGLE_APIKEY}`;
    axios.get(detail_url).then(resp => {
        res.json({
            'formatted_address': resp.data.result.formatted_address,
            'geometry': resp.data.result.geometry,
            'international_phone_number': resp.data.result.international_phone_number,
            'name': resp.data.result.name,
            'opening_hours': resp.data.result.opening_hours,
            'photos': resp.data.result.photos,
            'price_level': resp.data.result.price_level,
            'rating': resp.data.result.rating,
            'types': resp.data.result.types,
            'vicinity': resp.data.result.vicinity,
            'website': resp.data.result.website
        });
    }).catch(err => {
        console.log('Unable to send request to Google Places (Details) API:', detail_url)
        return res.send('FAILURE');
    });
});

app.get('/find_instaspots/:lat/:lng', (req, res) => {
    const spot_url = `https://us-central1-mari-a5cc7.cloudfunctions.net/api/v1/spots/getByArea/10/${req.params.lat}/${req.params.lng}/${process.env.GETNOFILTER_LIMIT}`;
    const config = {
        headers: {
            Accept: 'application/json',
            'Cache-Control': 'no-cache',
            'Content-Type': 'application/json',
            Authorization: `Bearer ${process.env.GETNOFILTER_APIKEY}`,
        }
    };
    axios.get(spot_url, config).then(resp => {
        res.json(resp.data);
    }).catch(err => {
        console.log('Unable to send request to GetNoFilter API:', spot_url);
        return res.send('FAILURE');
    });
});

app.get('/where/:location_details/:chosen_places/:chosen_events/:chosen_spots/:chosen_customs', check_tokens, (req, res) => {

    var location_details, input, address, radius, chosen_places, chosen_events, chosen_spots, chosen_customs;
    try {
        if (req.params.location_details == 'new') {
            console.log('a');
            location_details = {
                input: undefined,
                address: undefined,
                radius: undefined
            };
            chosen_places = [];
            chosen_events = [];
            chosen_spots = [];
            chosen_customs = [];
        } else {
            location_details = JSON.parse(req.params.location_details);
            if (!location_details.input || !location_details.address || !location_details.radius) throw 'Illegal Request for /where: Bad Request.';
            (req.params.chosen_places != 'new') ? chosen_places = JSON.parse(req.params.chosen_places) : chosen_places = [];
            (req.params.chosen_events != 'new') ? chosen_events = JSON.parse(req.params.chosen_events) : chosen_events = [];
            (req.params.chosen_spots != 'new') ? chosen_spots = JSON.parse(req.params.chosen_spots) : chosen_spots = [];
            (req.params.chosen_customs != 'new') ? chosen_customs = JSON.parse(req.params.chosen_customs) : chosen_customs = [];
            const chosen_count = chosen_places.length + chosen_events.length + chosen_spots.length + chosen_customs.length;
            try {
                new Map(chosen_places);
                new Map(chosen_events);
                new Map(chosen_spots);
                new Map(chosen_customs);
            } catch (err) {
                throw 'Illegal Request for /where: Bad Request.'
            }
            if (chosen_count > process.env.MAX_CHOSEN) throw 'Illegal Request to /where: Request exceeds checkpoint limit (8).';
        }
    } catch (err) {
        return res.render('illegal', {email: req.user.email, error: err});
    }
    return res.render('where', {
        email: req.user.email,
        input: location_details.input,
        address: location_details.address,
        radius: location_details.radius,
        chosen_places: [[1, 2], [3, 4]],
        chosen_events: chosen_events,
        chosen_spots: chosen_spots,
        chosen_customs: chosen_customs
    });
});


app.get('/when', check_tokens, (req, res) => {
    return res.render('pt_when', {email: req.user.email});
})

const host_port = process.env.PORT || 5000;
app.listen(host_port, () => {
    console.log('App listening on port', host_port);
});