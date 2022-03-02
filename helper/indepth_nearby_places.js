const axios = require('axios');

// Accepted subtypes for each type
/*
const food_types = ['bakery', 'bar', 'cafe', 'restaurant'];
const shop_types = ['clothing_store', 'convenience_store', 'department_store', 'shoe_store', 'shopping_mall', 'supermarket'];
const etmt_types = ['amusement_park', 'aquarium', 'art_gallery', 'bowling_alley', 'casino', 'movie_theater', 'museum', 'park', 'tourist_attraction', 'zoo'];
const need_types = ['atm', 'car_rental', 'doctor', 'laundry', 'lodging', 'pharmacy', 'post_office', 'taxi_stand'];
*/


// Recursive function to perfom indepth calls (api calls to next_page_tokens) to google places api
const indepth_nearby_places = (all_urls, place_id_array, place_array, page_chain = 0, callback) => {
    if (page_chain >= 10 || page_chain < 0) {
        return callback(`DANGEROUS REQUEST: page_chain = ${page_chain}`);
    }
    var axios_reqs = [];
    all_urls.forEach(el => {
        axios_reqs.push(axios.get(el));
    });
    var next_urls = [];
    axios.all(axios_reqs).then(axios.spread((...resps) => {
        for (x = 0; x < resps.length; x++) {
            // Bad response (due to illegal url or failed response from google places api)
            if ((resps[x].status != 200) || (resps[x].data.status != 'OK' && resps[x].data.status != 'ZERO_RESULTS')) {
                console.log('Bad response from Google Places API: status:', resps[x].status, 'data.status:', resps[x].data.status);
                return callback('FAILURE');
            }
            // Good response from google places api
            if (resps[x].data.status == 'OK') {
                resps[x].data.results.forEach(el => {
                    if (!place_id_array.includes(el.place_id)) {
                        place_id_array.push(el.place_id);
                        place_array.push({
                            'name': el.name,
                            'types': el.types,
                            'place_id': el.place_id,
                            'location': el.geometry.location,
                            'rating': el.rating,
                            'price_level': el.price_level,
                            'address': el.vicinity
                        });
                    }
                });
                // Add next page url in next_urls if next_page_token exists
                if (resps[x].data.next_page_token) {
                    next_urls.push(all_urls[x].split('&pageToken=')[0] + `&pageToken=${resps[x].data.next_page_token}`);
                }
            }
        }
        // Return if we hit page_chain limit or if no next_page_tokens were recieved
        if (page_chain == 0 || next_urls.length == 0) { // <= instead of < since < will result in infinite recursion (racks up very large bill if misused)
            var to_ret = {
                places: place_array,
                size: place_array.length
            };
            return callback(to_ret);
        }
        indepth_nearby_places(next_urls, place_id_array, place_array, page_chain - 1, callback);
    })).catch(err => {
        console.log('Unable to send request to Google Places API', err);
        return callback('FAILURE');
    });
};

module.exports = indepth_nearby_places;