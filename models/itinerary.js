const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var ItinerarySchema = new Schema({
        email: { type: String, required: true,},
        
    }, 
    { timestamps: true } 
);

module.exports = mongoose.model('User', UserSchema);