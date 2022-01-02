const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var UserSchema = new Schema({
        email: { type: String, required: true, unique: true },
        password: { type: String, required: true },
        preferences: [{ type: Number, required: true }],
    }, 
    {timestamps: true}
);

module.exports = mongoose.model('User', UserSchema);