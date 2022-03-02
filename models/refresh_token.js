const mongoose = require('mongoose');
var Schema = mongoose.Schema;

var RefreshTokenSchema = new Schema({
        email: { type: String, required: true, unique: true }
    },
    { timestamps: true }
);

module.exports = mongoose.model('Refresh_Token', RefreshTokenSchema);