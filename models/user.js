const mongoose = require('mongoose');
const passportLocalMongoose = require('passport-local-mongoose'); // Corrected spelling
const Schema = mongoose.Schema;

const userSchema = new Schema({
    email: {
        type: String,
        required: true,
        unique: true
    },
    username: {
        type: String,
        required: true,
        unique: true
    }
});

// Apply the passport-local-mongoose plugin to the user schema
userSchema.plugin(passportLocalMongoose);

module.exports = mongoose.model('User', userSchema);
