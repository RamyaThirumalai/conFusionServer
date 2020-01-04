const mongoose = require('mongoose');
var schema = mongoose.Schema;
var passportlocalmongoose = require('passport-local-mongoose');

var User = new schema({
    firstname : {
        type : String,
        default : ''
    },
    lastname : {
        type: String,
        default : ''
    },
    admin: {
        type: Boolean,
        default: false
    }
})

User.plugin(passportlocalmongoose);
module.exports = mongoose.model('User', User);