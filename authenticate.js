var passport = require('passport');
var localstrategy = require('passport-local').Strategy;
var User = require('./models/user');
var JwtStrategy =  require('passport-jwt').Strategy;
var ExtractJwt = require('passport-jwt').ExtractJwt;
var jwt = require('jsonwebtoken');
var config = require('./config');

passport.use(new localstrategy(User.authenticate()));
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());
//this function is used to create the token
exports.getToken = function(user) {
    return jwt.sign(user, config.secretkey, 
        {expiresIn: 36000});
}

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken(); // use to extract the jwt token from incoming request
opts.secretOrKey = config.secretkey;

console.log(opts.secretOrKey );
exports.jwtPassport = passport.use(new JwtStrategy(opts,
    (jwt_payload, done) => {
        console.log("JWT payload: ", jwt_payload);
        User.findOne({_id: jwt_payload._id}, (err, user) => {
            if (err) {
                return done(err, false);
            }
            else if (user) {
                return done(null, user);
            }
            else {
                return done(null, false);
            }
        });
    }));


exports.verifyUser = passport.authenticate('jwt', {session : false});