const GoogleStrategy = require('passport-google-oauth20').Strategy;

function initializeGoogle(passport) {

    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL
        },
        function(accessToken, refreshToken, profile, cb) {
            console.log(profile);
            cb(null, profile);
    }
    ));

    passport.serializeUser((user, done) => {
        done(null, user.id)
    })

    passport.deserializeUser((user, done) => {
        done(null, user)
    });
};

module.exports = initializeGoogle;
