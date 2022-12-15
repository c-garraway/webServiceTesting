const express = require('express');
const app = express();
const { pool, connectionString } = require('./config/dbConfig')
const bcrypt = require('bcrypt');
const session = require('express-session');
const flash = require('express-flash');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const cors = require('cors');

const PORT = process.env.EXPRESS_PORT || 4000;

const authenticateLocalUser = (email, password, done) => {
    pool.query(
        'SELECT * FROM users WHERE email = $1', [email], (err, results) => {
            if (err) {
                throw err;
            }
            //console.log(results.rows);

            if(results.rows.length > 0) {
                const user = results.rows[0];

                bcrypt.compare(password, user.password, (err, isMatch) => {
                    if(err) {
                        throw err
                    }
                    if(isMatch) {
                        return done(null, user);
                    } else {
                        return done(null, false, {message: 'Password is not correct'});
                    }
                });

            } else {
                return done(null, false, {message: 'Email is not registered'});
            }
        } 
    );
};

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
    },
    function(accessToken, refreshToken, profile, cb) {
        //console.log(profile);
        cb(null, profile);
}
));

passport.use(
    new LocalStrategy(
        {
            usernameField: 'email',
            passwordField: 'password'
        },
        authenticateLocalUser
    )
);

passport.serializeUser((user, done) => {
    done(null, user)
});

passport.deserializeUser((user, done) => {
    done(null, user)
});


app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: false}));

const conObject = {
    connectionString,
    //ssl: { rejectUnauthorized: false }
};

app.use(session({
    store: new (require('connect-pg-simple')(session))({
        conObject,
    }),
    secret: process.env.SESSION_SECRET,
    saveUninitialized: false,
    resave: false,
    cookie: { 
        secure: false,
        httpOnly: false,
        sameSite: false,
        maxAge: 24 * 60 * 60 * 1000
     } // 24 hours
    // Insert express-session options here
}));

app.use(passport.initialize());
app.use(passport.session());
app.use(flash());
app.use(cors());

const googleRouter = require('./routes/googleAuthRoutes');
app.use('/google', googleRouter);

const usersRouter = require('./routes/usersRoutes');
app.use('/users', usersRouter);

app.get('/', (req, res) => {
    res.render('index');
});

app.listen(PORT, ()=>{
    console.log(`Server running on port ${PORT}`)
});
