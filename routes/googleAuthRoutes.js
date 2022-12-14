const express = require('express');
const passport = require('passport');
const { pool } = require('../config/dbConfig');
const { checkAuthenticated, checkNotAuthenticated } = require('../utilities/utility')

//TODO: create Class without need to import passport

const googleRouter = express.Router();

googleRouter.get('/', checkAuthenticated, passport.authenticate('google', { 
    scope: ['profile', 'email'] })
);

googleRouter.get('/callback', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        console.log('Login Success');
        const gUser = req.user._json;

        // check for user in database
        pool.query(
            'SELECT * FROM users WHERE userOAuthID = $1', [gUser.sub], (err, results) => {
                if (err) {
                    throw err;
                }

                const googleUser = results.rows[0];

                if(googleUser === undefined || googleUser === null ) {
                    //console.log('user is undefined')
                    pool.query(
                        'INSERT INTO users (name, email, useroauthid) VALUES ($1, $2, $3)', [gUser.name, gUser.email, gUser.sub], (err, results) => {
                            if(err) {
                                throw err;
                            }

                            res.redirect('/users/dashboard');

                        }
                    );

                } else {
                    //console.log('user is in the database')
                    res.redirect('/users/dashboard');

                }
            }
        )
    }
);

module.exports = googleRouter;