//----------------------------------------
// Imports
//----------------------------------------
if(!process.env.VERCEL_ENV) require('dotenv').config();
const express = require('express');
const cors = require('cors');
const app = express().use(cors()).use(express.json());
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const User = require('../model/user');

//----------------------------------------
// Configurations for bodyParser
//----------------------------------------
var urlencodedParser = bodyParser.urlencoded({ extended: false });
var jsonParser = bodyParser.json();

//----------------------------------------
// MF Configurations
//----------------------------------------
app.use(urlencodedParser); // Attach body-parser middleware
app.use(jsonParser); // Parse JSON data

//----------------------------------------
// Testing authServer
app.get('/', (req, res) => {
    res.send('Helloooooo My Auth Server!');
});

//----------------------------------------
// Start of Login/API Key Endpoints

// Generate Access Token when user login [done]
// http://localhost:4001/login
app.post('/login', function (req, res) {
    let loginData = {
        user: req.body.loginUserName, // get from authenticateToken return
        pass: req.body.loginUserPass,
    };
    let rememberMe = req.body.rmbMeCheck;

    User.login(loginData).then((result) => {
        if (result.err) {
            res.status(404).json({ error: result.err });
        } else {
            const user = { id: result.userId };
            // to serialize user using login data and the secret key
            const accessToken = jwt.sign(
                user,
                process.env.ACCESS_TOKEN_SECRET,
                {
                    expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
                }
            );
            // return both refreshToken and accessToken when user select remember me
            if (rememberMe) {
                const refreshToken = jwt.sign(
                    user,
                    process.env.REFRESH_TOKEN_SECRET
                );

                //-------------------------------------------------------
                res.status(200).json({
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                });
            } else {
                res.status(200).json({ accessToken: accessToken });
            }
        }
    });
});

// Verify access token [done]
// http://localhost:4001/token
app.post('/verifyToken', function (req, res, next) {
    console.log("verifytoken")
    console.log(req.headers['authorization']);
    const authHeader = req.headers['authorization'];
    // console.log(authHeader);
    let accessToken = authHeader && authHeader.split(' ')[1]; // get token from req header: Bearer TOKEN
    const refreshToken = authHeader && authHeader.split(' ')[2];

    console.log('Your accessToken is: ' + accessToken);
    console.log('Your refreshToken is: ' + refreshToken);

    // check if the token match
    jwt.verify(
        accessToken,
        process.env.ACCESS_TOKEN_SECRET,
        // when have both token expired and secret not match, return JsonWebTokenError
        (err, user) => {
            if (err) {
                if (
                    (err.name === 'TokenExpiredError' ||
                        accessToken === 'null') &&
                    refreshToken !== 'null'
                ) {
                    // when got refresh token
                    const regeResult = regeAccessToken(refreshToken);
                    req.userId = regeResult.user; //regeResult.user = user.id
                    req.newAccessToken = regeResult.newAccessToken; // ------------------ should be return also then set in local storage
                    return res.status(200).json({
                        userId: req.userId,
                        newAccessToken: accessToken,
                    });
                } else {
                    // dont have valid token, the secret does not match
                    // JsonWebTokenError
                    return res
                        .status(401)
                        .json({ error: err.name + ' Not authorized' });
                }
                // totally no err
            } else {
                // verify successfully, return the data we serialized (here just return username)
                return res.status(200).json({ userId: user });
            }
        }
    );
});

// Verify access token [working]
// http://localhost:4001/token
app.post('/verifyMailToken', function (req, res, next) {
    console.log(req.headers['authorization']);
    const authHeader = req.headers['authorization'];
    console.log(authHeader);
    let emailSecretToken = authHeader && authHeader.split(' ')[1];

    console.log('Your emailSecretToken is: ' + emailSecretToken);

    // check if the token match
    jwt.verify(
        emailSecretToken,
        process.env.EMAIL_SECRET,
        // when have both token expired and secret not match, return JsonWebTokenError
        (err, user) => {
            if (err) {
                if (err.name === 'TokenExpiredError') {
                    return res.status(403).json({
                        error:
                            err.name +
                            ' Your Email link is expired! Please resend again!',
                    });
                } else {
                    // dont have valid token, the secret does not match
                    // JsonWebTokenError
                    return res.status(401).json({
                        error: err.name + ' Your Email token is not valid!',
                    });
                }
                // totally no err
            } else {
                // verify successfully, return the data we serialized (here just return username)
                console.log('User Email: ' + user);
                return res.status(200).json({ userEmail: user });
            }
        }
    );
});

// Regenerate new access token [done]
// http://localhost:4001/regeToken
app.post('/regeToken', function (req, res, next) {
    const authHeader = req.headers['authorization'];
    const refreshToken = authHeader && authHeader.split(' ')[1];

    if (refreshToken == null)
        return res.status(401).json({
            error: 'Refresh Token not valid!',
        });
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: err });
        accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        });
        res.status(201).json({ newAccessToken: accessToken });
    });
});

function regeAccessToken(refreshToken) {
    if (refreshToken == null)
        return res.status(401).json({
            error: 'Refresh Token not valid!',
        });

    console.log('regenerate token...........');
    let newAccessToken, userId, error;
    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
        if (err) {
            error = err;
        }
        console.log('regeToken user: ' + user.id);
        newAccessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
        });
        console.log(user); // user obj

        userId = user.id;
        console.log('Your new access token:' + newAccessToken);
    });
    if (error != undefined) {
        return { error: error };
    } else {
        return { newAccessToken: newAccessToken, user: userId };
    }
}

// End of Login/API Key Endpoints
//----------------------------------------

//----------------------------------------
// Module Exports
//----------------------------------------
module.exports = app;
