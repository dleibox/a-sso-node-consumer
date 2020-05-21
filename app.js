const express = require('express');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const app = express();
// const session = require("express-session");

const ssoURL = (process.env.SSOURL || `http://sso.localhost:8888`) + `/a-sso`;

app.use(cookieParser());

const isAuthenticated = async (req, res, next) => {
    // simple check to see if the user is authenicated or not,
    // if not redirect the user to the SSO Server for Login
    // pass the redirect URL as current URL
    // appURL is where the sso should redirect in case of valid user
    const redirectURL = `${req.protocol}://${req.headers.host}${req.path}`;
    const ssoLogin = `${ssoURL}/login?appURL=${redirectURL}`;
    const token = req.cookies.app_token;
    if (token) {
        try {
            const decoded = await verifyJwtToken(token);
            console.log('---app_token valid---:');
        } catch (err) {
            return res.redirect(ssoLogin);
        }
    } else {
        return res.redirect(ssoLogin);
    }
    next();
};

const ssoServerJWTURL = `${ssoURL}/verifykey`;
const url = require('url');
const axios = require('axios');
const fs = require('fs');
const path = require('path');
const ISSUER = 'a-sso';
const jwt = require('jsonwebtoken');
const publicKey = fs.readFileSync(path.resolve(__dirname, './jwtPublic.key'));
const verifyJwtToken = async (token) => {
    return new Promise((resolve, reject) => {
        jwt.verify(token, publicKey, { issuer: ISSUER, algorithms: ['RS256'] }, (err, decoded) => {
            if (err) return reject(err);
            return resolve(decoded);
        });
    });
};
const checkSSORedirect = () => {
    return async function (req, res, next) {
        // check if the req has the queryParameter as ssoKey and who is the referer.
        const { ssoKey } = req.query;
        if (ssoKey != null) {
            // to remove the ssoKey in query parameter redirect.
            const redirectURL = url.parse(req.url).pathname;

            try {
                const response = await axios.get(`${ssoServerJWTURL}?ssoKey=${ssoKey}`, {
                    headers: {
                        Authorization: 'Bearer 8888',
                    },
                });
                const { token } = response.data;
                const decoded = await verifyJwtToken(token);
                console.log('---app_token---:', token);
                res.cookie('app_token', token, { maxAge: 2 * 60 * 1000 });
                // // now that we have the decoded jwt, use the,
                // // global-session-id as the session id so that
                // // the logout can be implemented with the global session.
                // req.session.user = decoded;
            } catch (err) {
                return next(err);
            }
            console.log('---redirectURL---:', redirectURL);
            return res.redirect(`${redirectURL}`);
        }

        return next();
    };
};

// app.use(
//     session({
//         secret: 'keyboard cat',
//         resave: false,
//         saveUninitialized: true,
//     })
// );

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(morgan('dev'));
// app.engine('ejs', engine);
app.set('views', __dirname + '/views');
app.set('view engine', 'ejs');
app.use(checkSSORedirect());

app.get('/favicon.ico', function (req, res) {
    res.sendStatus(204);
});

app.get('/', isAuthenticated, (req, res, next) => {
    res.render('index', {
        title: 'SSO-Consumer | Home',
        sso: `${req.cookies.app_token}`,
    });
});

app.use((req, res, next) => {
    // catch 404 and forward to error handler
    const err = new Error('Resource Not Found');
    err.status = 404;
    next(err);
});

app.use((err, req, res, next) => {
    console.error({
        message: err.message,
        error: err,
    });
    const statusCode = err.status || 500;
    let message = err.message || 'Internal Server Error';

    if (statusCode === 500) {
        message = 'Internal Server Error';
    }
    res.status(statusCode).json({ message });
});

module.exports = app;
