const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const morgan = require('morgan');
const app = express();
const MongoClient = require('mongodb').MongoClient;
const ObjectID = require('mongodb').ObjectID;
const RateLimit = require('express-rate-limit');
const crypto = require('crypto'),
    algorithm = 'aes-256-ctr',
    password = 'd6F3Efeq';

const dbUrl = process.env.MONGO_URL;
const port = process.env.PORT;
let db;


app.enable('trust proxy');

const USER_COOKIE_NAME = 'poll-cookie';

app.use(bodyParser.json());
app.use(cookieParser());

let logger = morgan(function(tokens, req, res) {
    return [
        tokens.method(req, res),
        tokens.url(req, res),
        tokens.status(req, res),
        _getCookie(req) || 'unknown', // TODO use chalk
        req.body.vote || 'NONE',
        tokens['response-time'](req, res), 'ms',
    ].join(' ');
});
app.use(logger);

app.use(express.static(__dirname + '/public'));

const postVoteLimiter = new RateLimit({
    windowMs: 60*60*1000, // one hour window
    delayAfter: 500, // begin slowing down responses after the first 500 request
    delayMs: 100, // slow down subsequent responses by 100 ms per request
    max: 1000, // start blocking after 1000 requests
    message: "Or you trying to hack me, or i made a bug",
    skip: function (req) { // allow users with cookie to vote anyway
        return _getVoteId(_getCookie(req), req.connection.remoteAddress, _getFingerprint(req));
    }
});

app.post('/vote', postVoteLimiter, (req, res) => {
    let fingerprint = _getFingerprint(req);
    if (!fingerprint) {
        res.sendStatus(400);
        return;
    }

    let cookie = _getCookie(req);

    let data = {
        fingerprint: fingerprint,
        vote: req.body.vote,
    };

    if (!cookie) {
        let generatedUserId = _generateUserId(req.connection.remoteAddress, fingerprint);
        insertNewVote(data, res, generatedUserId);
    } else {
        let id = _getVoteId(cookie, req.connection.remoteAddress, fingerprint);
        if (id) {
            updateVote(id, data, res);
        } else {
            fuckHackers(res);
        }
    }
});

app.get('/vote', (req, res) => {
    let cookieUserId = _getVoteId(_getCookie(req), req.connection.remoteAddress, _getFingerprint(req));

    if (!cookieUserId) {
        fuckHackers(res);
        return;
    }
    db.collection('votes').findOne(_getVoteQuery(cookieUserId))
        .then((result) => {
            if (!result) {
                res.clearCookie(USER_COOKIE_NAME);
                res.sendStatus(401);
            } else {
                res.send({vote: result.vote});
            }
        });
});

app.get('/stats', (req, res) => {
    db.collection('votes').aggregate(
        [{$group: {_id: '$vote', count: {$sum: 1}}}], {}, (err, result) => {
            if (err) {
                res.status(500).send(err);
            }
            res.send(result);
        });
});

function _getCookie(req) {
    return req.cookies[USER_COOKIE_NAME];
}

function _generateUserId(ipAddr, fingerPrint) {
    return ipAddr + fingerPrint;
}

function _getVoteId(cookie, ipAddress, fingerprint) {
    try {
        if (!cookie) {
            return null;
        }
        let decrypted = decrypt(cookie);
        let userId = ipAddress + fingerprint;
        if (!decrypted.startsWith(userId)) {
            return null;
        }
        return decrypted.replace(userId, '');
    } catch(e) {

    }
    return null;
}

function _getFingerprint(req) {
    return req.headers['fingerprint'];
}

function insertNewVote(data, res, userID) {
    db.collection('votes').insertOne(data)
        .then((result) => {
            let str = encrypt(userID + result.insertedId);
            res.cookie(USER_COOKIE_NAME, str, {
                maxAge: 30 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                secure: false,
            });
            res.sendStatus(200);
        });
}

function updateVote(cookieUserId, data, res) {
    let query = _getVoteQuery(cookieUserId);
    db.collection('votes').updateOne(query, data)
        .then(() => {
            res.sendStatus(200);
        });
}

function _getVoteQuery(cookieUserId) {
    let id = new ObjectID(cookieUserId);
    return {_id: id};
}

function encrypt(text){
    let cipher = crypto.createCipher(algorithm,password)
    let crypted = cipher.update(text,'utf8','hex')
    crypted += cipher.final('hex');
    return crypted;
}

function decrypt(text){
    let decipher = crypto.createDecipher(algorithm,password)
    let dec = decipher.update(text,'hex','utf8')
    dec += decipher.final('utf8');
    return dec;
}

function fuckHackers(res) {
    res.status(400).send('Don`t try to hack me!');
}

MongoClient.connect(dbUrl, (err, database) => {
    if (err) {
        return console.log(err);
    }
    db = database;
    app.listen(port, function() {
        console.log('Poll listening on port ' + port);
    });
});
