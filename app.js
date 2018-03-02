const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const morgan = require('morgan');
const app = express();

const port = process.env.PORT || 3000;

app.use(bodyParser.json());
app.use(cookieParser());

let logger = morgan(function(tokens, req, res) {
    return [
        tokens.method(req, res),
        tokens.url(req, res),
        tokens.status(req, res),
        req.body.vote || 'NONE',
        tokens['response-time'](req, res), 'ms',
    ].join(' ');
});
app.use(logger);

app.use(express.static(__dirname + '/public'));

app.listen(port, function() {
    console.log('Poll listening on port ' + port);
});
