var bunyan = require('bunyan');

var log = bunyan.createLogger({
    name: "smarthome",
    streams: [
        {
            stream: process.stdout,
            level: "debug"
        }
    ]
});

module.exports = log;