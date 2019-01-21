// Copyright 2017, Google, Inc.
// Licensed under the Apache License, Version 2.0 (the 'License');
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an 'AS IS' BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

const bodyParser = require('body-parser');
const express = require('express');
const fetch = require('node-fetch');
const morgan = require('morgan');
const ngrok = require('ngrok');
const session = require('express-session');
const cors = require('cors');
const uuidv4 = require('uuid/v4');
const _ = require('lodash');

// internal app deps
const log = require('./logger');
const googleHa = require('./smart-home-app');
const datastore = require('./datastore');
const authProvider = require('./auth-provider');
const config = require('./config-provider');
const frontendLink = require('./frontend-link');
const devicesProvider = require('./devices-provider');

const sendError = (res, status, message) => error => {
  log.error({err: error}, message || error.message);
  res.status(status || error.status).json({
    type: 'error', 
    message: message || error.message
  });
};
const sendSuccess = (res, message) => data => {
  res.status(200).json({type: 'success', message, data})
};

// Check that the API key was changed from the default
if (config.smartHomeProviderApiKey === '<API_KEY>') {
  console.warn('You need to set the API key in config-provider.\n' +
    'Visit the Google Cloud Console to generate a key for your project.\n' +
    'https://console.cloud.google.com\n' +
    'Exiting...');
  process.exit();
}

const app = express();
app.use(cors());
app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));
app.set('trust proxy', 1); // trust first proxy
app.use(session({
  genid: (req) => {
    return uuidv4();
  },
  secret: 'xyzsecret',
  resave: false,
  saveUninitialized: true,
  cookie: {secure: false},
}));
// eslint-disable-next-line max-len
const requestSyncEndpoint = 'https://homegraph.googleapis.com/v1/devices:requestSync?key=';

/**
 * auth method
 *
 * required headers:
 * - Authorization
 *
 * TODO: Consider moving auth checks into its own request handler/middleware
 *       (http://expressjs.com/en/guide/writing-middleware.html)
 */
app.post('/smart-home-api/auth', async (request, res) => {
  try {
    // TODO : vérifier si on doit pas utiliser le authCode généré dans l'appel à /login plutôt que que le token directement
    // nécéssite maj frontend
    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});;
      return;
    }

    if (!await datastore.isValidAuth(token.uid, authToken)) {
      res.status(403).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({success: false, error: 'failed auth'});
      return;
    }
  
    res.status(200)
      .set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      })
      .send({success: true});
  } catch(err) {
    sendError(res, 500)(err);
  }
});

/**
 * Can be used to register a device.
 * Removing a device would be supplying the device id without any traits.
 *
 * requires auth headers
 *
 * body should look like:
 * {
 *   id: <device id>,
 *   properties: {
 *      type: <>,
 *      name: {},
 *      ...
 *   },
 *   state: {
 *      on: true,
 *      ...
 *   }
 * }
 */
app.post('/smart-home-api/register-device', async (request, res) => {
  try {
    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});
      return;
    }

    if (!await datastore.isValidAuth(token.uid, authToken)) {
      console.error('Invalid auth', authToken, 'for user', token.uid);
      res.status(403).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid auth'});
      return;
    }

    let device = request.body;
    await datastore.registerDevice(token.uid, device);

    let registeredDevice = await datastore.getDeviceById(token.uid, device.deviceId);
    if (!registeredDevice) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'failed to register device'});
      return;
    }

    app.requestSync(authToken, token.uid);

    // otherwise, all good!
    res.status(200)
      .set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      })
      .send(registeredDevice);
  } catch(err) {
    sendError(res, 500)(err);
  }
});

/**
 * Can be used to unregister a device.
 * Removing a device would be supplying the device id without any traits.
 */
app.post('/smart-home-api/remove-device', async (request, res) => {
  try {
    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});;
      return;
    }

    if (!await datastore.isValidAuth(token.uid, authToken)) {
      console.error('Invalid auth', authToken, 'for user', token.uid);
      res.status(403).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid auth'});
      return;
    }

    let device = request.body;
    datastore.removeDevice(token.uid, device);

    let removedDevice = await datastore.getDeviceById(token.uid, device.deviceId);
    if (removedDevice) {
      res.status(500).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'failed to remove device'});
      return;
    }

    app.requestSync(authToken, token.uid);

    // otherwise, all good!
    res.status(200)
      .set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      })
      .send({
        uid: token.uid,
        devices: _.keyBy(await datastore.getDevicesByUserUID(token.uid), 'deviceId')
      });
  } catch(err) {
    sendError(res, 500)(err);
  }
});

/**
 * Can be used to modify state of a device, or to add or remove a device.
 * Removing a device would be supplying the device id without any traits.
 *
 * requires auth headers
 *
 * body should look like:
 * {
 *   id: <device id>,
 *   type: <device type>,
 *   <trait name>: <trait value>,
 *   ...
 * }
 */
app.post('/smart-home-api/exec', async (request, res) => {
  try {
    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});
      return;
    }

    if (!await datastore.isValidAuth(token.uid, authToken)) {
      res.status(403).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid auth'});
      return;
    }

    let device = request.body;
    await datastore.execDevice(token.uid, device); // Database update (only requested fields)

    // TODO : transform response
    let executedDevice = await datastore.getDeviceById(token.uid, device.deviceId); // Get device full state
    if (!executedDevice) {
      res.status(500).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'failed to exec device'});
      return;
    }

    if (device.nameChanged) {
      log.info('calling request sync from exec to update name');
      app.requestSync(authToken, token.uid);
    }

    // TODO : update 'online' state
    await devicesProvider.sendCommand(executedDevice.properties.name.name, JSON.stringify({
      on: executedDevice.states.on, 
      color: executedDevice.states.color.spectrumRGB, 
      brightness: executedDevice.states.brightness
    }));

    // otherwise, all good!
    res.status(200)
      .set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      })
      .send({'deviceId': executedDevice.deviceId});
  } catch(err) {
    sendError(res, 500)(err);
  }
});

/*
app.post('/smart-home-api/execute-scene', async(request, res) => {
  try {
    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});
      return;
    }

    reqdata = request.body;
    data = {
      requestId: reqdata.requestId,
      uid: token.uid,
      auth: authToken,
      commands: reqdata.inputs[0].payload.commands,
    };

    return googleHa.registerAgent.exec(data, res);
  } catch(err) {
    sendError(res, 500)(err);
  }
});
*/

/**
 * This is how to query.
 *
 * req body:
 * [<device id>,...] // (optional)
 *
 * response:
 * {
 *   <device id>: {
 *     <trait name>: <trait value>,
 *     <trait name>: <trait value>,
 *     <trait name>: <trait value>,
 *     ...
 *   },
 *   <device id>: {
 *     <trait name>: <trait value>,
 *     <trait name>: <trait value>,
 *     <trait name>: <trait value>,
 *     ...
 *   },
 * }
 */
app.post('/smart-home-api/status', async (request, res) => {
  try {
    // console.log('post /smart-home-api/status');

    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});
      return;
    }

    if (!await datastore.isValidAuth(token.uid, authToken)) {
      res.status(403).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid auth'});
      return;
    }

    let deviceList = request.body;
    if (!deviceList || !Object.keys(deviceList).length) {
      deviceList = null;
    }

    let devices = await datastore.getDevicesById(token.uid, deviceList);
    if (!devices) {
      res.status(500).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'failed to get device'});
      return;
    }

    res.status(200)
      .set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      })
      .send(_.keyBy(devices, 'deviceId'));
  } catch(err) {
    sendError(res, 500)(err);
  }
});

/**
 * Creates an Server Send Event source for a device.
 * Called from a device.
 */
app.get('/smart-home-api/device-connection/:deviceId', (req, res) => {
  const deviceId = req.params.deviceId;
  
  frontendLink.register(deviceId, res);

  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.connection.setTimeout(0);
  res.on('close', () => {
    frontendLink.unregister(deviceId);
  });
});

// frontend UI
app.set('jsonp callback name', 'cid');

// TODO : The frontend should ask for an access_token
app.get('/getauthcode', async (req, res) => {
  try {
    /* forbid caching to force reload of getauthcode */
    res.set('Cache-Control', 'no-store, must-revalidate');
    /* set correct mime type else browser will refuse to execute the script*/
    res.set('Content-Type', 'text/javascript');

    if (!req.session.user) {
      let badaccess = req.headers.referer.indexOf('badaccess=true') >= 0;
      res.status(200).send('' +
        '(function(){' +
        'window.location.replace("/login?client_id=' +
        config.smartHomeProviderGoogleClientId +
        '&redirect_uri=/frontend&state=cool_jazz' +
        '&badaccess=' + badaccess + '")' +
        '})();' +
        '');// redirect to login
    } else {
      let accessToken = await datastore.getAccessTokenByUID(req.session.user.uid);
      res.status(200).send('' +
        'var AUTH_TOKEN = "' + accessToken.token + '";' +
        'var USERNAME = "' + req.session.user.username + '";' +
        '');
    }
  } catch(err) {
    sendError(res, 500)(err);
  }
});

app.post('/smarthome', async (req, res, next) => {
  try {
    let authToken = authProvider.parseAccessToken(req);
    if (!authToken) {
      throw new Error('missing auth headers');
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      throw new Error('invalid_grant');
    }

    if (!req.body.inputs) {
      throw new Error('missing inputs');
    }
  } catch(err) {
    next(err);
  }

  next();
}, googleHa);

app.use('/frontend', express.static('./frontend'));
app.use('/frontend/', express.static('./frontend'));
app.use('/', express.static('./frontend'));

app.requestSync = (authToken, uid) => {
  // REQUEST_SYNC
  const apiKey = config.smartHomeProviderApiKey;
  const options = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
  };
  optBody = {
    'agentUserId': uid,
  };
  options.body = JSON.stringify(optBody);
  console.info('POST REQUEST_SYNC', requestSyncEndpoint + apiKey);
  console.info(`POST payload: ${JSON.stringify(options)}`);
  fetch(requestSyncEndpoint + apiKey, options)
    .then((res) => {
      console.log('request-sync response', res.status, res.statusText);
    });
};

/**
 * Pushes the current state of a device to the HomeGraph
 */
app.post('/smart-home-api/report-state', async (request, res) => {
  try {
    let authToken = authProvider.parseAccessToken(request);
    if (!authToken) {
      res.status(401).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'missing auth headers'});
      return;
    }

    let token = await datastore.getAccessToken(authToken);
    if (!token) {
      res.status(400).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid_grant'});
      return;
    }

    if (!await datastore.isValidAuth(token.uid, authToken)) {
      console.error('Invalid auth', authToken, 'for user', token.uid);
      res.status(403).set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      }).json({error: 'invalid auth'});
      return;
    }

    let device = request.body;
    app.reportState(authToken, token.uid, device);

    // otherwise, all good!
    res.status(200)
      .set({
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      })
      .send({status: 'OK'});
  } catch(err) {
    sendError(res, 500)(err);
  }
});


app.reportState = (authToken, uid, device) => {
  const https = require('https');
  const {google} = require('googleapis');
  const jwtClient = new google.auth.JWT(
    config.jwt.client_email,
    null,
    config.jwt.private_key,
    ['https://www.googleapis.com/auth/homegraph'],
    null
  );

  const reportedStates = {};
  if (!device.reportStates) {
    console.warn(`Device ${device.deviceId} has no states to report`);
    return;
  }
  device.reportStates.map((key) => {
    reportedStates[key] = device.states[key];
  });
  const postData = {
    requestId: 'ff366a3cc', // Any unique ID
    agentUserId: uid,
    payload: {
      devices: {
        states: {
          [device.deviceId]: reportedStates,
        },
      },
    },
  };

  console.log('Report State request', JSON.stringify(postData));

  jwtClient.authorize((err, tokens) => {
    if (err) {
      console.error(err);
      return;
    }
    const options = {
      hostname: 'homegraph.googleapis.com',
      port: 443,
      path: '/v1/devices:reportStateAndNotification',
      method: 'POST',
      headers: {
        Authorization: ` Bearer ${tokens.access_token}`,
      },
    };
    return new Promise((resolve, reject) => {
      let responseData = '';
      const req = https.request(options, (res) => {
        res.on('data', (d) => {
          responseData += d.toString();
        });
        res.on('end', () => {
          resolve(responseData);
        });
      });
      req.on('error', (e) => {
        reject(e);
      });
      // Write data to request body
      req.write(JSON.stringify(postData));
      req.end();
    }).then((data) => {
      console.info('Report State response', data);
    });
  });
};

const appPort = process.env.PORT || config.devPortSmartHome;

const server = app.listen(appPort, () => {
  const host = server.address().address;
  const port = server.address().port;

  console.log('Smart Home Cloud and App listening at %s:%s', host, port);

  if (config.isLocal) {
    startNgrok();
  }
});

async function startNgrok() {
  const url = await ngrok.connect(config.devPortSmartHome);
    if (!url) {
      console.log('ngrok err');
      process.exit();
    }

    console.log('|###################################################|');
    console.log('|                                                   |');
    console.log('|        COPY & PASTE NGROK URL BELOW:              |');
    console.log('|                                                   |');
    console.log('|          ' + url + '                |');
    console.log('|                                                   |');
    console.log('|###################################################|');

    console.log('=====');
    console.log('Visit the Actions on Google console at http://console.actions.google.com');
    console.log('Replace the webhook URL in the Actions section with:');
    console.log('    ' + url + '/smarthome');

    console.log('In the console, set the Authorization URL to:');
    console.log('    ' + url + '/oauth');

    console.log('');
    console.log('Then set the Token URL to:');
    console.log('    ' + url + '/token');
    console.log('');

    console.log('Finally press the \'TEST DRAFT\' button');
}

authProvider.registerAuth(app);

console.log('\n\nRegistered routes:');
app._router.stack.forEach((r) => {
  if (r.route && r.route.path) {
    console.log(r.route.path);
  }
});

