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

/* eslint require-jsdoc: "off" */
/* eslint valid-jsdoc: "off" */

/**
 * Structure of Data
 * {
 *   <uid>: {
 *     <device id>: {
 *       properties: {
 *         <property name>: <property value>,
 *         <property name>: <property value>
 *       },
 *       states: {
 *         <state name>: <state value>,
 *         <state name>: <state value>
 *       }
 *     },
 *     <device id>: {...}
 *   },
 *   <uid>: {
 *     <device id>: {...},
 *     <device id>: {...},
 *     <device id>: {...}
 *   },
 *   ...
 * }
 */
const Datastore = require('nedb');
const uuidv4 = require('uuid/v4');
const _ = require('lodash');

const config = require('./config-provider');
const log = require('./logger');

const db = {};
const Auth = {};
const Data = {};

// Devices
db.devices = new Datastore({ autoload: true, filename: config.datastore.devicesFileLocation });
// Users
db.users = new Datastore({ autoload: true, filename: config.datastore.usersFileLocation, onload: err => {
  if(err)
    throw err;

  // TODO manage users through dedicated webservices
  Auth.getUserByUsername('rick').then(doc => {
    if(!doc) {
      db.users.insert({
        uid: uuidv4(),
        username: 'rick',
        password: 'oldman'
      });
    }
  });
} });
// Clients have access to the API
db.clients = new Datastore({ autoload: true, filename: config.datastore.clientsFileLocation, onload: err => {
  if(err)
    throw err;
  
  db.clients.update(
    { clientId: config.smartHomeProviderGoogleClientId }, 
    { clientId: config.smartHomeProviderGoogleClientId, clientSecret: config.smartHomeProvideGoogleClientSecret },
    { upsert: true });
}});
// Authcodes are used to get an access token
db.authcodes = new Datastore({ autoload: true, filename: config.datastore.authcodesFileLocation });
// Tokens are used to identify an user
db.accessTokens = new Datastore({ autoload: true, filename: config.datastore.accessTokensFileLocation, onload: err => {
  if(err)
    throw err;

} });
// Refresh tokens are used to get new tokens
db.refreshTokens = new Datastore({ autoload: true, filename: config.datastore.refreshTokensFileLocation });

// TODO : temporary for test purposes
/*
db.accessTokens.insert({
  uid: uid,
  clientId: config.smartHomeProviderGoogleClientId,
  token: uuidv4(),
  expiresAt: new Date(Date.now() + (60 * 10000))
});
*/

/**
 * get a full status for everything stored for a user
 *
 * @param uid
 * @return
 * {
 *   uid: <uid>,
 *   devices: {
 *     <device id>: {
 *       properties: {
 *         <property name>: <property value>,
 *         <property name>: <property value>
 *       },
 *       states: {
 *         <state name>: <state value>,
 *         <state name>: <state value>
 *       }
 *     },
 *     <device id>: {...},
 *     ...
 *   }
 * }
 */
Data.getDevicesByUserUID = function(uid) {
  return new Promise((resolve, reject) => db.devices.find({ uid: uid }, (err, docs) => {
    if(err) {
      return reject(err);
    }
    return resolve(docs);
  }));
};

/**
 * get current states for all devices stored for a user
 *
 * @param uid
 * @param deviceIds
 * @return
 * {
 *   <device id>: {
 *     <state name>: <state value>,
 *     <state name>: <state value>
 *   },
 *   <device id>: {...},
 * }
 */
// TODO : a sortir de 'database'
Data.getStates = async function(uid, deviceIds = undefined) {
  let states = {};

  let devices = (!deviceIds) ? await Data.getDevicesByUserUID(uid) : await Data.getDevicesById(uid, deviceIds);
  devices.forEach(function(device) {
    states[device.deviceId] = device.states;
  });

  return states;
};

/**
 * get properties for all devices stored for a user
 *
 * @param uid
 * @param deviceIds
 * @return
 * {
 *   <device id>: {
 *     <property name>: <property value>,
 *     <property name>: <property value>
 *   },
 *   <device id>: {...},
 * }
 */
Data.getProperties = async function(uid, deviceIds = undefined) {
  let properties = {};

  let devices = (!deviceIds) ? await Data.getDevicesByUserUID(uid) : await Data.getDevicesById(uid, deviceIds);
  devices.forEach(function(device) {
    properties[device.deviceId] = device.properties;
  });

  return properties;
};

Data.getDeviceById = (uid, deviceId) => {
  return new Promise((resolve, reject) => db.devices.findOne({ "uid": uid, "deviceId": deviceId }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Data.getDevicesById = (uid, deviceIds) => {
  let req = (deviceIds) ? { "uid": uid, "deviceId": { $in: deviceIds } } : { "uid": uid };
  return new Promise((resolve, reject) => db.devices.find(req, function (err, docs) {
    if(err) {
      return reject(err);
    }
    resolve(docs);
  }));
}

/**
 * update a device
 *
 * @param uid
 * @param device
 * {
 *   states: {
 *     on: true,
 *     online: true
 *      ...
 *   },
 *   properties: {
 *     name: "smart home light 1",
 *     firmware: "1fzxa84232n4nb6478n8",
 *     traits: ["onoff"],
 *     nickname: "kitchen light",
 *     type: "light",
 *      ...
 *   }
 * }
 */
Data.execDevice = async function(uid, deviceDto) {
  let device = { deviceId: deviceDto.deviceId, uid: uid };
  let deviceFromDatabase = await Data.getDeviceById(uid, device.deviceId) || device;
  if (deviceDto.hasOwnProperty('properties')) {
    device.properties = _.cloneDeep(deviceDto.properties);
  }
  if (deviceDto.hasOwnProperty('states')) {
    device.states = _.cloneDeep(deviceDto.states);
  }
  if (deviceDto.hasOwnProperty('executionStates')) {
    device.executionStates = _.cloneDeep(deviceDto.executionStates);
  }

  if(deviceFromDatabase !== device) {
    _.merge(deviceFromDatabase, device);
  }

  return new Promise((resolve, reject) => db.devices.update({ "uid": uid, "deviceId": deviceDto.deviceId }, { $set: deviceFromDatabase }, { upsert: true }, (err, numberOfUpdated, upsert) => {
    if(err) {
      return reject(err);
    }
    resolve(numberOfUpdated);
  }));
};

/**
 * register or update a device
 *
 * @param uid
 * @param device
 */
Data.registerDevice = async function(uid, device) {
  // wrapper for exec, since they do the same thing
  await Data.execDevice(uid, device);
};

/**
 * resets user account, deleting all devices
 */
Data.resetDevices = function(uid) {
  console.info('Deleting all devices for ' + uid);

  db.devices.remove({ uid: uid });
};

/**
 * removes a device for user
 *
 * @param uid
 * @param device
 */
Data.removeDevice = function(uid, device) {
  console.info('Deleting device ' + device.deviceId + ' for ' + uid);
  db.devices.remove({ deviceId: device.deviceId, uid: uid });
};

/**
 * checks if user and auth exist and match
 *
 * @param uid
 * @param authToken
 * @return {boolean}
 */
Data.isValidAuth = async function(uid, authToken) {
  let token = await Auth.getAccessToken(authToken);
  return (token && token.uid === uid);
};

Auth.getUserByUsername = (username) => {
  return new Promise((resolve, reject) => db.users.findOne({ "username": username }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Auth.getUserByUID = (uid) => {
  return new Promise((resolve, reject) => db.users.findOne({ "uid": uid }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Auth.addAuthcode = (authcode) => {
  return new Promise((resolve, reject) => db.authcodes.insert(authcode, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Auth.getAuthcode = (code) => {
  return new Promise((resolve, reject) => db.authcodes.findOne({ "code": code }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Auth.getAccessToken = (token) => {
  return new Promise((resolve, reject) => db.accessTokens.findOne({ "token": token }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}
Auth.getRefreshToken = (token) => {
  return new Promise((resolve, reject) => db.refreshTokens.findOne({ "token": token }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}
Auth.getAccessTokenByUID = (uid) => {
  return new Promise((resolve, reject) => db.accessTokens.findOne({ "uid": uid, "expiresAt": { $gt: new Date() } }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Auth.addAccessToken = (token) => {
  return new Promise((resolve, reject) => db.accessTokens.insert(token, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}
Auth.addRefreshToken = (token) => {
  return new Promise((resolve, reject) => db.refreshTokens.insert(token, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

Auth.getClientById = (clientId) => {
  return new Promise((resolve, reject) => db.clients.findOne({ "clientId": clientId }, function (err, doc) {
    if(err) {
      return reject(err);
    }
    resolve(doc);
  }));
}

exports.getDevicesByUserUID = Data.getDevicesByUserUID;
exports.getStates = Data.getStates;
exports.getProperties = Data.getProperties;
exports.isValidAuth = Data.isValidAuth;
exports.execDevice = Data.execDevice;
exports.registerDevice = Data.registerDevice;
exports.resetDevices = Data.resetDevices;
exports.removeDevice = Data.removeDevice;
exports.getDeviceById = Data.getDeviceById;
exports.getDevicesById = Data.getDevicesById;

exports.addAuthcode = Auth.addAuthcode;
exports.getAuthcode = Auth.getAuthcode;
exports.getUserByUsername = Auth.getUserByUsername;
exports.getUserByUID = Auth.getUserByUID;
exports.getAccessToken = Auth.getAccessToken;
exports.getRefreshToken = Auth.getRefreshToken;
exports.getAccessTokenByUID = Auth.getAccessTokenByUID;
exports.addRefreshToken = Auth.addRefreshToken;
exports.addAccessToken = Auth.addAccessToken;
exports.getClientById = Auth.getClientById;