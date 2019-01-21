const { smarthome } = require('actions-on-google');

const config = require('./config-provider');
const datastore = require('./datastore');
const frontendLink = require('./frontend-link');
const devicesProvider = require('./devices-provider');
const log = require('./logger');

const app = smarthome({
  debug: true,
  jwt: config.jwt,
  key: config.smartHomeProviderApiKey
});

app.getUserUID = async (headers) => {
  let tokenCode = headers.authorization.split(' ')[1];
  let accessToken = await datastore.getAccessToken(tokenCode);
  return accessToken.uid;
}

app.onExecute(async (body, headers) => {
  var userUID = await app.getUserUID(headers);

  let commands = body.inputs[0].payload.commands;
  let respCommands = [];
  for (let i = 0; i < commands.length; i++) {
    let curCommand = commands[i];
    for (let j = 0; j < curCommand.execution.length; j++) {
      let curExec = curCommand.execution[j];
      let devices = curCommand.devices;
      for (let k = 0; k < devices.length; k++) {
        devices[k].deviceId = devices[k].id;
        let executionResponse = await execDevice(userUID, curExec, devices[k]);
        const execState = {};
        if (executionResponse.executionStates) {
          executionResponse.executionStates.map((key) => {
            execState[key] = executionResponse.states[key];
          });
        } else {
          log.warn('No execution states were found for this device');
        }
        respCommands.push({
          ids: [devices[k].deviceId],
          status: executionResponse.status,
          errorCode: executionResponse.errorCode
              ? executionResponse.errorCode : undefined,
          states: execState,
        });
      }
    }
  }

  return {
    requestId: body.requestId,
    payload: {
      commands: respCommands,
    },
  };
});

app.onQuery(async (body, headers) => {
  var userUID = await app.getUserUID(headers);

  let deviceIds = [];
  for (let i = 0; i < body.inputs[0].payload.devices.length; i++) {
    if (body.inputs[0].payload.devices[i] && body.inputs[0].payload.devices[i].id) {
      deviceIds.push(body.inputs[0].payload.devices[i].id);
    }
  }

  if (!deviceIds || deviceIds == {}) {
    deviceIds = null;
  }
  let devices = await datastore.getStates(userUID, deviceIds);
    
  if (!devices) {
    throw new Error("Query failed");
  }

  let deviceStates = {
    requestId: body.requestId,
    payload: {
      devices: devices,
    },
  };
  return deviceStates;
});

app.onSync(async (body, headers) => {
  var userUID = await app.getUserUID(headers);
  let devices = await datastore.getProperties(userUID, null);
  if (!devices) {
    throw Error('Unable to retrieve devices for this user');
  }
  let deviceList = [];
  Object.keys(devices).forEach(function(key) {
    if (devices.hasOwnProperty(key) && devices[key]) {
      log.info('Getting device information for id \'%s\'', key);
      let device = devices[key];
      device.id = key;
      deviceList.push(device);
    }
  });
  let deviceProps = {
    requestId: body.requestId,
    payload: {
      agentUserId: userUID,
      devices: deviceList,  
    },
  };
  return deviceProps;
});

async function execDevice(uid, command, device) {
  let curDevice = {
    deviceId: device.deviceId,
    states: {},
  };
  Object.keys(command.params).forEach(function(key) {
    if (command.params.hasOwnProperty(key)) {
      curDevice.states[key] = command.params[key];
    }
  });
  let payLoadDevice = {
    ids: [curDevice.deviceId],
    status: 'SUCCESS',
    states: {},
  };

  await datastore.execDevice(uid, curDevice); // Database update (only requested fields)
  let execDevice = await datastore.getDeviceById(uid, curDevice.deviceId); // Get device full state

  // Check whether the device exists or whether
  // it exists and it is disconnected.
  if (!execDevice || !execDevice.states.online) {
    log.warn('The device you want to control is offline');
    return {status: 'ERROR', errorCode: 'deviceOffline'};
  }

  try {
    await devicesProvider.sendCommand(execDevice.properties.name.name, JSON.stringify({
      on: execDevice.states.on, 
      color: execDevice.states.color.spectrumRGB, 
      brightness: execDevice.states.brightness
    }));
  } catch(err) {
    // TODO : listen to 'state' data and update the online flag as well
    // https://cloud.google.com/iot/docs/how-tos/config/getting-state#getting_device_state_data
    //execDevice.states.online = false;
    //await datastore.execDevice(uid, curDevice);
    return {status: 'ERROR', errorCode: 'deviceOffline'};
  }
  
  let deviceCommand = {
    type: 'change',
    state: {},
  };
  deviceCommand.state[curDevice.deviceId] = execDevice.states;
  frontendLink.broadcastChangeState(deviceCommand); // publish change to frontend

  payLoadDevice.states = execDevice.states;

  Object.keys(command.params).forEach(function(key) {
    if (command.params.hasOwnProperty(key)) {
      if (payLoadDevice.states[key] != command.params[key]) {
        return {status: 'ERROR', errorCode: 'notSupported'};
      }
    }
  });
  return {
    status: 'SUCCESS',
    states: execDevice.states,
    executionStates: execDevice.executionStates,
  };
}

module.exports = app;