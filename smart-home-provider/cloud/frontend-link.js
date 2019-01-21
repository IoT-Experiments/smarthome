const log = require('./logger');

const deviceConnections = {};

const frontendLink = {};

frontendLink.register = (deviceId, res) => {
  deviceConnections[deviceId] = res;
};

frontendLink.unregister = (deviceId) => {
  delete deviceConnections[deviceId];
};

frontendLink.broadcastChangeState = (command) => {
    if (command.type === 'change') {
      for (let deviceId in command.state) {
        const deviceChanges = command.state[deviceId];

        const connection = deviceConnections[deviceId];
        if (!connection) {
          log.error('Device ' + deviceId +' unknown to cloud');
          return false;
        }

        connection.write('event: change\n');
        connection.write('data: ' + JSON.stringify(deviceChanges) + '\n\n');
      }
    } else if (command.type === 'delete') {
      log.error('Device deletion unimplemented');
      return false;
    } else {
      log.error('Unknown change type "' + command.type + '"');
      return false;
    }
    return true;
};

module.exports = frontendLink;