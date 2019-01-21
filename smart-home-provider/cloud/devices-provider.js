const {google} = require('googleapis');

const log = require('./logger');
const config = require('./config-provider');

const API_VERSION = 'v1';
const DISCOVERY_API = 'https://cloudiot.googleapis.com/$discovery/rest';

var clientInstance;

async function getClientInstance() {
  if(!clientInstance) {
    clientInstance = await getClient(config.jwtFilename);/*.catch(err => {
      log.error(err, 'Error during API discovery.');
      process.exit(1);
    });*/
  }
  return clientInstance;
}

// Returns an authorized API client by discovering the Cloud IoT Core API with
// the provided API key.
async function getClient(serviceAccountJson) {
// the getClient method looks for the GCLOUD_PROJECT and GOOGLE_APPLICATION_CREDENTIALS
// environment variables if serviceAccountJson is not passed in
  return google.auth
    .getClient({
      keyFilename: serviceAccountJson,
      scopes: ['https://www.googleapis.com/auth/cloud-platform'],
    })
    .then(authClient => {
      const discoveryUrl = `${DISCOVERY_API}?version=${API_VERSION}`;

      google.options({
        auth: authClient,
      });

      return google.discoverAPI(discoveryUrl);
        /*.catch(err => {
          log.error(err, 'Error during API discovery.');
        });*/
    });
}

async function sendCommand(client, deviceId, registryId, projectId, cloudRegion, commandMessage) {
  const parentName = `projects/${projectId}/locations/${cloudRegion}`;
  const registryName = `${parentName}/registries/${registryId}`;

  const binaryData = Buffer.from(commandMessage).toString('base64');

  // NOTE: The device must be subscribed to the wildcard subfolder
  // or you should pass a subfolder
  const request = {
    name: `${registryName}/devices/${deviceId}`,
    binaryData: binaryData,
    //subfolder: <your-subfolder>
  };

  return new Promise((resolve, reject) => client.projects.locations.registries.devices.sendCommandToDevice(
    request,
    (err, data) => {
      if (err) {
        log.error({ err: {message: err.message, stack: err.stack, code: err.code }, command: request }, 'Could not send command');
        reject(err.message ? new Error(err.message) : err);
      } else {
        resolve(data);
      }
    }
  ));
}

module.exports = {
  sendCommand: async (deviceId, commandMessage) => sendCommand(await getClientInstance(), deviceId, config.registryId, config.projectId, config.cloudRegion, commandMessage)
}