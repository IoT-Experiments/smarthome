const path = require('path');

let jwtFilename = path.resolve(__dirname, 'jwt-key.json');

module.exports = {
  // Client id that Google will use
  smartHomeProviderGoogleClientId: '',
  // Client secret that Google will use
  smartHomeProvideGoogleClientSecret: '',
  // Client API Key generated on the console
  smartHomeProviderApiKey: '',
  // Client service key to use for reporting state
  jwtFilename: jwtFilename,
  jwt: require(jwtFilename),
  datastore: {
    devicesFileLocation: path.resolve(__dirname, 'datastore', 'devices.db'),
    usersFileLocation: path.resolve(__dirname, 'datastore', 'users.db'),
    clientsFileLocation: path.resolve(__dirname, 'datastore', 'clients.db'),
    authcodesFileLocation: path.resolve(__dirname, 'datastore', 'authcodes.db'),
    accessTokensFileLocation: path.resolve(__dirname, 'datastore', 'access-tokens.db'),
    refreshTokensFileLocation: path.resolve(__dirname, 'datastore', 'refresh-tokens.db')
  },
  cloudRegion: '',
  projectId: '',
  registryId: ''
}