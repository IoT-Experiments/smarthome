# Actions on Google: SmartHome for IoT-Experiments

This repository is based on the source code of the "[Actions on Google: Smart Home sample using Node.js](https://github.com/actions-on-google/smart-home-nodejs)" sample.

This repository contains a fully functioning example of a Smart Home provider
cloud service designed to work with Actions on Google.

It's in a "work in progress" state, and is not a good example of how to do it.
The app has been limited to an RGB lamp, with a specific payload to the device, even if the based sample is able to manage a lot more devices.
Please read the full article on [IoT-Experiments website](https://www.iot-experiments.com).

The Smart Home IoT cloud engine is stored in
`smart-home-provider`. This consists of both the main
`cloud/` main web service, as well as the web portal used
to interact with virtual devices in `frontend/`. `smart-home-provider-cloud.js`
is the entry point to the Node.js Express app that runs the IoT cloud service,
and handles authentication, and ultimately handles requests from the Google
Assistant.

The primary AoG intent handlers are stored in
`smart-home-provider/smart-home-app.js`. Here, you can find listeners for POST
requests similar to the one your app will receive from the Google Assistant
when SYNCing, QUERYing, or EXECuting smart home device control with your cloud.
The path for requests to this app is '/smarthome'.

## Setup Instructions

See the developer guide and release notes at [https://developers.google.com/actions/](https://developers.google.com/actions/) for more details.

### Steps for testing with Google Assistant

#### Create and setup project in Actions Console

1. Use the [Actions on Google Console](https://console.actions.google.com) to add a new project with a name of your choosing and click *Create Project*.
1. Click *Home Control*, then click *Smart Home*.
1. On the left navigation menu under *SETUP*, click on *Invocation*.
1. Add your App's name. Click *Save*.
1. On the left navigation menu under *DEPLOY*, click on *Directory Information*.
1. Add your App info, including images, a contact email and privacy policy. This information can all be edited before submitting for review.
1. Click *Save*.


#### Add Request Sync
The Request Sync feature allows a cloud integration to send a request to the Home Graph
to send a new SYNC request.

1. Navigate to the
[Google Cloud Console API Manager](https://console.developers.google.com/apis)
for your project id.
1. Enable the [HomeGraph API](https://console.cloud.google.com/apis/api/homegraph.googleapis.com/overview). This will be used to request a new sync and to report the state back to the HomeGraph.
1. Click Credentials
1. Click 'Create credentials'
1. Click 'API key'
1. Copy the API key shown and insert it in
`smart-home-provider/cloud/config-provider.js`
   Enable Request-Sync API using [these
   instructions](https://developers.google.com/actions/smarthome/create-app#request-sync).

To use it, add a new device while the sample is active.

#### Add Report State
The Report State feature allows a cloud integration to proactively provide the
current state of devices to the Home Graph without a `QUERY` request. This is
done securely through [JWT (JSON web tokens)](https://jwt.io/).

1. Navigate to the [Google Cloud Console API & Services page](https://console.cloud.google.com/apis/credentials)
1. Select **Create Credentials** and create a **Service account key**
1. Create the account and download a JSON file.
   Save this as `data/jwt-key.json`.

The sample already includes support for report state. To use it, create a device
in the web frontend. Then click on the arrow icon in the top-right corner. It will
start reporting state when the state changes locally.

#### Setup sample service

1. Set up the web portal

        cd smart-home-provider/frontend
        npm install -g bower
        bower install
        cd ..

1. Configure the app.
    * If running locally, create a `data/config.dev.js` file based on the `data/config.default.js` file, and update the configuration.
    * If running in a hosted env, create a `config.js` file based on the `data/config.default.js` file, update the configuration and set the `CONFIG` environment variable with the location of this file.

1. Run index.js, either locally or hosted
    * If running locally

          npm install
          npm start

    * If running in a hosted env,

          node index.js

1. In the resulting output, note the config data. In particular the client ID and client Secret.
1. In a browser, open the ngrok URL shown.
1. Log in with one of the sample user accounts, for instance:

       user: rick
       password: oldman

1. This is a web portal to your Smart Home devices. Configure the smart lights
shown as you please. Click the cloud icon shown above at least one of them to
enable it for cloud control.

#### Start testing

1. Navigate back to the [Actions on Google Console](https://console.actions.google.com).
1. On the left navigation menu under *BUILD*, click on *Actions*. Click on *Add Your First Action* and choose your app's language(s).
1. Enter the URL for fulfillment, e.g. https://xyz123.ngrok.io/smarthome, click *Done*.
1. On the left navigation menu under *ADVANCED OPTIONS*, click on *Account Linking*. 
1. Select *No, I only want to allow account creation on my website*. Click *Next*.
1. For Linking Type, select *OAuth*.
1. For Grant Type, select 'Authorization Code' for Grant Type.
1. Under Client Information, enter the client ID and secret from earlier.
1. The Authorization URL is the hosted URL of your app with '/oauth' as the
path, e.g. https://xyz123.ngrok.io/oauth
1. The Token URL is the hosted URL of your app with '/token' as the path,
e.g. https://xyz123.ngrok.io/token
1. Enter any remaining necessary information you might need for
authentication your app. Click *Save*.
1. On the left navigation menu under *Test*, click on *Simulator*, to begin testing this app.

#### Setup Account linking

1. On a device with the Google Assistant logged into the same account used
to create the project in the Actions Console, enter your Assistant settings.
1. Click Home Control.
1. Click the '+' sign to add a device.
1. Find your app in the list of providers.
1. Log in to your service.
1. Start using the Google Assistant in the Actions Console to control your devices. Try saying 'turn my lights on'.

:information_source: Assistant will only provide you control over items that are registered, so if you visit your front end https://xyz123.ngrok.io and click the add icon to create a device your server will receive a new SYNC command.

### Examples of SYNC, QUERY, and EXEC requests

Your app will need to handle these 3 basic requests from the Google Assistant.

#### Sync

    POST /smarthome HTTP/1.1
    Host: <something>.ngrok.io
    Accept: application/json
    Content-Type: application/json
    Authorization: Bearer psokmCxKjfhk7qHLeYd1
    Cache-Control: no-cache

    Body:
    {
        "requestId": "ff36a3cc-ec34-11e6-b1a0-64510650abcf",
        "inputs": [{
            "intent": "action.devices.SYNC"
        }]
     }

#### Query

    POST /smarthome HTTP/1.1
    Host: <something>.ngrok.io
    Accept: application/json
    Content-Type: application/json
    Authorization: Bearer psokmCxKjfhk7qHLeYd1
    Cache-Control: no-cache

    Body:
    {
        "requestId": "ff36a3cc-ec34-11e6-b1a0-64510650abcf",
        "inputs": [{
            "intent": "action.devices.QUERY",
            "payload": {
                "devices": [{
                    "id": "1",
                    "customData": {
                        "smartHomeProviderId": "FkldJVJCmDNSaoLkoq0txiz8Byf2Hr"
                    }
                },{
                    "id": "2"
                },{
                    "id": "3"
                },{
                    "id": "4"
                }]
            }
        }]
    }

#### Execute

    POST /smarthome HTTP/1.1
    Host: <something>.ngrok.io
    Accept: application/json
    Content-Type: application/json
    Authorization: Bearer psokmCxKjfhk7qHLeYd1
    Cache-Control: no-cache

    Body:
    {
        "requestId": "ff36a3cc-ec34-11e6-b1a0-64510650abcf",
        "inputs": [{
            "intent": "action.devices.EXECUTE",
            "payload": {
                "commands": [{
                    "devices": [{
                        "id": "1",
                        "customData": {
                            "smartHomeProviderId": "FkldJVJCmDNSaoLkoq0txiz8Byf2Hr"
                        }
                    },{
                        "id": "3"
                    }],
                    "execution": [{
                        "command": "action.devices.commands.Brightness",
                        "params": {
                            "brightness": 60
                        }
                    },{
                        "command": "action.devices.commands.ChangeColor",
                        "params": {
                            "color": {
                                "name": "red",
                                "spectrumRGB": 65280
                            }
                        }
                    },{
                        "command": "action.devices.commands.OnOff",
                        "params": {
                            "on": true
                        }
                    }]
                }]
            }
        }]
    }

## References and How to report bugs
* Actions on Google documentation: [https://developers.google.com/actions/](https://developers.google.com/actions/).
* Full article on [IoT-Experiments](https://www.iot-experiments.com)

## Terms
Your use of this sample is subject to, and by using or downloading the sample files you agree to comply with, the [Google APIs Terms of Service](https://developers.google.com/terms/).


