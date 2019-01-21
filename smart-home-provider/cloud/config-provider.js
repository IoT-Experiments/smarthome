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

let configFromFile = require(process.env.CONFIG ? process.env.CONFIG : '../../data/config.dev.js');

let exportConfig = configFromFile;

exportConfig.devPortSmartHome = '3000';
// Running server locally using ngrok
exportConfig.isLocal = false;

function init() {
  process.argv.forEach(function(value, i, arr) {
    if (value.includes('isLocal')) {
      exportConfig.isLocal = true;
    }
  });
  console.log('config: ', exportConfig);
}
init();

module.exports = exportConfig;