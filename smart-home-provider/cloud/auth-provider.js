/* eslint require-jsdoc: "off" */
/* eslint valid-jsdoc: "off" */

const AuthProvider = {};
const express = require('express');
const authstore = require('./datastore');
const log = require('./logger');
const util = require('util');
// eslint-disable-next-line no-unused-vars
const session = require('express-session');
const uuidv4 = require('uuid/v4');

// TODO : rework error / success management
const sendError = (res, status, message) => error => {
  log.error({err: error}, message || error.message);
  res.status(status || error.status).json({
    type: 'error', 
    message: message || error.message, 
    error
  });
};
const sendSuccess = (res, message) => data => {
  res.status(200).json({type: 'success', message, data})
};

AuthProvider.parseAccessToken = (request) => {
  return request.headers.authorization ?
      request.headers.authorization.split(' ')[1] : null;
};

const SmartHomeModel = {};

SmartHomeModel.generateAuthCode = async function(uid, clientId) {
  return await authstore.addAuthcode({
    code: uuidv4(),
    type: 'AUTH_CODE',
    uid: uid,
    clientId: clientId,
    expiresAt: new Date(Date.now() + (60 * 10000))
  });
};

SmartHomeModel.getClient = async (clientId, clientSecret) => {
  log.info('getClient %s, %s', clientId, clientSecret);
  let client = await authstore.getClientById(clientId);
  if (!client || (client.clientSecret != clientSecret)) {
    log.info('clientSecret doesn\'t match %s, %s', client.clientSecret, clientSecret);
    return false;
  }

  log.info({client: client}, 'return getClient');
  return client;
};

AuthProvider.registerAuth = function(app) {
  /**
   * expecting something like the following:
   *
   * GET https://myservice.example.com/auth? \
   *   client_id=GOOGLE_CLIENT_ID
   *      - The Google client ID you registered with Google.
   *   &redirect_uri=REDIRECT_URI
   *      - The URL to which to send the response to this request
   *   &state=STATE_STRING
   *      - A bookkeeping value that is passed back to Google unchanged
   *          in the result
   *   &response_type=code
   *      - The string code
   */
  app.get('/oauth', async (req, res) => {
    try {
      let clientId = req.query.client_id;
      let redirectUri = req.query.redirect_uri;
      let state = req.query.state;
      let responseType = req.query.response_type;
      let authCode = req.query.code;

      if ('code' != responseType) {
        return res.status(500)
          .send('response_type ' + responseType + ' must equal "code"');
      }

      if (!(await authstore.getClientById(clientId))) {
        return res.status(500).send('client_id ' + clientId + ' invalid');
      }

      // if you have an authcode use that
      if (authCode) {
        return res.redirect(util.format('%s?code=%s&state=%s',
          redirectUri, authCode, state
        ));
      }

      let user = req.session.user;
      // Redirect anonymous users to login page.
      if (!user) {
        return res.redirect(util.format(
            '/login?client_id=%s&redirect_uri=%s&redirect=%s&state=%s',
            clientId, encodeURIComponent(redirectUri), req.path, state));
      }

      log.info('login successful %s', user.username);
      authCode = await SmartHomeModel.generateAuthCode(user.uid, clientId);

      if (authCode) {
        log.info({authCode: authCode}, 'authCode successful');
        return res.redirect(util.format('%s?code=%s&state=%s',
          redirectUri, authCode.code, state));
      }

      return res.status(400).send('something went wrong');
    } catch(err) {
      sendError(res, 500)(err);
    }
  });

  app.use('/login', express.static('./frontend/login.html'));

  // Post login.
  app.post('/login', async (req, res) => {
    try {
      log.info('/login ', req.body);
      
      let user = await authstore.getUserByUsername(req.body.username);
      if (!user || user.password != req.body.password) {
        log.info('%s not a user or passwords do not match!', req.body.username);

        return res.redirect(util.format(
          '%s?client_id=%s&redirect_uri=%s&state=%s&response_type=code&badaccess=true',
          '/frontend', req.body.client_id,
          encodeURIComponent(req.body.redirect_uri), req.body.state));
      }
    
      log.info({user: user}, 'logging in');
      req.session.user = user;

      // Successful logins should send the user back to /oauth/.
      let path = decodeURIComponent(req.body.redirect) || '/frontend';

      log.info('login successful %s', user.username);
      let authCode = await SmartHomeModel.generateAuthCode(user.uid, req.body.client_id);

      // tmp : creates a new access token for the user
      await authstore.addAccessToken({
        uid: user.uid,
        clientId: authCode.clientId,
        token: uuidv4(),
        expiresAt: new Date(Date.now() + (60 * 10000))
      });

      if (authCode) {
        log.info({authCode: authCode}, 'authCode successful');
        return res.redirect(util.format('%s?code=%s&state=%s',
          decodeURIComponent(req.body.redirect_uri), authCode.code, req.body.state));
      } else {
        log.info('authCode failed');
        return res.redirect(util.format(
            '%s?client_id=%s&redirect_uri=%s&state=%s&response_type=code',
            path, req.body.client_id, encodeURIComponent(req.body.redirect_uri),
            req.body.state));
      }
    } catch(err) {
      sendError(res, 500)(err);
    }
  });

  /**
   * client_id=GOOGLE_CLIENT_ID
   * &client_secret=GOOGLE_CLIENT_SECRET
   * &response_type=token
   * &grant_type=authorization_code
   * &code=AUTHORIZATION_CODE
   *
   * OR
   *
   *
   * client_id=GOOGLE_CLIENT_ID
   * &client_secret=GOOGLE_CLIENT_SECRET
   * &response_type=token
   * &grant_type=refresh_token
   * &refresh_token=REFRESH_TOKEN
   */
  app.all('/token', async (req, res) => {
    try {
      log.info({query: req.query}, '/token query');
      log.info({body: req.body}, '/token body');
      let clientId = req.query.client_id
          ? req.query.client_id : req.body.client_id;
      let clientSecret = req.query.client_secret
          ? req.query.client_secret : req.body.client_secret;
      let grantType = req.query.grant_type
          ? req.query.grant_type : req.body.grant_type;

      if (!clientId || !clientSecret) {
        log.error('missing required parameter');
        return res.status(400).json({error: 'invalid_grant'});
      }

      let client = await SmartHomeModel.getClient(clientId, clientSecret);
      log.info({client: client}, 'client');
      if (!client) {
        log.error('incorrect client data');
        return res.status(400).json({error: 'invalid_grant'});
      }

      if ('authorization_code' == grantType) {
        return handleAuthCode(req, res);
      } else if ('refresh_token' == grantType) {
        return handleRefreshToken(req, res);
      } else {
        log.error('grant_type %s is not supported', grantType);
        return res.status(400)
            .send('grant_type ' + grantType + ' is not supported');
      }
    } catch(err) {
      sendError(res, 500)(err);
    }
  });
};


// code=wk41krp1kz4s8cs00s04s8o4s
// &redirect_uri=https%3A%2F%2Fdevelopers.google.com%2Foauthplayground
// &client_id=RKkWfsi0Z9
// &client_secret=eToBzeBT7OwrPQO8mZHsZtLp1qhQbe
// &scope=
// &grant_type=authorization_code


/**
 * @return {{}}
 * {
 *   token_type: "bearer",
 *   access_token: "ACCESS_TOKEN",
 *   refresh_token: "REFRESH_TOKEN"
 * }
 */
async function handleAuthCode(req, res) {
  console.log('handleAuthCode %s', req.query);
  let clientId = req.query.client_id
      ? req.query.client_id : req.body.client_id;
  let clientSecret = req.query.client_secret
      ? req.query.client_secret : req.body.client_secret;
  let code = req.query.code ? req.query.code : req.body.code;

  let client = await SmartHomeModel.getClient(clientId, clientSecret);

  if (!code) {
    log.error('missing required parameter');
    return res.status(400).json({error: 'invalid_grant'});
  }
  if (!client) {
    log.error('invalid client id or secret %s, %s', clientId, clientSecret);
    return res.status(400).json({error: 'invalid_grant'});
  }

  let authCode = await authstore.getAuthcode(code);
  if (!authCode) {
    log.error('invalid code');
    return res.status(400).json({error: 'invalid_grant'});
  }
  if (new Date(authCode.expiresAt) < Date.now()) {
    log.error('expired code');
    return res.status(400).json({error: 'invalid_grant'});
  }
  if (authCode.clientId != clientId) {
    log.error({authCode: authCode}, 'invalid code - wrong client');
    return res.status(400).json({error: 'invalid_grant'});
  }

  let user = await authstore.getUserByUID(authCode.uid);
  if (!user) {
    log.error('could not find user');
    return false;
  }

  // TODO : rework refresh token to store it with access token
  let accessToken = await authstore.addAccessToken({
    uid: user.uid,
    clientId: authCode.clientId,
    token: uuidv4(),
    expiresAt: new Date(Date.now() + (60 * 10000))
  });

  let refreshToken = await authstore.addRefreshToken({
    uid: user.uid,
    clientId: authCode.clientId,
    token: uuidv4(),
  });

  // TODO : Delete authCode

  let returnToken = {
    token_type: 'Bearer',
    access_token: accessToken.token,
    refresh_token: refreshToken.token,
    expires_in: Math.round((new Date(accessToken.expiresAt).getTime() - Date.now())/1000)
  };

  log.info({token: returnToken}, 'respond success');
  return res.status(200).json(returnToken);
}

/**
 * @return {{}}
 * {
 *   token_type: "bearer",
 *   access_token: "ACCESS_TOKEN",
 * }
 */
async function handleRefreshToken(req, res) {
  let clientId = req.query.client_id
      ? req.query.client_id : req.body.client_id;
  let clientSecret = req.query.client_secret
      ? req.query.client_secret : req.body.client_secret;
  let refreshTokenCode = req.query.refresh_token
      ? req.query.refresh_token : req.body.refresh_token;

  let client = await SmartHomeModel.getClient(clientId, clientSecret);
  if (!client) {
    log.error('invalid client id or secret %s, %s', clientId, clientSecret);
    return res.status(400).json({error: 'invalid_grant'});
  }

  if (!refreshTokenCode) {
    log.error('missing required parameter');
    return res.status(400).send({error: 'invalid_grant'});
  }

  let token = await authstore.getRefreshToken(refreshTokenCode);
  if (!token) {
    log.error('invalid refresh token');
    return res.status(400).send({error: 'invalid_grant'});
  }
  if (token.clientId != clientId) {
    log.error({token: token}, 'invalid refresh token - wrong client');
    return res.status(400).json({error: 'invalid_grant'});
  }

  let newAccessToken = await authstore.addAccessToken({
    uid: token.uid,
    clientId: token.clientId,
    token: uuidv4(),
    expiresAt: new Date(Date.now() + (60 * 10000))
  });

  res.status(200).json({
    token_type: 'bearer',
    access_token: newAccessToken.token,
    expires_in: Math.round((new Date(newAccessToken.expiresAt).getTime() - Date.now())/1000)
  });
}

exports.registerAuth = AuthProvider.registerAuth;
exports.parseAccessToken = AuthProvider.parseAccessToken;
