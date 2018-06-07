'use strict'

const axios = require('axios')
const jose = require('node-jose')

var pino = require('pino')()

const PROVIDER = 'cognito'

module.exports = {
  initialize
}

function initialize(options) {
  if (!options.region || !options.userPoolId || !options.clientId) {
    pino.error(options, "initialize: required options not provided to Cognito")
    throw new Error("Cognito requires 'region', 'userPoolId', and 'clientId' to be provided.")
  }
  var name = options.name || PROVIDER
  var keys_url = `https://cognito-idp.${options.region}.amazonaws.com/${options.userPoolId}/.well-known/jwks.json`
  var clientId = options.clientId
  
  function isIssuer(decoded) {
    return (decoded.payload.iss.indexOf("cognito-idp") >= 0)  
  }
  
  async function verify(token, decoded, options) {
    // get the kid from the headers prior to verification
    var header = decoded.header
    var kid = header.kid
    // download the public keys
    try {
      var data = (await axios.get(keys_url)).data
      var key = findInPublicKeys(data.keys, kid)
      if (!key) {
        pino.warn(kid, data.keys, "Public key not found in jwks.json")
        return Promise.resolve({
          provider: PROVIDER,
          verified: false,
          message: "Public key not found in jwks.json"
        })
      }
      var joseVerify = jose.JWS.createVerify(await jose.JWK.asKey(key))
      var result = await joseVerify.verify(token)
       // now we can use the claims
      var claims = JSON.parse(result.payload);
      // additionally we can verify the token expiration
      var current_ts = Math.floor(new Date() / 1000);
      if (current_ts > claims.exp) {
        pino.warn(kid, data.keys, "Token is expired")
        return Promise.resolve({
          provider: PROVIDER,
          verified: false,
          message: "Token is expired"
        })
      }
      // and the Audience (use claims.client_id if verifying an access token)
      if (claims.aud != clientId) {
        pino.warn(clientId, claims.aud, "Token was not issued for this audience")
        return Promise.resolve({
          provider: PROVIDER,
          verified: false,
          message: "Token was not issued for this audience"
        })
      }
      return Promise.resolve({
        provider: PROVIDER,
        verified: true,
        claims: claims
      })
    } catch (err) {
      pino.error("Error in verify", err)
      return Promise.reject(err)
    }
  }

  return {
    provider: PROVIDER,
    name,
    isIssuer,
    verify
  }
}

function findInPublicKeys(keys, kid) {
  for (var key of keys) {
    if (key.kid == kid) {
      return key
    }
  }
  return false
}

// AWS Cognito JWT decoded

// {
//   "sub": "aaaaaaaa-bbbb-cccc-dddd-example",
//   "aud": "xxxxxxxxxxxxexample",
//   "email_verified": true,
//   "token_use": "id",
//   "auth_time": 1500009400,
//   "iss": "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example",
//   "cognito:username": "anaya",
//   "exp": 1500013000,
//   "given_name": "Anaya",
//   "iat": 1500009400,
//   "email": "anaya@example.com"
// }

// {
//   "aud": "5a7rgt4jcbgqju20knmv5lu189", 
//   "auth_time": 1528001203, 
//   "cognito:username": "0edb3176-e3d9-45ac-8a26-b6d43cb1f6d1", 
//   "email": "danieljyoo@gmail.com", 
//   "email_verified": true, 
//   "event_id": "1caf176a-66e9-11e8-8fc8-21bbb10658fb", 
//   "exp": 1528004803, 
//   "iat": 1528001203, 
//   "iss": "https://cognito-idp.us-west-2.amazonaws.com/us-west-2_eJTw2dsFU", 
//   "preferred_username": "danieljyoo", 
//   "sub": "0edb3176-e3d9-45ac-8a26-b6d43cb1f6d1", 
//   "token_use": "id"
// }

// https://cognito-idp.{region}.amazonaws.com/{userPoolId}/.well-known/jwks.json

// https://github.com/awslabs/aws-support-tools/tree/master/Cognito/decode-verify-jwt


// https://github.com/awslabs/aws-support-tools/tree/master/Cognito/decode-verify-jwt
// #jwks.json

// {
//     "keys": [{
//         "alg": "RS256",
//         "e": "AQAB",
//         "kid": "abcdefghijklmnopqrsexample=",
//         "kty": "RSA",
//         "n": "lsjhglskjhgslkjgh43lj5h34lkjh34lkjht3example",
//         "use": "sig"
//     }, {
//         "alg":
//         "RS256",
//         "e": "AQAB",
//         "kid": "fgjhlkhjlkhexample=",
//         "kty": "RSA",
//         "n": "sgjhlk6jp98ugp98up34hpexample",
//         "use": "sig"
//     }]
// }

// var https = require('https');
// var jose = require('node-jose');

// var region = 'ap-southeast-2';
// var userpool_id = 'ap-southeast-2_xxxxxxxxx';
// var app_client_id = '<ENTER APP CLIENT ID HERE>';
// var keys_url = 'https://cognito-idp.' + region + '.amazonaws.com/' + userpool_id + '/.well-known/jwks.json';

// exports.handler = (event, context, callback) => {
//     var token = event.token;
//     var sections = token.split('.');
//     // get the kid from the headers prior to verification
//     var header = jose.util.base64url.decode(sections[0]);
//     header = JSON.parse(header);
//     var kid = header.kid;
//     // download the public keys
//     https.get(keys_url, function(response) {
//         if (response.statusCode == 200) {
//             response.on('data', function(body) {
//                 var keys = JSON.parse(body)['keys'];
//                 // search for the kid in the downloaded public keys
//                 var key_index = -1;
//                 for (var i=0; i < keys.length; i++) {
//                         if (kid == keys[i].kid) {
//                             key_index = i;
//                             break;
//                         }
//                 }
//                 if (key_index == -1) {
//                     console.log('Public key not found in jwks.json');
//                     callback('Public key not found in jwks.json');
//                 }
//                 // construct the public key
//                 jose.JWK.asKey(keys[key_index]).
//                 then(function(result) {
//                     // verify the signature
//                     jose.JWS.createVerify(result).
//                     verify(token).
//                     then(function(result) {
//                         // now we can use the claims
//                         var claims = JSON.parse(result.payload);
//                         // additionally we can verify the token expiration
//                         current_ts = Math.floor(new Date() / 1000);
//                         if (current_ts > claims.exp) {
//                             callback('Token is expired');
//                         }
//                         // and the Audience (use claims.client_id if verifying an access token)
//                         if (claims.aud != app_client_id) {
//                             callback('Token was not issued for this audience');
//                         }
//                         callback(null, claims);
//                     }).
//                     catch(function() {
//                         callback('Signature verification failed');
//                     });
//                 });
//             });
//         }
//     });
// }