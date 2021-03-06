'use strict'

var pino = require('pino')()

const jwtDecode = require('jwt-decode')

// Currently supported identity providers
const auth0 = require('./auth0')
const cognito = require('./cognito')
const okta = require('./okta')

const plugins = [ ]

function create(options) {
  var plugins = [ ]
  
  function initializePlugins(options) {
    options = options || { }
    plugins.length = 0 // clear any prior plugins initialized
    if (!options.plugins || options.plugins.length == 0) return plugins
    for (var conf of options.plugins) {
      if (conf.provider == "auth0") {
        plugins.push(auth0.initialize(conf))      
      }
      if (conf.provider == "cognito") {
        plugins.push(cognito.initialize(conf)) 
      }
      if (conf.provider == "okta") {
        plugins.push(okta.initialize(conf))
      }
    }
    return plugins
  }
  
  async function verify(token, options) {
    options = options || { }
    
    // options.decoded to allow decoded token to be passed in for testing
    var decoded = options.decoded || decodeToken(token)  
    pino.debug(decoded, "decoded token")
    if (!decoded) {
      return {
        token, verification: {
          provider: null,
          verified: false,
          message: "invalid token",
        }
      }
    }
    // check if the token is already expired unless skipExpirationCheck is true (for testing) 
    if (isTokenExpired(decoded) && !options.skipExpirationCheck) {
      pino.info(decoded, "token is expired")  
      return {
        token, decoded, verification: {
          provider: null,
          verified: false,
          message: "token is expired",
        }
      }
    }
    
    if (!decoded.payload.iss) {
      pino.warn(decoded, "token missing iss field")
      return {
        token, decoded, verification: {
          provider: null,
          verified: false,
          message: "token missing iss field"
        }
      }
    }
    
    for (var plugin of plugins) {
      if (plugin.isIssuer(decoded)) {
        try {
          var verification = await plugin.verify(token, decoded)
          pino.debug(verification, "verification")
          if (verification) {
            pino.info({ token, decoded, verification }, "returned")
            return {
              token, decoded, verification
            }
          }
        } catch (err) {
          pino.error(err, "Error calling verify")
          return {
            token, decoded, verification: {
              provider: plugin.name,
              verified: false,
              message: err.message
            }
          }
        }
      }
    }
    return { token, decoded, verification: {
        provider: null,
        verified: false,
        message: "No matching provider for token"
      }
    }
  }

  initializePlugins(options)
  
  return {
    plugins,
    verify,
    initializePlugins
  }
}

function isTokenExpired(decoded) {
  var t = (new Date()).getTime() / 1000
  if (!decoded.payload.exp) {
    pino.warn(decoded, "token does not have exp field")
    return { t, exp: false }
  }
  var exp = decoded.payload.exp
  if (t < exp) {
    pino.debug({ t, exp }, "token is not expired")
    return false
  } else {
    pino.debug({ t, exp }, "token is expired")
    return { t, exp }
  }
}

function decodeToken(token) {
  try {
    var payload =  jwtDecode(token)
    var header = jwtDecode(token, { header: true })
    return { header, payload }
  } catch (err) {
    pino.error("Error decoding jwt token", err)
    return null
  }
}

module.exports = {
  create,
  isTokenExpired
}


// iss: The issuer of the token
// sub: The subject of the token
// aud: The audience of the token
// exp: This will probably be the registered claim most often used. This will define the expiration in NumericDate value. The expiration MUST be after the current date/time.
// nbf: Defines the time before which the JWT MUST NOT be accepted for processing
// iat: The time the JWT was issued. Can be used to determine the age of the JWT
// jti: Unique identifier for the JWT. Can be used to prevent the JWT from being replayed. This is helpful for a one time use token.