const OktaJwtVerifier = require('@okta/jwt-verifier')
var pino = require('pino')()

const PROVIDER = 'okta'

module.exports = {
  initialize
}

function initialize(options) {
  if (!options.issuer) {
    pino.error(options, "initialize: required options not provided to Okta")
    throw new Error("Okta requires 'issuer' to be provided.")
  }
  
  var name = options.name || PROVIDER
  
  const oktaJwtVerifier = new OktaJwtVerifier({
    issuer: options.issuer
  })

  function isIssuer(decoded) {
    return (decoded.payload.iss.indexOf("oktapreview.com") >= 0)
  }
  
  async function verify(token, decoded) {
    try {
      var jwt = await oktaJwtVerifier.verifyAccessToken(token)
      return Promise.resolve({
        provider: PROVIDER,
        verified: true,
        claims: jwt.claims
      })
    } catch (err) {
      pino.error(err, "Error verifying Okta token")
      return Promise.resolve({
        provider: PROVIDER,
        verified: false,
        message: err.message
      })
    }
  }
  
  return {
    provider: PROVIDER,
    name,
    isIssuer,
    verify
  }
}


// oktaJwtVerifier.verifyAccessToken(accessTokenString)
// .then(jwt => {
//   // the token is valid
//   console.log(jwt.claims);
// })
// .catch(err => {
//   // a validation failed, inspect the error
// });

// Custom Claims Assertions
// For basic use cases, you can ask the verifier to assert a custom set of claims. For example, if you need to assert that this JWT was issued for a given client id:

// const verifier = new OktaJwtVerifier({
//   issuer: ISSUER,
//   assertClaims: {
//     cid: 'myKnownClientId'
//   }
// });
// Validation will fail and an error returned if an access token does not have the configured claim.

// Caching & Rate Limiting
// By default, found keys are cached by key ID for one hour. This can be configured with the cacheMaxAge option for cache entries.
// If a key ID is not found in the cache, the JWKs endpoint will be requested. To prevent a DoS if many not-found keys are requested, a rate limit of 10 JWKs requests per minute is enforced. This is configurable with the jwksRequestsPerMinute option.
// Here is a configuration example that shows the default values:

// // All values are default files
// const oktaJwtVerifier = new OktaJwtVerifier({
//   cacheMaxAge: 60 * 60 * 1000, // 1 hour
//   jwksRequestsPerMinute: 10
// });