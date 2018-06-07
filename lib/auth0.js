'use strict'

const auth0 = require('auth0')
var pino = require('pino')()

const PROVIDER = "auth0"

module.exports = {
  initialize
}

function initialize(options) {
  if (!options.domain || !options.clientId) {
    pino.error(options, "initialize: required options not provided to Auth0")
    throw new Error("Auth0 requires 'domain' and 'clientId' to be provided.")
  }
  
  var name = options.name || PROVIDER
  
  var client = new auth0.AuthenticationClient({
    domain: options.domain,
    clientId: options.clientId
  })
  
  function isIssuer(decoded) {
    return (decoded.payload.iss.indexOf("auth0.com") >= 0)
  }
  
  async function verify(token, decoded) {
    try {
      var ret = await client.users.getInfo(token)
      if (typeof ret == 'string') {
        return Promise.resolve({
          provider: PROVIDER,
          verified: false,
          message: ret
        })
      }
      if (typeof ret == 'object') {
        return Promise.resolve({
          provider: PROVIDER,
          verified: true,
          claims: ret
        })
      }
      return Promise.resolve({
        provider: PROVIDER,
        verified: false,
        message: "Unknown response from issuer"
      })
    } catch (err) {
      pino.error(err, "Error verifying Auth0 token")
      return Promise.resolve({
        provider: PROVIDER,
        verified: false,
        message: err.message
      })
    }
  }
  
  return {
    provider: "auth0",
    name,
    isIssuer,
    verify
  }
}




// Auth0 Google Authentication

// { 
//   sub: 'google-oauth2|113620159765357156857',
//   given_name: 'Daniel Jhin',
//   family_name: 'Yoo',
//   nickname: 'danieljyoo',
//   name: 'Daniel Jhin Yoo',
//   picture: 'https://lh3.googleusercontent.com/-fuKaakI9XQs/AAAAAAAAAAI/AAAAAAAAADs/vPUAm9vEKps/photo.jpg',
//   gender: 'male',
//   locale: 'en',
//   updated_at: '2018-05-28T22:01:47.721Z',
//   email: 'danieljyoo@gmail.com',
//   email_verified: true 
// }
  

// Auth0 Github Integration

// {
//   "sub": "github|17211",
//   "nickname": "danieljyoo",
//   "name": "Daniel Jhin Yoo",
//   "picture": "https://avatars0.githubusercontent.com/u/17211?v=4",
//   "updated_at": "2018-05-30T05:11:33.804Z",
//   "email": "danieljyoo@gmail.com",
//   "email_verified": true
// }
    

// Auth0 Email / Password Authentication

// { 
//   sub: 'auth0|5b0b406f42f10e18ba765017',
//   nickname: 'danieljyoo',
//   name: 'danieljyoo@goalbookapp.com',
//   picture: 'https://s.gravatar.com/avatar/23f28a1dc36a69db111a95c6cede2993?s=480&r=pg&d=https%3A%2F%2Fcdn.auth0.com%2Favatars%2Fda.png',
//   updated_at: '2018-05-29T03:50:09.288Z',
//   email: 'danieljyoo@goalbookapp.com',
//   email_verified: true 
// }
  

// Auth0 JWT Decoded

// # header

// { typ: 'JWT',
//       alg: 'RS256',
//       kid: 'OUQwRDhDMzY0NjMxNkFGQjkzQzQwNkJDMTY1M0Q0MkJFQTc5NUI1Qg' }

// # Payload

// { iss: 'https://funcmatic.auth0.com/', # Domain
//       sub: 'google-oauth2|113620159765357156857',
//       aud: 
//       [ 'https://funcmatic.auth0.com/api/v2/',
//         'https://funcmatic.auth0.com/userinfo' ],
//       iat: 1527565984,
//       exp: 1527573184,
//       azp: '9BkCn2wkyw1gcjTkwF63qS2iOjWM5keT',  # clientid
//       scope: 'openid profile email' }
      
  

