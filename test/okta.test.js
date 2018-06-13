const okta = require('../lib/okta')
var pino = require('pino')()

describe('Okta Initialization', () => {
  it ('should initialize plugin', async () => {
    var plugin = okta.initialize({ 
      issuer: process.env.OKTA_ISSUER
    })
    expect(plugin.verify).toBeTruthy()
    expect(plugin.isIssuer).toBeTruthy()
  })  
  it ('should throw Error if options not provided', async () => {
    expect(() => { 
      okta.initialize({ }) 
    }).toThrow()
  })
})

describe('Okta isIssuer', () => {
  var plugin = null
  
  beforeEach(() => {
    plugin = okta.initialize({ 
      issuer: process.env.OKTA_ISSUER
    })
  });
  it ('should return true if oktapreview.com is in iss', async () => {
    var flag = plugin.isIssuer({
      payload: { iss: 'https://my-domain.oktapreview.com/' }
    })
    expect(flag).toBe(true)
  })
  it ('should return false if oktapreview.com is not in iss', async () => {
    var flag = plugin.isIssuer({
      payload: { iss: 'https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example' }
    })
    expect(flag).toBe(false)
  })
})

describe('Okta verification', () => {
  var plugin = null
  
  beforeEach(() => {
    plugin = okta.initialize({ 
      issuer: process.env.OKTA_ISSUER
    })
  });
  it ('should return Bad Request for an invalid token format', async () => {
    var token = "BAD TOKEN"
    var user = await plugin.verify(token)
    expect(user).toMatchObject({
      verified: false,
      message: "Jwt cannot be parsed"
    })
  })
  it ('should return Unauthorized for an expired token', async () => {
    var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9VUXdSRGhETXpZME5qTXhOa0ZHUWprelF6UXdOa0pETVRZMU0wUTBNa0pGUVRjNU5VSTFRZyJ9.eyJpc3MiOiJodHRwczovL2Z1bmNtYXRpYy5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTM2MjAxNTk3NjUzNTcxNTY4NTciLCJhdWQiOlsiaHR0cHM6Ly9mdW5jbWF0aWMuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2Z1bmNtYXRpYy5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI3NTQ0OTA3LCJleHAiOjE1Mjc1NTIxMDcsImF6cCI6IjlCa0NuMndreXcxZ2NqVGt3RjYzcVMyaU9qV001a2VUIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9.PvuKP_c1Fpaor9UvwyOf6pgSkylST-wdYR7zau-tF7kt6Gtb0u4MEs9hTr6ydMDyjpHAkhc6Tdumq_vvEJkVcwtIWzycSTwdW8IfhKUWai1Dh3w7ZnVtPqxWesmK5ny8ytw36Km0Yt_aOpNeyUNQ3JACLe9UuVuY8wDA9mJXGZDOi2zBu03hBA0NssgOTpzfx1L1IHqi5H8leaIeQ2AgXWgVXIuK81k6UKHgqOLbqnVSpU7yllxystTKqL6NrpZ1Qn4Vkt33df2GrjHaeipOpep_LXxFG2DZ2nN6vcyjEQIsY_7QO7p9JIq-u_zRKnGhFHL65bJeQI0sNipPb5NpnQ"
    var user = await plugin.verify(token)
    expect(user).toMatchObject({
      verified: false,
      message: "Jwt is expired"
    })
  })
  // it ('should return user info for a valid token', async () => {
  //   var token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9VUXdSRGhETXpZME5qTXhOa0ZHUWprelF6UXdOa0pETVRZMU0wUTBNa0pGUVRjNU5VSTFRZyJ9.eyJpc3MiOiJodHRwczovL2Z1bmNtYXRpYy5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTM2MjAxNTk3NjUzNTcxNTY4NTciLCJhdWQiOlsiaHR0cHM6Ly9mdW5jbWF0aWMuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2Z1bmNtYXRpYy5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI3NTY1OTg0LCJleHAiOjE1Mjc1NzMxODQsImF6cCI6IjlCa0NuMndreXcxZ2NqVGt3RjYzcVMyaU9qV001a2VUIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9.lFGaFFtwQhF_CcUQKEeG9jpxWFj5nL-nzL3SpllK2YsabRxoBrqkwouku9tBt5MDwb1nlFefxNTkN_wPNLbxCo41GldIYczC7AHq5GlvAKMQZNT67BzIEuLP4B5ieNNwMGWfd5VM4MOq_HXlfR8VR1GJtNkGvH0qqU6Z8dB02WPihkYXnUP2u4UjVt2uSXSk8lcr_nMQu1PoQDCkxSHRDMfBolhlrpylY7TgJryg24OdPkgFmyeXS8QBvRNgRYRGtoMLkSVvBvt2SDlhkTAtNStH5uZA1qx4ww6cXNE7ifjthI7cZ1T4csA0DSBS6jgu99GoVN21p-MfrlIWszX3-A"
  //   var user = await plugin.verify(token)
  //   expect(user).toMatchObject({ 
  //     sub: 'google-oauth2|113620159765357156857',
  //     nickname: 'danieljyoo',
  //     email: 'danieljyoo@gmail.com'
  //   })
  // })
})