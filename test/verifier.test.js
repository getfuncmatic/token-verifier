const verifier = require('../lib/verifier')
var pino = require('pino')()

const EXPIRED_AUTH0_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6Ik9VUXdSRGhETXpZME5qTXhOa0ZHUWprelF6UXdOa0pETVRZMU0wUTBNa0pGUVRjNU5VSTFRZyJ9.eyJpc3MiOiJodHRwczovL2Z1bmNtYXRpYy5hdXRoMC5jb20vIiwic3ViIjoiZ29vZ2xlLW9hdXRoMnwxMTM2MjAxNTk3NjUzNTcxNTY4NTciLCJhdWQiOlsiaHR0cHM6Ly9mdW5jbWF0aWMuYXV0aDAuY29tL2FwaS92Mi8iLCJodHRwczovL2Z1bmNtYXRpYy5hdXRoMC5jb20vdXNlcmluZm8iXSwiaWF0IjoxNTI3NTQ0OTA3LCJleHAiOjE1Mjc1NTIxMDcsImF6cCI6IjlCa0NuMndreXcxZ2NqVGt3RjYzcVMyaU9qV001a2VUIiwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCJ9.PvuKP_c1Fpaor9UvwyOf6pgSkylST-wdYR7zau-tF7kt6Gtb0u4MEs9hTr6ydMDyjpHAkhc6Tdumq_vvEJkVcwtIWzycSTwdW8IfhKUWai1Dh3w7ZnVtPqxWesmK5ny8ytw36Km0Yt_aOpNeyUNQ3JACLe9UuVuY8wDA9mJXGZDOi2zBu03hBA0NssgOTpzfx1L1IHqi5H8leaIeQ2AgXWgVXIuK81k6UKHgqOLbqnVSpU7yllxystTKqL6NrpZ1Qn4Vkt33df2GrjHaeipOpep_LXxFG2DZ2nN6vcyjEQIsY_7QO7p9JIq-u_zRKnGhFHL65bJeQI0sNipPb5NpnQ"
const EXPIRED_COGNITO_TOKEN = "eyJraWQiOiJVMmozN3pRMDlBMFdOWVM0Z2t1YWhwVzJRXC94amFIZ0hYRWFlMHAyMzBETT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwZWRiMzE3Ni1lM2Q5LTQ1YWMtOGEyNi1iNmQ0M2NiMWY2ZDEiLCJhdWQiOiI1YTdyZ3Q0amNiZ3FqdTIwa25tdjVsdTE4OSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjFjYWYxNzZhLTY2ZTktMTFlOC04ZmM4LTIxYmJiMTA2NThmYiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTI4MDAxMjAzLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9lSlR3MmRzRlUiLCJjb2duaXRvOnVzZXJuYW1lIjoiMGVkYjMxNzYtZTNkOS00NWFjLThhMjYtYjZkNDNjYjFmNmQxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZGFuaWVsanlvbyIsImV4cCI6MTUyODAwNDgwMywiaWF0IjoxNTI4MDAxMjAzLCJlbWFpbCI6ImRhbmllbGp5b29AZ21haWwuY29tIn0.VwegW4bXu11vlnAWD0UT5SEfIZJnLQd0z2LSyECugiWl8nxOjz0KwDHj4Zs2o2MAEqDEowsUIJIVA5IfO9W9Zlay7_EPTktzAwXa6o8Sh5qEgDwd9B6dCH4a6nAudXOfEZX38jJbVvgJkmE9_xdWEG0XHt1Yl7w14ulBz8cFQp0qY8lgJxaCwRSpYdm5OFhi9NgTHzb0McLx93ty0EyPA3JTPBex-XpvpXiGyaY1sobNzj1NGVQROIju2zxSp96t2BckCavrG8NCNWoHi0jJu0iNv3LZxTB6F_34VzPY70Zj03yfuqKpqVLgUhgmZosUUDJsfo0DaARN1LESeECQzQ"

describe('isTokenExpired', () => {
  it ('should return false if token is not expired', async () => {
    var exp = getCurrentTimeInSeconds(10)  
    var res = verifier.isTokenExpired({ exp })
    expect(res).toBe(false)
  })
  it ('should return current true value with time and exp if token is expired', async () => {
    var exp = getCurrentTimeInSeconds(-10)
    var res = verifier.isTokenExpired({ exp })
    expect(res).toBeTruthy()
    expect(res).toMatchObject({
      t: expect.anything(),
      exp
    })
  })
  it ('should return current true value with time if token does not have exp', async () => {
    var res = verifier.isTokenExpired({ })
    expect(res).toBeTruthy()
    expect(res).toMatchObject({
      t: expect.anything()
    })
  })
})

describe('Initialize Plugins', async () => {
  it ('should initialize the correct plugins based on options', async () => {
    var options = {
      auth0: { 
        domain: 'auth0domain',
        clientId: 'auth0clientid'
      }
    }
    var plugins = verifier.initializePlugins(options)
    expect(plugins.length).toBe(1)
    expect(plugins[0].name).toBe("auth0")
    options.cognito = {
      region: 'region',
      userPoolId: 'userpoolid',
      clientId: 'clientid'
    }
    plugins = verifier.initializePlugins(options)
    expect(plugins.length).toBe(2)
    expect(plugins[0].name).toBe("auth0")
    expect(plugins[1].name).toBe("cognito")
  })
})

describe('Verify token', async () => {
  beforeEach(() => {
    verifier.initializePlugins({
      auth0: { 
        domain: process.env.AUTH0_DOMAIN,
        clientId: process.env.AUTH0_CLIENTID
      },
      cognito: {
        region: process.env.COGNITO_REGION,
        userPoolId: process.env.COGNITO_USERPOOLID,
        clientId: process.env.AUTH0_CLIENTID
      }
    })
  })
  it ('should return false before providers if given token is already expired', async () => {
    var result = await verifier.verify(EXPIRED_AUTH0_TOKEN)
      expect(result.verification).toMatchObject({
        provider: null,
        verified: false,
        message: "token is expired"
    })
  })
  it ('should route the token to the correct plugin', async () => {
    var result = await verifier.verify(EXPIRED_AUTH0_TOKEN, { skipExpirationCheck: true })
    expect(result.verification).toMatchObject({
      provider: "auth0"
    })
    var result = await verifier.verify(EXPIRED_COGNITO_TOKEN, { skipExpirationCheck: true })
    expect(result.verification).toMatchObject({
      provider: "cognito"
    })
  })
  it ('should return no matching provider if no plugin matches', async () => {
    var result = await verifier.verify("DUMMY-TOKEN", {
      skipExpirationCheck: true,
      decoded: {
        payload: { iss: "https://no-matching-provider.com" }
      }
    })
    expect(result.verification).toMatchObject({
      provider: null,
      verified: false,
      message: "No matching provider for token"
    })
  })
})

function getCurrentTimeInSeconds(offset) {
  return ((new Date()).getTime() / 1000) + (offset || 0)
}