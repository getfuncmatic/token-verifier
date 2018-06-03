const cognito = require('../lib/cognito')
const jwtDecode = require('jwt-decode')

var pino = require('pino')()

describe('Cognito Initialization', () => {
  it ('should initialize plugin', async () => {
    var plugin = cognito.initialize({ 
      region: process.env.COGNITO_REGION, 
      userPoolId: process.env.COGNITO_USERPOOLID,
      clientId: process.env.COGNITO_CLIENTID
    })
    expect(plugin.verify).toBeTruthy()
    expect(plugin.isIssuer).toBeTruthy()
  })  
  it ('should throw Error if options not provided', async () => {
    expect(() => { 
      cognito.initialize({ }) 
    }).toThrow()
  })
})

describe('Cognito isIssuer', () => {
  var plugin = null
  
  beforeEach(() => {
    plugin = cognito.initialize({ 
      region: process.env.COGNITO_REGION, 
      userPoolId: process.env.COGNITO_USERPOOLID,
      clientId: process.env.COGNITO_CLIENTID
    })
  });
  it ('should return true if cognito-idp is in iss', async () => {
    var flag = plugin.isIssuer({
      payload: { iss: 'https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_example' }
    })
    expect(flag).toBe(true)
  })
  it ('should return false if cognito-idp is not in iss', async () => {
    var flag = plugin.isIssuer({
      payload: { iss: 'https://my-domain.auth0.com/'  }
    })
    expect(flag).toBe(false)
  })
})

describe('Cognito verification', () => {
  var plugin = null
  
  beforeEach(() => {
    plugin = cognito.initialize({ 
      region: process.env.COGNITO_REGION, 
      userPoolId: process.env.COGNITO_USERPOOLID,
      clientId: process.env.COGNITO_CLIENTID
    })
  });
  it ('should return Bad Request for an invalid token format', async () => {
    var token = "BAD TOKEN"
    var user = await plugin.verify(token, { header: { kid: "BAD-KID" } })
    expect(user).toMatchObject({
      verified: false,
      message: "Public key not found in jwks.json"
    })
  })
  it ('should return for an expired token', async () => {
    var token = "eyJraWQiOiJVMmozN3pRMDlBMFdOWVM0Z2t1YWhwVzJRXC94amFIZ0hYRWFlMHAyMzBETT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwZWRiMzE3Ni1lM2Q5LTQ1YWMtOGEyNi1iNmQ0M2NiMWY2ZDEiLCJhdWQiOiI1YTdyZ3Q0amNiZ3FqdTIwa25tdjVsdTE4OSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjFjYWYxNzZhLTY2ZTktMTFlOC04ZmM4LTIxYmJiMTA2NThmYiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTI4MDAxMjAzLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9lSlR3MmRzRlUiLCJjb2duaXRvOnVzZXJuYW1lIjoiMGVkYjMxNzYtZTNkOS00NWFjLThhMjYtYjZkNDNjYjFmNmQxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZGFuaWVsanlvbyIsImV4cCI6MTUyODAwNDgwMywiaWF0IjoxNTI4MDAxMjAzLCJlbWFpbCI6ImRhbmllbGp5b29AZ21haWwuY29tIn0.VwegW4bXu11vlnAWD0UT5SEfIZJnLQd0z2LSyECugiWl8nxOjz0KwDHj4Zs2o2MAEqDEowsUIJIVA5IfO9W9Zlay7_EPTktzAwXa6o8Sh5qEgDwd9B6dCH4a6nAudXOfEZX38jJbVvgJkmE9_xdWEG0XHt1Yl7w14ulBz8cFQp0qY8lgJxaCwRSpYdm5OFhi9NgTHzb0McLx93ty0EyPA3JTPBex-XpvpXiGyaY1sobNzj1NGVQROIju2zxSp96t2BckCavrG8NCNWoHi0jJu0iNv3LZxTB6F_34VzPY70Zj03yfuqKpqVLgUhgmZosUUDJsfo0DaARN1LESeECQzQ"
    var decoded = decodeToken(token)
    var user = await plugin.verify(token, decoded)
    expect(user).toMatchObject({
      verified: false,
      message: "Token is expired"
    })
  })
  // it ('should return user info for a valid token', async () => {
  //   var token = "eyJraWQiOiJVMmozN3pRMDlBMFdOWVM0Z2t1YWhwVzJRXC94amFIZ0hYRWFlMHAyMzBETT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIwZWRiMzE3Ni1lM2Q5LTQ1YWMtOGEyNi1iNmQ0M2NiMWY2ZDEiLCJhdWQiOiI1YTdyZ3Q0amNiZ3FqdTIwa25tdjVsdTE4OSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJldmVudF9pZCI6IjFjYWYxNzZhLTY2ZTktMTFlOC04ZmM4LTIxYmJiMTA2NThmYiIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNTI4MDAxMjAzLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtd2VzdC0yLmFtYXpvbmF3cy5jb21cL3VzLXdlc3QtMl9lSlR3MmRzRlUiLCJjb2duaXRvOnVzZXJuYW1lIjoiMGVkYjMxNzYtZTNkOS00NWFjLThhMjYtYjZkNDNjYjFmNmQxIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiZGFuaWVsanlvbyIsImV4cCI6MTUyODAwNDgwMywiaWF0IjoxNTI4MDAxMjAzLCJlbWFpbCI6ImRhbmllbGp5b29AZ21haWwuY29tIn0.VwegW4bXu11vlnAWD0UT5SEfIZJnLQd0z2LSyECugiWl8nxOjz0KwDHj4Zs2o2MAEqDEowsUIJIVA5IfO9W9Zlay7_EPTktzAwXa6o8Sh5qEgDwd9B6dCH4a6nAudXOfEZX38jJbVvgJkmE9_xdWEG0XHt1Yl7w14ulBz8cFQp0qY8lgJxaCwRSpYdm5OFhi9NgTHzb0McLx93ty0EyPA3JTPBex-XpvpXiGyaY1sobNzj1NGVQROIju2zxSp96t2BckCavrG8NCNWoHi0jJu0iNv3LZxTB6F_34VzPY70Zj03yfuqKpqVLgUhgmZosUUDJsfo0DaARN1LESeECQzQ"
  //   var decoded = decodeToken(token)
  //   var user = await plugin.verify(token, decoded)
  //   expect(user).toMatchObject({
  //     verified: true,
  //     claims: {
  //       sub: expect.anything()
  //     }
  //   })
  // })
})

function decodeToken(token) {
  var payload =  jwtDecode(token)
  var header = jwtDecode(token, { header: true })
  return { header, payload }
}
