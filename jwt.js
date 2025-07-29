const crypto = require('crypto');
//Just a test implemenation of a JWT in js from https://www.jwt.io/

class JWT {
  #secretKey;
  constructor(header, payload, secretKey) {
    this.header = header;
    this.payload = payload;
    this.#secretKey = secretKey;
    this.hashAlgorithm = 'SHA256';

    if (this.#secretKey === undefined) {
      this.#secretKey = "";
    }
  }
  valueOf() {
    return JWT.encode(this);
  }
  toString(){
    return JWT.encode(this);
  }
  setSecretKey(newSecretKey) {
    this.#secretKey = newSecretKey;
  }
  getSecretKey(){
    return this.#secretKey;
  }
  static convertBase64fromBase64URL(base64URLString) {
    const base64String = base64URLString.replaceAll("-", "+").replaceAll("_", "/");
    return base64String;
  }
  static convertBase64URLfromBase64(base64String) {
    const base64URLString = base64String.replaceAll("+", "-").replaceAll("/", "_");
    return base64URLString;

  }
  static encode(jwtObj) {
    let { header, payload } = jwtObj;

    const headerBase64 = btoa(JSON.stringify(header)).replaceAll("=", "");
    const payloadBase64 = btoa(JSON.stringify(payload)).replaceAll("=", "");
    const signatureBase64 = crypto
      .createHmac('SHA256', jwtObj.getSecretKey())
      .update(headerBase64 + "." + payloadBase64)
      .digest("base64")
      .replaceAll("=", "");
    const headerBase64URL = JWT.convertBase64URLfromBase64(headerBase64);
    const payloadBase64URL = JWT.convertBase64URLfromBase64(payloadBase64);
    const signatureBase64URL = JWT.convertBase64URLfromBase64(signatureBase64);
    return `${headerBase64URL}.${payloadBase64URL}.${signatureBase64URL}`;
  }
  static decode(base64URL) {
    if (typeof base64URL !== "string") {
      throw new Error("JWT.decode requires a base64URL string")
    }
    let [header, payload, signature] = base64URL
      .split(".")
      .map(base64URL => {
        const jsonString = JWT.convertBase64fromBase64URL(base64URL);
        return atob(jsonString);
      });
    try {
      header = JSON.parse(header);
      payload = JSON.parse(payload)
    } catch (e) {
      console.error("Error parsing JWT Header/Payload");
      console.error(e);
    }
    return { header, payload, signature }
  }
}
const testHeader = {
  "alg": "HS256",
  "typ": "JWT"
};
const testPayload = {
  "sub": "1234567890",
  "name": "John Doe",
  "admin": true,
  "iat": 1516239022
}

const sampleFromJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30"

const jwt = new JWT(testHeader, testPayload)
jwt.setSecretKey("a-string-secret-at-least-256-bits-long");
const encoded_jwt = JWT.encode(jwt);


console.log(sampleFromJWT, encoded_jwt);
assert.strictEqual(sampleFromJWT, encoded_jwt);
assert.strictEqual(sampleFromJWT, `${jwt}`);

console.log(`${jwt}`)