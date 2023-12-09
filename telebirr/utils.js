const crypto = require('crypto');
const { v1: uuidv1 } = require('uuid');

function sign_sha256(data, private_key) {
  const orderedItems = Object.fromEntries(Object.entries(data).sort());
  let string_a = '';
  for (const [key, value] of Object.entries(orderedItems)) {
    if (string_a === '') {
      string_a = `${key}=${value}`;
    } else {
      string_a += `&${key}=${value}`;
    }
  }
  let string_b;
  if (private_key === undefined) {
    string_b = crypto.createHash('sha256').update(string_a).digest('hex');
  } else {
    string_b = sign_rsa(string_a, private_key);
  }
  return string_b;
}

function SignWithRSA(data, key, sign_type = "SHA256withRSA") {
  if (sign_type === "SHA256withRSA") {
    const keyBuffer = Buffer.from(key, 'base64');
    const privateKey = crypto.createPrivateKey({
      key: keyBuffer,
      format: 'der',
      type: 'pkcs1'
    });
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(data);
    const signature = signer.sign(privateKey, 'base64');
    return signature;
  } else {
    return "Only allowed to the type SHA256withRSA hash";
  }
}

function sign(request, privateKey) {
  const excludeFields = ["sign", "sign_type", "header", "refund_info", "openType", "raw_request"];
  const join = [];

  for (const key in request) {
    if (excludeFields.includes(key)) {
      continue;
    }
    if (key === "biz_content") {
      const bizContent = request["biz_content"];
      for (const k in bizContent) {
        join.push(`${k}=${bizContent[k]}`);
      }
    } else {
      join.push(`${key}=${request[key]}`);
    }
  }

  join.sort();
  const separator = '&';
  const inputString = join.join(separator);

  return SignWithRSA(inputString, privateKey, "SHA256withRSA");
}

function createMerchantOrderId() {
  return String(Math.floor(Date.now() / 1000));
}

function createTimeStamp() {
  return String(Math.floor(Date.now() / 1000));
}

function createNonceStr() {
  return uuidv1();
}

module.exports = { sign_sha256, SignWithRSA, sign }