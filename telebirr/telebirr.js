const { sign_sha256, SignWithRSA, sign } = require('./utils')
const axios = require('axios');
const moment = require('moment');
const crypto = require('crypto');
const NodeRSA = require('node-rsa');

class Telebirr {
  constructor(appId, appKey, publicKey, notifyUrl, receiveName, returnUrl, shortCode, subject, timeoutExpress, totalAmount, nonce, outTradeNo, api = 'http://196.188.120.3:10443/service-openup/toTradeWebPay') {
    this.api = api;
    this.appId = appId;
    this.ussd = this.encryptUssd(
      {
        appId: this.appId,
        notifyUrl,
        outTradeNo,
        receiveName,
        returnUrl,
        shortCode,
        subject,
        timeoutExpress,
        totalAmount,
        nonce,
        timestamp: String(Math.floor(Date.now() / 1000))
      },
      publicKey
    );
    this.sign = this.signUssd(
      {
        appId: this.appId,
        notifyUrl,
        outTradeNo,
        receiveName,
        returnUrl,
        shortCode,
        subject,
        timeoutExpress,
        totalAmount,
        nonce,
        timestamp: String(Math.floor(Date.now() / 1000))
      },
      appKey
    );
  }

  static encryptUssd(ussd, publicKey) {
	  const formattedPublicKey = publicKey.replace(/(.{64})/g, '$1\n');
	  const formattedKey = `-----BEGIN CERTIFICATE-----\n${formattedPublicKey}\n-----END CERTIFICATE-----`;
	  const ussdJson = JSON.stringify(ussd);
	  const encrypt = Telebirr.encrypt(formattedKey, ussdJson);
	  return encrypt;
	}

  requestParams() {
    return {
      appid: this.appId,
      sign: this.sign,
      ussd: this.ussd
    };
  }

  async sendRequest() {
    try {
      const response = await axios.post(this.api, this.requestParams());
      return response.data;
    } catch (error) {
      console.error('Error sending request:', error);
      throw error;
    }
  }

  static decrypt(publicKey, payload) {
    const key = new NodeRSA();
    key.importKey(publicKey, 'pkcs8-public-pem');
    const signature = Buffer.from(payload, 'base64');
    const decrypted = key.decrypt(signature, 'utf8');
    return JSON.parse(decrypted);
  }
  static encrypt(publicKey, msg) {
	  const rsa = new NodeRSA();
	  rsa.importKey(publicKey, 'pkcs8-public-pem');
	  const cipher = crypto.createCipheriv('RSAES-PKCS1-v1_5', rsa.exportKey('public'), '');
	  let ciphertext = cipher.update(msg, 'utf8', 'base64');
	  ciphertext += cipher.final('base64');
	  return ciphertext;
	}
}

class TelebirrSuperApp{
	constructor(short_code, app_key, app_secret, merchant_id, private_key, url) {
	    this.short_code = short_code
	    this.app_key = app_key
	    this.app_secret = app_secret
	    this.merchant_id = merchant_id
	    this.private_key = private_key
	    this.url = url
	}
	async applyFabricToken() {
	  try {
	    const response = await axios.post(
	      `${this.url}/apiaccess/payment/gateway/payment/v1/token`,
	      { appSecret: this.app_secret },
	      {
	        headers: { 'X-App-key': this.app_key },
	        validateStatus: false
	      }
	    );

	    return JSON.parse(response.data);
	  } catch (error) {
	    console.error(error);
	    // Handle error
	  }
	}

	async auth(token) {
	    const fabric_token = await this.applyFabricToken();
	    const url = this.url + "/apiaccess/payment/gateway/payment/v1/auth/authToken";

	    const timestamp = moment().unix();
	    const nonce_str = uuidv4().replace(/-/g, '');
	    
	    const payload = {
	      timestamp: timestamp.toString(),
	      method: "payment.authtoken",
	      nonce_str: nonce_str,
	      biz_content: {
	        access_token: token,
	        trade_type: "InApp",
	        appid: this.merchant_id,
	        resource_type: "OpenId",
	      },
	      version: "1.0",
	      sign_type: "SHA256WithRSA",
	    };

	    const signature = sign(payload, this.private_key);
	    payload.sign = signature;

	    try {
	      const response = await axios.post(url, payload, {
	        headers: {
	          "X-App-key": this.app_key,
	          "Authorization": fabric_token.token,
	          "Content-Type": "application/json"
	        },
	        validateStatus: false
	      });

	      return response.data;
	    } catch (error) {
	      console.error(error);
	      // Handle error
	    }
  	}

  	async requestCreateOrder(nonce_str, amount, notify_url, redirect_url, merch_order_id, timeout_express, title, business_type, payee_identifier_type) {
	    const fabric_token = await this.applyFabricToken();
	    const url = this.url + "/apiaccess/payment/gateway/payment/v1/merchant/preOrder";
	    const SIGN_TYPE = "SHA256WithRSA";
	    const timestamp = moment().unix().toString();

	    const payload = {
	      nonce_str: nonce_str,
	      biz_content: {
	        notify_url: notify_url,
	        redirect_url: redirect_url,
	        trans_currency: "ETB",
	        total_amount: amount,
	        merch_order_id: merch_order_id,
	        appid: this.merchant_id,
	        merch_code: this.short_code,
	        timeout_express: timeout_express,
	        trade_type: "InApp",
	        title: title,
	        business_type: business_type,
	        payee_identifier: this.short_code,
	        payee_identifier_type: payee_identifier_type,
	        payee_type: "5000"
	      },
	      method: "payment.preorder",
	      version: "1.0",
	      sign_type: SIGN_TYPE,
	      timestamp: timestamp
	    };

	    const signature = sign(payload, this.private_key);
	    payload.sign = signature;

	    try {
	      const response = await axios.post(url, payload, {
	        headers: {
	          "X-App-key": this.app_key,
	          "Authorization": fabric_token.token,
	          "Content-Type": "application/json"
	        },
	        validateStatus: false
	      });

	      const responseData = response.data;
	      const prepay_id = responseData.biz_content.prepay_id;

	      const payPayload = {
	        appid: this.merchant_id,
	        merch_code: this.short_code,
	        nonce_str: nonce_str,
	        prepay_id: prepay_id,
	        timestamp: timestamp,
	        sign_type: SIGN_TYPE
	      };

	      const paySignature = sign(payPayload, this.private_key);
	      payPayload.sign = paySignature;

	      return { response: responseData, payload: payPayload };
	    } catch (error) {
	      console.error(error);
	      // Handle error
	    }
  }
  async queryOrder(nonce_str, merch_order_id, version = "1.0", method = "payment.queryorder", sign_type = "SHA256WithRSA") {
    const fabric_token = await this.applyFabricToken();
    const url = this.url + "/apiaccess/payment/gateway/payment/v1/merchant/queryOrder";
    const timestamp = moment().unix().toString();

    const payload = {
      timestamp: timestamp,
      nonce_str: nonce_str,
      method: method,
      sign_type: sign_type,
      version: version,
      biz_content: {
        appid: this.merchant_id,
        merch_code: this.short_code,
        merch_order_id: merch_order_id
      }
    };
    //pay_signature = utils.sign(payload, self.private_key)
    const signature = sign(payload, this.private_key);
    payload.sign = signature;

    try {
      const response = await axios.post(url, payload, {
        headers: {
          "X-App-key": this.app_key,
          "Authorization": fabric_token.token,
          "Content-Type": "application/json"
        },
        validateStatus: false
      });

      return JSON.parse(response.data);
    } catch (error) {
      console.error(error);
      // Handle error
    }
  }

  static __sign(data, private_key) {
	  const excludeFields = [
	    "sign",
	    "sign_type",
	    "header",
	    "refund_info",
	    "openType",
	    "raw_request",
	    "biz_cont"
	  ];

	  const to_sign_data = { ...data };
	  const flat_signa_data = {};

	  for (const [key, value] of Object.entries(to_sign_data)) {
	    if (typeof value === 'object') {
	      for (const [k, v] of Object.entries(value)) {
	        if (!excludeFields.includes(k)) {
	          flat_signa_data[k] = v;
	        }
	      }
	    } else {
	      if (!excludeFields.includes(key)) {
	        flat_signa_data[key] = value;
	      }
	    }
	  }

	  const string_b = sign_sha256(flat_signa_data, private_key);
	  return string_b;
	}

}
