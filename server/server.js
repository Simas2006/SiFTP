var fs = require("fs");
var CryptoJS = require("crypto-js");
var express = require("express");
var PORT = process.argv[3] || 5750;
var PASSWORD = process.argv[2];
var AUTH_KEYS = {};
var app = express();

if ( ! PASSWORD ) throw new Error("No password provided");

class Cryptographer {
  encrypt(message,key) {
    key = CryptoJS.enc.Base64.parse(key);
    var iv = CryptoJS.lib.WordArray.random(32);
    var encrypted = CryptoJS.AES.encrypt(
      message.toString(CryptoJS.enc.Base64),
      key,
      {iv}
    );
    return [
      encrypted.ciphertext.toString(CryptoJS.enc.Base64),
      iv.toString(CryptoJS.enc.Base64)
    ].join(":");
  }
  decrypt(message,key) {
    try {
      key = CryptoJS.enc.Base64.parse(key);
      var decrypted = CryptoJS.AES.decrypt(
        message.split(":")[0],
        key,
        {iv: CryptoJS.enc.Base64.parse(message.split(":")[1])}
      );
      return decrypted.toString(CryptoJS.enc.Utf8);
    } catch ( err ) {
      return "decrypt-failed";
    }
  }
  generateKey(passphrase) {
    if ( passphrase ) return passphrase + "/".repeat(32 - passphrase.length);
    else return CryptoJS.lib.WordArray.random(32).toString(CryptoJS.enc.Base64);
  }
}

function getPostData(request,callback) {
  var body = "";
  request.on("data",function(chunk) {
    body += chunk;
  });
  request.on("end",function() {
    callback(body);
  });
}

app.post("/connect",function(request,response) {
  getPostData(request,function(body) {
    var cg = new Cryptographer();
    if ( cg.decrypt(body,cg.generateKey(PASSWORD)) == "siftp-authentication" ) {
      var id = Math.floor(Math.random() * 1e8);
      var key = cg.generateKey();
      AUTH_KEYS[id] = key;
      response.send(cg.encrypt(`${id},${key}`,cg.generateKey(PASSWORD)));
    } else {
      response.send("error");
    }
  });
});

app.get("/blank",function(request,response) {
  response.send("hi");
});

app.listen(PORT,function() {
  console.log("Listening on port " + PORT);
  var cg = new Cryptographer();
  console.log(cg.encrypt("siftp-authentication",cg.generateKey(PASSWORD)));
});
