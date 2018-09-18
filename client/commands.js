var fs = require("fs");
var CryptoJS = require("crypto-js");
var request = require("request");
var IP,CLIENT_ID,AUTH_KEY,PATH;

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

function loadParams(callback) {
  fs.readFile(__dirname + "/loginData.json",function(err,data) {
    if ( err ) throw err;
    data = JSON.parse(data.toString());
    IP = data.ip;
    CLIENT_ID = data.clientID;
    AUTH_KEY = data.key;
    PATH = data.path;
    callback();
  });
}

function generateTable(files) {
  files = files.sort();
  files = files.map(item => [item.slice(1),item.charAt(0) == "d" ? "Directory" : "File"]);
  files = [["Name","Type"]].concat(files);
  var max = files.reduce((a,b) => Math.max(a,b[0].length),0);
  var set = [];
  for ( var i = 0; i < files.length; i++ ) {
    set.push(`${files[i][0]}${" ".repeat(max - files[i][0].length)} | ${files[i][1]}`);
    if ( i == 0 ) set.push("-".repeat(max + 12));
  }
  console.log(set.join("\n"));
}

function listFolder(callback) {
  loadParams(function() {
    var cg = new Cryptographer();
    request.post({
      url: `http://${IP}:5750/list?cid=${CLIENT_ID}`,
      body: cg.encrypt(PATH,AUTH_KEY),
    },function(err,response,body) {
      if ( err ) throw err;
      if ( body == "error" ) throw new Error("Failed to communicate with server");
      var files = cg.decrypt(body,AUTH_KEY).split(",");
      if ( callback ) {
        callback(files);
        return;
      }
      console.log(`Files at ${PATH}:\n`);
      generateTable(files);
    });
  });
}


listFolder();
