var fs = require("fs");
var crypto = require("crypto");
var request = require("request");
var {exec} = require("child_process");
var IP,CLIENT_ID,AUTH_KEY,PATH;
var unzipProc;

class Cryptographer {
  encrypt(text,key) {
    key = "/".repeat(32 - key.length) + key;
    var iv = crypto.randomBytes(16);
    var cipher = crypto.createCipheriv("aes-256-cbc",Buffer.from(key),iv);
    var encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted,cipher.final()]);
    return encrypted.toString("hex") + ":" + iv.toString("hex");
  }
  decrypt(text,key) {
    try {
      key = "/".repeat(32 - key.length) + key;
      text = text.toString().split(":");
      var iv = Buffer.from(text.pop(),"hex");
      var encrypted = Buffer.from(text.join(":"),"hex");
      var decipher = crypto.createDecipheriv("aes-256-cbc",Buffer.from(key),iv);
      var decrypted = decipher.update(encrypted);
      decrypted = Buffer.concat([decrypted,decipher.final()]);
      return decrypted.toString();
    } catch ( err ) {
      return "decrypt-failed";
    }
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
  files = files.filter(item => item).map(item => [item.slice(1),item.charAt(0) == "d" ? "Directory" : "File"]);
  files = [["Name","Type"]].concat(files);
  var max = files.reduce((a,b) => Math.max(a,b[0].length),0);
  var set = [];
  for ( var i = 0; i < files.length; i++ ) {
    set.push(`${files[i][0]}${" ".repeat(max - files[i][0].length)} | ${files[i][1]}`);
    if ( i == 0 ) set.push("-".repeat(max + 12));
  }
  if ( files.length == 1 ) set.push("Directory empty");
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
      if ( body == "error" ) {
        throw new Error("Failed to communicate with server");
        return;
      }
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

function changeDirectory(toDir) {
  if ( toDir == ".." ) {
    loadParams(function() {
      PATH = (PATH.split("/").slice(0,-1).join("/")) || "/";
      var obj = {
        mode: "connected",
        ip: IP,
        clientID: CLIENT_ID,
        key: AUTH_KEY,
        path: PATH
      }
      fs.writeFile(__dirname + "/loginData.json",JSON.stringify(obj,null,2),function(err) {
        if ( err ) throw err;
      });
    });
  } else {
    listFolder(function(files) {
      if ( files.indexOf("d" + toDir) <= -1 ) {
        throw new Error("Invalid folder name in working directory");
        return;
      } else {
        PATH += "/" + toDir;
        PATH = PATH.split("//").join("/");
        var obj = {
          mode: "connected",
          ip: IP,
          clientID: CLIENT_ID,
          key: AUTH_KEY,
          path: PATH
        }
        fs.writeFile(__dirname + "/loginData.json",JSON.stringify(obj,null,2),function(err) {
          if ( err ) throw err;
        });
      }
    });
  }
}

function removeFile(toRemove) {
  listFolder(function(files) {
    if ( files.indexOf("d" + toRemove) <= -1 && files.indexOf("f" + toRemove) <= -1 ) {
      throw new Error("Invalid file or directory");
      return;
    } else {
      var cg = new Cryptographer();
      request.post({
        url: `http://${IP}:5750/remove?cid=${CLIENT_ID}`,
        body: cg.encrypt(toRemove,AUTH_KEY)
      },function(err,response,body) {
        if ( err ) throw err;
        if ( body == "error" ) {
          throw new Error("Failed to communicate with server");
          return;
        }
      });
    }
  });
}

function downloadFile(toDownload) {
  listFolder(function(files) {
    var cg = new Cryptographer();
    if ( files.indexOf("f" + toDownload) > -1 ) {
      request.post({
        url: `http://${IP}:5750/prepare?cid=${CLIENT_ID}`,
        body: cg.encrypt(`${PATH}/${toDownload},download`,AUTH_KEY)
      },function(err,response,body) {
        if ( err ) throw err;
        if ( body == "error" ) {
          throw new Error("Failed to communicate with server");
          return;
        }
        var iv = cg.decrypt(body,AUTH_KEY);
        var decipher = crypto.createDecipheriv("aes-256-cbc",Buffer.from(AUTH_KEY),Buffer.from(iv,"base64"));
        var write = fs.createWriteStream(`./${toDownload}`);
        request.post({
          url: `http://${IP}:5750/download?cid=${CLIENT_ID}`,
          body: ""
        }).pipe(decipher).pipe(write);
      });
    } else if ( files.indexOf("d" + toDownload) > -1 ) {
      request.post({
        url: `http://${IP}:5750/prepare?cid=${CLIENT_ID}`,
        body: cg.encrypt(`${PATH}/${toDownload},download`,AUTH_KEY)
      },function(err,response,body) {
        if ( err ) throw err;
        if ( body == "error" ) {
          throw new Error("Failed to communicate with server");
          return;
        }
        var iv = cg.decrypt(body,AUTH_KEY);
        var decipher = crypto.createDecipheriv("aes-256-cbc",Buffer.from(AUTH_KEY),Buffer.from(iv,"base64"));
        var write = fs.createWriteStream(`${__dirname}/temp.zip`);
        write.on("close",function() {
          unzipProc = exec(`yes | unzip ${__dirname}/temp.zip -d ./${toDownload}`);
          unzipProc.stdout.on("data",Function.prototype);
          unzipProc.stderr.on("data",Function.prototype);
          unzipProc.on("close",function(code) {
            fs.unlink(`${__dirname}/temp.zip`,function(err) {
              if ( err ) throw err;
            });
          });
        });
        request.post({
          url: `http://${IP}:5750/download?cid=${CLIENT_ID}`,
          body: ""
        }).pipe(decipher).pipe(write);
      });
    } else {
      throw new Error("Invalid file or directory");
      return;
    }
  });
}

downloadFile("nested")
