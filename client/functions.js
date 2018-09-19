var fs = require("fs");
var crypto = require("crypto");
var request = require("request");
var archiver = require("archiver");
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

function connectToHost(name,callback) {
  var cg = new Cryptographer();
  fs.readFile(__dirname + "/hosts.json",function(err,data) {
    if ( err ) throw err;
    data = JSON.parse(data.toString());
    if ( ! data[name] ) {
      throw new Error("Invalid host name");
      return;
    }
    request.post({
      url: `http://${data[name].ip}:5750/connect`,
      body: cg.encrypt("siftp-authentication",data[name].password)
    },function(err,response,body) {
      if ( err ) throw err;
      if ( body == "error" ) {
        throw new Error("Failed to communicate with server");
        return;
      }
      body = cg.decrypt(body,data[name].password).split(",");
      CLIENT_ID = body[0];
      AUTH_KEY = body[1];
      IP = data[name].ip;
      PATH = "/";
      var obj = {
        mode: "connected",
        ip: IP,
        clientID: CLIENT_ID,
        key: AUTH_KEY,
        path: PATH
      }
      fs.writeFile(__dirname + "/loginData.json",JSON.stringify(obj,null,2),function(err) {
        if ( err ) throw err;
        callback();
      });
    })
  });
}

function disconnectFromHost(callback) {
  loadParams(function() {
    var cg = new Cryptographer();
    request.post({
      url: `http://${IP}:5750/disconnect?cid=${CLIENT_ID}`,
      body: cg.encrypt("siftp-authentication",AUTH_KEY)
    },function(err,response,body) {
      if ( err ) throw err;
      if ( body == "error" ) {
        throw new Error("Failed to communicate with server");
        return;
      }
      var obj = {
        mode: "disconnected"
      }
      fs.writeFile(__dirname + "/loginData.json",JSON.stringify(obj,null,2),function(err) {
        if ( err ) throw err;
        callback();
      });
    });
  });
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
      callback(files);
    });
  });
}

function changeDirectory(toDir,callback) {
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
        callback();
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
          callback();
        });
      }
    });
  }
}

function removeFile(toRemove,callback) {
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
        callback();
      });
    }
  });
}

function downloadFile(toDownload,callback) {
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
        write.on("close",function() {
          callback();
        });
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
              callback();
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

function uploadFile(toUpload,callback) {
  loadParams(function() {
    var cg = new Cryptographer();
    fs.stat(`./${toUpload}`,function(err,stats) {
      if ( err ) throw err;
      if ( ! stats.isDirectory() ) {
        request.post({
          url: `http://${IP}:5750/prepare?cid=${CLIENT_ID}`,
          body: cg.encrypt(`${PATH}/${toUpload},upload,file`,AUTH_KEY)
        },function(err,response,body) {
          if ( err ) throw err;
          if ( body == "error" ) {
            throw new Error("Failed to communicate with server");
            return;
          }
          var iv = cg.decrypt(body,AUTH_KEY);
          var cipher = crypto.createCipheriv("aes-256-cbc",Buffer.from(AUTH_KEY),Buffer.from(iv,"base64"));
          var read = fs.createReadStream(`./${toUpload}`);
          read.pipe(cipher).pipe(request.post({
            url: `http://${IP}:5750/upload?cid=${CLIENT_ID}`,
            headers: {
              "Content-Type": "application/octet-stream"
            }
          },function(err,response,body) {
            if ( err ) throw err;
            callback();
          }));
        });
      } else {
        request.post({
          url: `http://${IP}:5750/prepare?cid=${CLIENT_ID}`,
          body: cg.encrypt(`${PATH}/${toUpload},upload,directory`,AUTH_KEY)
        },function(err,response,body) {
          if ( err ) throw err;
          if ( body == "error" ) {
            throw new Error("Failed to communicate with server");
            return;
          }
          var iv = cg.decrypt(body,AUTH_KEY);
          var cipher = crypto.createCipheriv("aes-256-cbc",Buffer.from(AUTH_KEY),Buffer.from(iv,"base64"));
          var archive = archiver("zip",{
            zlib: {level: 9}
          });
          archive.on("warning",function(err) {
            if ( err.code != "ENOENT" ) throw err;
          });
          archive.on("error",function(err) {
            if ( err.code != "ENOENT" ) throw err;
          });
          archive.pipe(cipher).pipe(request.post({
            url: `http://${IP}:5750/upload?cid=${CLIENT_ID}`,
            headers: {
              "Content-Type": "application/octet-stream"
            }
          },function(err,response,body) {
            if ( err ) throw err;
            callback();
          }));
          archive.directory(`./${toUpload}`,false);
          archive.finalize();
        });
      }
    });
  });
}

disconnectFromHost(function() {
  console.log("done");
});
