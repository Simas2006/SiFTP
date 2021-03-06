var fs = require("fs");
var crypto = require("crypto");
var express = require("express");
var rimraf = require("rimraf");
var archiver = require("archiver");
var {exec} = require("child_process");
var PORT = process.argv[3] || 5750;
var PASSWORD = process.argv[2];
var auth_keys = {};
var preparations = {};
var unzipProc;
var unzipperLocked = false;
var app = express();

if ( ! PASSWORD ) throw new Error("No password provided");

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
  generateKey() {
    return crypto.randomBytes(24).toString("base64");
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
    if ( cg.decrypt(body,PASSWORD) == "siftp-authentication" ) {
      var id = Math.floor(Math.random() * 1e8);
      var key = cg.generateKey();
      auth_keys[id] = key;
      response.send(cg.encrypt(`${id},${key}`,PASSWORD));
    } else {
      response.send("error");
    }
  });
});

app.post("/disconnect",function(request,response) {
  getPostData(request,function(body) {
    var cg = new Cryptographer();
    var key = auth_keys[request.query.cid];
    if ( cg.decrypt(body,key) == "siftp-authentication" ) {
      auth_keys[request.query.cid] = null;
      preparations[request.query.cid] = null;
      response.send("ok");
    } else {
      response.send("error");
    }
  });
});

app.post("/list",function(request,response) {
  getPostData(request,function(body) {
    var cg = new Cryptographer();
    var key = auth_keys[request.query.cid];
    body = cg.decrypt(body,key);
    if ( body == "decrypt-failed" || body.indexOf("..") > -1 ) {
      response.send("error");
    } else {
      fs.readdir(`${__dirname}/data/${body}`,function(err,files) {
        if ( err ) {
          response.send("error");
        } else {
          var fileList = files.map(item => `${fs.lstatSync(`${__dirname}/data/${body}/${item}`).isDirectory() ? "d" : "f"}${item}`).join(",");
          response.send(cg.encrypt(fileList,key));
        }
      });
    }
  });
});

app.post("/remove",function(request,response) {
  getPostData(request,function(body) {
    var cg = new Cryptographer();
    var key = auth_keys[request.query.cid];
    body = cg.decrypt(body,key);
    if ( body == "decrypt-failed" || body.indexOf("..") > -1 ) {
      response.send("error");
    } else {
      fs.stat(`${__dirname}/data/${body}`,function(err,stats) {
        if ( err ) {
          response.send("error");
        } else {
          if ( ! stats.isDirectory() ) {
            fs.unlink(`${__dirname}/data/${body}`,function(err) {
              if ( err ) throw err;
              response.send("ok");
            });
          } else {
            rimraf(`${__dirname}/data/${body}`,{
              disableGlob: true
            },function(err) {
              if ( err ) throw err;
              response.send("ok");
            });
          }
        }
      });
    }
  });
});

app.post("/prepare",function(request,response) {
  getPostData(request,function(body) {
    var cg = new Cryptographer();
    var key = auth_keys[request.query.cid];
    body = cg.decrypt(body,key);
    if ( body == "decrypt-failed" || body.indexOf("..") > -1 ) {
      response.send("error");
    } else {
      body = body.split(",");
      fs.stat(`${__dirname}/data/${body[0]}`,function(err,stats) {
        if ( (err && (err.code != "ENOENT" || (err.code == "ENOENT" && body[1] == "download"))) || ["download","upload"].indexOf(body[1]) <= -1 ) {
          response.send("error");
        } else {
          var iv = crypto.randomBytes(16);
          preparations[request.query.cid] = {
            path: body[0],
            mode: body[1],
            isDirectory: body[1] == "download" ? stats.isDirectory() : body[2] == "directory",
            iv: iv
          }
          response.send(cg.encrypt(iv.toString("base64"),key));
        }
      });
    }
  });
});

app.post("/download",function(request,response) {
  if ( ! preparations[request.query.cid] || preparations[request.query.cid].type == "upload" ) {
    response.send("error");
  } else {
    var key = auth_keys[request.query.cid];
    var data = preparations[request.query.cid];
    var cipher = crypto.createCipheriv("aes-256-cbc",Buffer.from(key),data.iv);
    if ( ! data.isDirectory ) {
      var read = fs.createReadStream(`${__dirname}/data/${data.path}`);
      read.pipe(cipher).pipe(response);
    } else {
      var archive = archiver("zip",{
        zlib: {level: 9}
      });
      archive.on("warning",function(err) {
        if ( err.code != "ENOENT" ) throw err;
      });
      archive.on("error",function(err) {
        if ( err.code != "ENOENT" ) throw err;
      });
      archive.pipe(cipher).pipe(response);
      archive.directory(`${__dirname}/data/${data.path}`,false);
      archive.finalize();
    }
  }
});

app.post("/upload",function(request,response) {
  if ( ! preparations[request.query.cid] || preparations[request.query.cid].type == "upload" ) {
    response.send("error");
  } else {
    var key = auth_keys[request.query.cid];
    var data = preparations[request.query.cid];
    fs.stat(`${__dirname}/data/${data.path}`,function(err,stats) {
      function merge() {
        var decipher = crypto.createDecipheriv("aes-256-cbc",Buffer.from(key),data.iv);
        if ( ! data.isDirectory ) {
          var write = fs.createWriteStream(`${__dirname}/data/${data.path}`);
          write.on("close",function() {
            response.send("ok");
          });
          request.pipe(decipher).pipe(write);
        } else {
          if ( unzipperLocked ) {
            response.send("busy");
            return;
          }
          unzipperLocked = true;
          var write = fs.createWriteStream(`${__dirname}/temp.zip`);
          write.on("error",function(err) {
            throw err;
          })
          write.on("close",function() {
            unzipProc = exec(`yes | unzip ${__dirname}/temp.zip -d ${__dirname}/data/${data.path}`);
            unzipProc.stdout.on("data",Function.prototype);
            unzipProc.stderr.on("data",Function.prototype);
            unzipProc.on("close",function(code) {
              fs.unlink(`${__dirname}/temp.zip`,function(err) {
                if ( err ) throw err;
                  unzipperLocked = false;
                  response.send("ok");
              });
            });
          });
          request.pipe(decipher).pipe(write);
        }
      }
      if ( err ) {
        if ( err.code != "ENOENT" ) throw err;
        else merge();
      } else if ( stats.isDirectory() ) {
        rimraf(`${__dirname}/data/${data.path}`,{
          disableGlob: true
        },function(err) {
          if ( err ) throw err;
          merge();
        });
      } else {
        fs.unlink(`${__dirname}/data/${data.path}`,function(err) {
          if ( err ) throw err;
          merge();
        });
      }
    });
  }
});

app.get("/blank",function(request,response) {
  response.send("hi");
});

app.listen(PORT,function() {
  console.log("Listening on port " + PORT);
  var cg = new Cryptographer();
  console.log(cg.encrypt("siftp-authentication",PASSWORD));
});
