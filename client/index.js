var fs = require("fs");
var functions = require("./functions");

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

function onError(error) {
  console.log(`\u001b[1m\u001b[31;1mError: \u001b[0m${error}`);
}

function handleCommands() {
  var args = process.argv.slice(2);
  fs.readFile(__dirname + "/loginData.json",function(err,data) {
    if ( err ) throw err;
    data = JSON.parse(data.toString());
    var connected = data.mode == "connected";
    if ( ["disconnect","ls","cd","pwd","rm","mkdir","touch","edit","download","upload"].indexOf(args[0]) > -1 && ! connected ) {
      onError("Not connected to any server");
      return;
    }
    if ( args[0] == "connect" ) {
      functions.connectToHost(args[1],function() {
        console.log(`Sucessfully connected to ${args[1]}`);
      });
    } else if ( args[0] == "disconnect" ) {
      functions.disconnectFromHost(function() {
        console.log("Sucessfully disconnected");
      });
    } else if ( args[0] == "ls" ) {
      functions.listFolder(generateTable);
    } else if ( args[0] == "cd" ) {
      functions.changeDirectory(args[1],Function.prototype);
    } else if ( args[0] == "pwd" ) {
      console.log(data.path);
    } else if ( args[0] == "rm" ) {
      functions.removeFile(args[1],function() {
        console.log(`Removed item "${args[1]}"`);
      });
    } else if ( args[0] == "download" ) {
      functions.downloadFile(args[1],function() {
        console.log(`Downloaded "${args[1]}"`);
      });
    } else if ( args[0] == "upload" ) {
      functions.uploadFile(args[1],function() {
        console.log(`Uploaded "${args[1]}"`);
      });
    }
  });
}

handleCommands();
