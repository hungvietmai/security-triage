// Development-only synthetic controls; never execute these functions.
var cp = require('child_process');
var exec = require('child_process').exec;
var execSync = require('child_process').execSync;

exports.namespace = function(command) {
  cp.exec("curl " + command);
};
exports.direct = function(command) {
  exec("curl " + command);
};
exports.directSync = function(command) {
  execSync("curl " + command);
};
exports.fixed = function(command) {
  exec("printf hello");
};
exports.unused = function(command) {
  return "curl " + command;
};
