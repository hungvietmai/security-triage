const cp = require('child_process');
module.exports = function(input) { return cp.exec('printf ' + input); };
