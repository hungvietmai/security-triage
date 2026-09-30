const cp = require('child_process');
module.exports = function(input) { return cp.spawn('printf', ['fixed'], {shell: true}); };
