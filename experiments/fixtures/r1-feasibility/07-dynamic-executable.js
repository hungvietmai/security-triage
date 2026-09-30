const cp = require('child_process');
module.exports = function(input) { return cp.spawn(input, [], {shell: false}); };
