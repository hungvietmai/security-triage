const cp = require('child_process');
module.exports = function(input) { return cp.spawn('/bin/sh', ['-c', input], {shell: false}); };
