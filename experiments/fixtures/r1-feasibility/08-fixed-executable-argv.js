const cp = require('child_process');
module.exports = function(input) { return cp.spawn('/usr/bin/printf', ['%s', input], {shell: false}); };
