const cp = require('child_process');
module.exports = function(input) { const prefix = 'printf '; const suffix = 'fixed'; return cp.exec(prefix + suffix); };
