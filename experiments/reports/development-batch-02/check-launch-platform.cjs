// Bounded branch witness on checksum-pinned source. Every process call is mocked.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync(process.argv[2], 'utf8');
const sourceHash = crypto.createHash('sha256').update(source).digest('hex');
if (sourceHash !== '67aaecfb57e82054dbd1c4ce08b859f09d93ee926d50ffbd2d3a35dc53ab74ff') {
  throw Error('Source checksum mismatch');
}
const results = ['linux', 'win32'].map(platform => {
  const calls = [];
  const child = {on() {return this;}, kill() {throw Error('Unexpected kill');}};
  const modules = {
    fs: {existsSync: () => true},
    os: {release: () => 'controlled-test'},
    path: platform === 'win32' ? path.win32 : path.posix,
    picocolors: {red: value => value},
    child_process: {
      exec(...args) {calls.push({method: 'exec', args}); return child;},
      spawn(...args) {calls.push({method: 'spawn', args}); return child;}
    },
    './guess': () => ['code'],
    './get-args': () => {throw Error('Unexpected position parser');}
  };
  const sandbox = {
    module: {exports: {}}, process: Object.freeze({platform}),
    console: {log() {throw Error('Unexpected error callback');}},
    require(name) {
      if (!Object.hasOwn(modules, name)) throw Error('Unexpected module: ' + name);
      return modules[name];
    }
  };
  vm.runInNewContext(source, sandbox, {timeout: 1000});
  sandbox.module.exports(platform === 'win32' ? 'C:\\review\\sample.js' : '/review/sample.js', 'code');
  const expected = platform === 'win32' ? 'exec' : 'spawn';
  if (calls.length !== 1 || calls[0].method !== expected) throw Error('Wrong branch');
  return {modeled_platform: platform, expected_method: expected, calls};
});
console.log(JSON.stringify({
  source_sha256: sourceHash, node_version: process.version,
  scope: 'Two mocked platform branches; source guard is the scope evidence. This is not native Windows execution or an exploit/sanitizer test.',
  substitutions: ['fs.existsSync always true', 'guessEditor returns trusted code', 'process.platform mocked', 'exec and spawn capture only'],
  results
}, null, 2));
