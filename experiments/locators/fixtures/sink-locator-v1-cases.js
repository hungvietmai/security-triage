// Synthetic test data for sink-locator-v1-javascript.yaml. Never executed.
// A line ending in "// locate" must be reported as a child_process call;
// a line ending in "// skip" must not.
const cp = require('child_process');
const nodeCp = require('node:child_process');
const run = require('child_process').exec;
const twoStep = cp.exec;
const twoStepSpawn = nodeCp.spawn;
const { execFile, execSync } = require('child_process');
const util = require('util');
const execAsync = util.promisify(require('child_process').exec);
const execFileAsync = util.promisify(cp.execFile);
const { execSync: renamedSync } = require('child_process');
const mine = require('./my-exec');
const other = require('./process-helpers');

function namespace(cmd) { cp.exec(cmd); } // locate
function nodePrefix(cmd) { nodeCp.execSync(cmd); } // locate
function directAlias(cmd) { run(cmd); } // locate
function twoStepAlias(cmd) { twoStep(cmd); } // locate
function twoStepAliasSpawn(file) { twoStepSpawn('tar', ['-xf', file]); } // locate
function destructured(file) { execFile('tar', ['-xf', file]); } // locate
function destructuredSync(cmd) { execSync(cmd); } // locate
function promisified(cmd) { return execAsync(cmd); } // locate
function promisifiedNamespace(file) { return execFileAsync('ls', [file]); } // locate
function inlineRequire(cmd) { require('child_process').exec(cmd); } // locate
function renamedDestructured(cmd) { return renamedSync(cmd, { cwd: '.' }); } // locate
function adjacentFirst(a) { twoStep('pkill -f ' + a); } // locate
function adjacentSecond(b) { twoStep('taskkill /IM ' + b); } // locate

function notChildProcess(sql) { mine(sql); } // skip
function otherNamespace(cmd) { other.exec(cmd); } // skip
function regexExec(text) { return /a+/.exec(text); } // skip
function databaseExec(db, sql) { return db.exec(sql); } // skip
function localFunction(cmd) { function exec(value) { return value; } return localHelper(cmd); } // skip
function unknownMethod(cmd) { cp.kill(cmd); } // skip
