const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const source = fs.readFileSync(process.argv[2], 'utf8');
const expected = 'debb7b0fde4bc70b530cd90a023549e98acc98cdb5586f9e25cff84c3b0e902b';
if (crypto.createHash('sha256').update(source).digest('hex') !== expected) throw Error('Source mismatch');
const captures = [];
const sandbox = {exports: {}, require(name) {
  if (name !== 'child_process') throw Error('Unexpected import');
  return {exec(command) {captures.push(command); return {on() {return this;}};}};
}};
vm.runInNewContext(source, sandbox, {timeout: 1000});
const tests = [
  {id: 'direct-run', input: '; printf TRIAGE_MARKER', expected: 'curl ; printf TRIAGE_MARKER', call(api, input) {api.run(input, () => {});}},
  {id: 'get-url', input: 'https://example.invalid/; printf TRIAGE_MARKER', expected: 'curl --GET https://example.invalid/; printf TRIAGE_MARKER', call(api, input) {api.connect().get(input, {}, () => {});}},
  {id: 'get-option', input: '$(printf TRIAGE_MARKER)', expected: 'curl --GET https://example.invalid/ --header "$(printf TRIAGE_MARKER)"', call(api, input) {api.connect().get('https://example.invalid/', {header: input}, () => {});}}
];
const rows = tests.map(test => {
  test.call(sandbox.exports, test.input);
  const command = captures.pop();
  if (command !== test.expected) throw Error('Unexpected command: ' + test.id);
  return {id: test.id, input: test.input, captured_command: command, matches_expected: true};
});
console.log(JSON.stringify({source_sha256: expected, node_version: process.version, execution: 'child_process.exec replaced with capture stub; no shell, curl, filesystem payload or network request executed', claim: 'Three concrete API inputs reach the command string unchanged. This is a bounded transport witness, not a shell-execution or whole-package safety test.', cases: rows}, null, 2));
