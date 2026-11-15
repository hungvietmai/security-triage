// Synthetic test data for constant-command.yaml. Never executed.
// constant_*: the evidence rule must report the call. kept_*: it must not.
const cp = require('child_process');
const { exec } = require('child_process');

function constant_literal() { exec('ls -l'); }
function constant_const_variable() { const cmd = 'ls -l'; exec(cmd); }
function constant_concatenation() { const a = 'git '; const b = 'status'; exec(a + b); }
function constant_template_without_placeholder() { exec(`uname -a`); }
function constant_namespace_call() { cp.exec('whoami', function () {}); }
function constant_one_of_two_literals(flag) { let cmd; if (flag) { cmd = 'ipconfig'; } else { cmd = 'ifconfig'; } exec(cmd); }

function kept_parameter(name) { exec('ls ' + name); }
function kept_template_placeholder(name) { exec(`ls ${name}`); }
function kept_reassigned(input) { let cmd = 'ls'; cmd = input; exec(cmd); }
function kept_conditionally_reassigned(input, flag) { let cmd = 'ls'; if (flag) { cmd = input; } exec(cmd); }
function kept_argv() { const cmd = process.argv[2]; exec(cmd); }
function kept_call_result() { const cmd = build(); exec(cmd); }
function kept_property(options) { exec(options.command); }
function kept_object_field() { const o = { c: 'ls' }; o.c = read(); exec(o.c); }

let shared = 'ls';
function setShared(value) { shared = value; }
function kept_module_variable_changed_elsewhere() { exec(shared); }

var hoisted = 'ls';
function kept_var_changed_in_closure(input) { function change() { hoisted = input; } change(); exec(hoisted); }

function kept_loop(items) { let cmd = 'echo'; for (const item of items) { cmd = cmd + ' ' + item; } exec(cmd); }
function kept_default_parameter(cmd = 'ls') { exec(cmd); }
function kept_ternary(input) { const cmd = input ? input : 'ls'; exec(cmd); }
function kept_spawn_arguments(file) { cp.spawn('tar', ['-xf', file]); }
