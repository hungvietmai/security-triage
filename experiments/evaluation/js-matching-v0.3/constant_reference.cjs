// Reference labels for "the command string of this call is a constant", independent of Semgrep
// and of the application. Reads JSON {file, calls: [{line, column, endLine, endColumn}]} from stdin, parses the
// file with espree (the ESLint parser, from tools/eslint/node_modules) and prints one verdict
// per call: constant_command, not_constant or unreadable. The file is parsed, never executed.
//
// A name counts as constant only when EVERY write to that name assigns a constant expression.
// For a name declared inside the function that contains the call, the writes inside that
// function count (closures nested in it included); for any other name, every write in the whole
// file counts. A name that is a parameter, is destructured, updated with ++/+= or bound by a
// loop, a catch clause, a function, a class or an import is never constant. The rule is
// name-based on purpose: it is stricter than a dataflow analysis.
const path = require("node:path");
const { createRequire } = require("node:module");
const fs = require("node:fs");

const tools = path.resolve(__dirname, "../../../tools/eslint/package.json");
const espree = createRequire(tools)("espree");

function parse(text) {
  for (const sourceType of ["module", "script", "commonjs"]) {
    try {
      return espree.parse(text, { ecmaVersion: "latest", sourceType, loc: true, range: true });
    } catch {
      // try the next source type
    }
  }
  return null;
}

function walk(node, visit, parent = null) {
  if (!node || typeof node.type !== "string") return;
  visit(node, parent);
  for (const key of Object.keys(node)) {
    if (key === "loc" || key === "range") continue;
    const value = node[key];
    if (Array.isArray(value)) value.forEach((child) => walk(child, visit, node));
    else if (value && typeof value.type === "string") walk(value, visit, node);
  }
}

function patternNames(pattern, into) {
  if (!pattern) return;
  if (pattern.type === "Identifier") into.push(pattern.name);
  else if (pattern.type === "AssignmentPattern") patternNames(pattern.left, into);
  else if (pattern.type === "RestElement") patternNames(pattern.argument, into);
  else if (pattern.type === "ArrayPattern") pattern.elements.forEach((e) => patternNames(e, into));
  else if (pattern.type === "ObjectPattern")
    pattern.properties.forEach((p) => patternNames(p.type === "Property" ? p.value : p, into));
}

function collect(tree) {
  const writes = new Map();
  const tainted = new Set();
  const declared = new Set();
  const taintAll = (pattern) => {
    const names = [];
    patternNames(pattern, names);
    names.forEach((name) => tainted.add(name));
  };
  const record = (name, expression) => {
    if (!writes.has(name)) writes.set(name, []);
    writes.get(name).push(expression);
  };
  walk(tree, (node) => {
    switch (node.type) {
      case "VariableDeclarator":
        if (node.id.type === "Identifier") {
          declared.add(node.id.name);
          if (node.init) record(node.id.name, node.init);
        } else taintAll(node.id);
        break;
      case "AssignmentExpression":
        if (node.left.type === "Identifier") {
          if (node.operator === "=") record(node.left.name, node.right);
          else tainted.add(node.left.name);
        } else if (node.left.type !== "MemberExpression") taintAll(node.left);
        break;
      case "UpdateExpression":
        if (node.argument.type === "Identifier") tainted.add(node.argument.name);
        break;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        if (node.id) tainted.add(node.id.name);
        node.params.forEach(taintAll);
        break;
      case "ClassDeclaration":
        if (node.id) tainted.add(node.id.name);
        break;
      case "CatchClause":
        taintAll(node.param);
        break;
      case "ForInStatement":
      case "ForOfStatement":
        if (node.left.type === "VariableDeclaration")
          node.left.declarations.forEach((d) => taintAll(d.id));
        else taintAll(node.left);
        break;
      case "ImportSpecifier":
      case "ImportDefaultSpecifier":
      case "ImportNamespaceSpecifier":
        tainted.add(node.local.name);
        break;
      default:
    }
  });
  return { writes, tainted, declared };
}

function isConstant(node, scope, seen = new Set()) {
  if (!node) return false;
  switch (node.type) {
    case "Literal":
      return typeof node.value === "string" || typeof node.value === "number";
    case "TemplateLiteral":
      return node.expressions.every((e) => isConstant(e, scope, seen));
    case "BinaryExpression":
      return (
        node.operator === "+" &&
        isConstant(node.left, scope, seen) &&
        isConstant(node.right, scope, seen)
      );
    case "ConditionalExpression":
      return isConstant(node.consequent, scope, seen) && isConstant(node.alternate, scope, seen);
    case "LogicalExpression":
      return isConstant(node.left, scope, seen) && isConstant(node.right, scope, seen);
    case "Identifier": {
      // A name the enclosing function declares or binds is judged by that function alone.
      const local = scope.local;
      const own = local && (local.declared.has(node.name) || local.tainted.has(node.name));
      const used = own ? local : scope;
      const written = used.writes.get(node.name);
      if (used.tainted.has(node.name) || !written || seen.has(node.name)) return false;
      const next = new Set(seen).add(node.name);
      return written.every((expression) => isConstant(expression, scope, next));
    }
    default:
      return false;
  }
}

const job = JSON.parse(fs.readFileSync(0, "utf8"));
const text = fs.readFileSync(job.file, "utf8");
const tree = parse(text);
const out = [];
if (!tree) {
  job.calls.forEach((call) => out.push({ ...call, verdict: "unreadable", command: null }));
} else {
  const fileScope = collect(tree);
  const calls = [];
  const functions = [];
  walk(tree, (node) => {
    if (node.type === "CallExpression") calls.push(node);
    if (/^(FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(node.type))
      functions.push(node);
  });
  const scopeFor = (call) => {
    const around = functions
      .filter((f) => f.range[0] <= call.range[0] && call.range[1] <= f.range[1])
      .sort((a, b) => a.range[1] - a.range[0] - (b.range[1] - b.range[0]));
    // The outermost enclosing function: a closure may change a variable of its parent.
    const outer = around[around.length - 1];
    return { ...fileScope, local: outer ? collect(outer) : null };
  };
  for (const wanted of job.calls) {
    // espree columns are 0-based, the locator's are 1-based.
    // Several calls can start at one place (`require(m).exec(c)`, `exec(c).toString()`): the
    // located call is the one that also ends where the locator says. Columns are 0-based in
    // espree and 1-based in the locator.
    const call = calls.find(
      (c) =>
        c.loc.start.line === wanted.line &&
        c.loc.start.column + 1 === wanted.column &&
        c.loc.end.line === wanted.endLine &&
        c.loc.end.column + 1 === wanted.endColumn,
    );
    if (!call || call.arguments.length === 0) {
      out.push({ ...wanted, verdict: "unreadable", command: null });
      continue;
    }
    const argument = call.arguments[0];
    const lines = text.split(/\r?\n/);
    const command = lines[argument.loc.start.line - 1].slice(
      argument.loc.start.column,
      argument.loc.start.line === argument.loc.end.line ? argument.loc.end.column : undefined,
    );
    out.push({
      ...wanted,
      verdict: isConstant(argument, scopeFor(call)) ? "constant_command" : "not_constant",
      command: command.slice(0, 120),
    });
  }
}
process.stdout.write(JSON.stringify(out));
