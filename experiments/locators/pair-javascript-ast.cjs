// Parse source as data. This helper never loads or executes a benchmark module.
const fs = require("node:fs");
const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const source = input.source;
const tree = parser.parse(source, {
  sourceType: "unambiguous",
  plugins: ["jsx"],
  errorRecovery: false,
});
const sinks = [];
const methods = new Set([
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "spawn",
  "spawnSync",
  "fork",
]);
function required(node, scope) {
  if (
    node?.type !== "CallExpression" ||
    node.callee.type !== "Identifier" ||
    node.callee.name !== "require" ||
    scope.getBinding("require") ||
    node.arguments.length !== 1 ||
    node.arguments[0].type !== "StringLiteral"
  )
    return null;
  const module = node.arguments[0].value.replace(/^node:/, "");
  return ["child_process", "shelljs"].includes(module) ? module : null;
}
function member(node) {
  if (node?.type !== "MemberExpression") return null;
  return !node.computed && node.property.type === "Identifier"
    ? node.property.name
    : node.computed && node.property.type === "StringLiteral"
      ? node.property.value
      : null;
}
function namespace(node, scope) {
  const immediate = required(node, scope);
  if (immediate) return immediate;
  if (node?.type !== "Identifier") return null;
  const binding = scope.getBinding(node.name);
  if (!binding || !binding.constant) return null;
  const declaration = binding.path.node;
  if (
    ["ImportDefaultSpecifier", "ImportNamespaceSpecifier"].includes(
      declaration.type,
    )
  ) {
    const module = binding.path.parent.source.value.replace(/^node:/, "");
    return ["child_process", "shelljs"].includes(module) ? module : null;
  }
  if (
    declaration.type === "VariableDeclarator" &&
    declaration.id.type === "Identifier"
  )
    return required(declaration.init, binding.path.scope);
  return null;
}
function canonical(node, scope) {
  const method = member(node);
  if (method) {
    const module = namespace(node.object, scope);
    return module ? `${module}.${method}` : null;
  }
  if (node?.type !== "Identifier") return null;
  const binding = scope.getBinding(node.name);
  if (!binding || !binding.constant) return null;
  const declaration = binding.path.node;
  if (declaration.type === "ImportSpecifier") {
    const module = binding.path.parent.source.value.replace(/^node:/, "");
    return ["child_process", "shelljs"].includes(module)
      ? `${module}.${declaration.imported.name ?? declaration.imported.value}`
      : null;
  }
  if (declaration.type !== "VariableDeclarator") return null;
  if (declaration.id.type === "Identifier" && member(declaration.init)) {
    const module = namespace(declaration.init.object, binding.path.scope);
    return module ? `${module}.${member(declaration.init)}` : null;
  }
  const module = required(declaration.init, binding.path.scope);
  if (module && declaration.id.type === "ObjectPattern") {
    const property = declaration.id.properties.find(
      (property) =>
        property.type === "ObjectProperty" &&
        property.value.type === "Identifier" &&
        property.value.name === node.name,
    );
    if (property) return `${module}.${property.key.name ?? property.key.value}`;
  }
  return null;
}
function span(node) {
  // Babel columns are UTF-16; persisted sink spans use one-based UTF-8 byte columns.
  const point = (offset) => {
    const prefix = source.slice(0, offset);
    const last = prefix.lastIndexOf("\n");
    return [
      prefix.split("\n").length,
      Buffer.byteLength(prefix.slice(last + 1), "utf8") + 1,
    ];
  };
  const start = point(node.start),
    end = point(node.end);
  return {
    startLine: start[0],
    startColumn: start[1],
    endLine: end[0],
    endColumn: end[1],
  };
}
traverse(tree, {
  CallExpression(call) {
    const node = call.node;
    const kind = canonical(node.callee, call.scope);
    if (
      !kind ||
      !(
        (kind.startsWith("child_process.") &&
          methods.has(kind.split(".")[1])) ||
        kind === "shelljs.exec"
      )
    )
      return;
    sinks.push({
      path: input.path,
      span: span(node),
      callee_span: span(node.callee),
      callee: source.slice(node.callee.start, node.callee.end),
      sink_kind: kind,
      args: node.arguments.map((argument, position) => ({
        position,
        keyword: null,
        span: span(argument),
        text: source.slice(argument.start, argument.end),
        value_kind:
          argument.type === "BooleanLiteral"
            ? "bool"
            : argument.type === "StringLiteral"
              ? "string"
              : argument.type === "Identifier"
                ? "name"
                : argument.type === "ObjectExpression"
                  ? "dict"
                  : argument.type === "ArrayExpression"
                    ? "list"
                    : "expression",
        literal_bool:
          argument.type === "BooleanLiteral" ? argument.value : null,
      })),
    });
  },
});
process.stdout.write(
  JSON.stringify({
    locator: "pair-javascript-ast-v0",
    parser_version: require("@babel/parser/package.json").version,
    traverse_version: require("@babel/traverse/package.json").version,
    sinks,
  }),
);
