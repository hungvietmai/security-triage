/**
 * Safety evidence v0.3, stage 1 — interprocedural, exception-based path guards (CWE-22).
 * Implements SPEC.md steps (a) `Segment` via `uuid.UUID`, (b) `SafeRel` via validators that
 * raise and (c) `Contained` via containment checks (`safe_join` shapes, `resolve` checks).
 *
 * A fact is a must-property of a control-flow node: the value has it on every execution that
 * reaches the node. Facts come only from the closed rules below (validator summaries, the
 * call-site rule, SSA value steps and the listed transformations); anything else yields no fact.
 *
 * An alert is suppressed only when the sink argument itself is proven contained in a trusted
 * root `r` (`contained`, SPEC ProvenContained) and `r` is an allowed root of the sink
 * (`allowedRoot`, SPEC AllowedRoot): declared by a contract (model pack), or, when no contract
 * covers the sink, the root of a containment check applied to that very value (local contract).
 */

import python
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.internal.DataFlowDispatch as DataFlowDispatch

/**
 * Declared sink contract (SPEC §4.0): file operations in `function` (or any function, "*") of
 * `file` (path relative to the source root) may access `root`. Supplied by a model pack.
 */
extensible predicate sinkAllowedRoot(string file, string function, string root);

module IpgGuard {
  /* ------------------------------------------------------------------ trusted roots (T1-T4) */
  /** The value of the only store to module variable `g`: `g = value` at module scope (T1, T2). */
  private Expr moduleConstant(GlobalVariable g) {
    exists(AssignStmt a, Name t |
      a.getScope() instanceof Module and
      t = a.getTarget(0) and
      not exists(a.getTarget(1)) and
      t.defines(g) and
      result = a.getValue() and
      forall(Name n | n.getVariable() = g and not n.getCtx() instanceof Load | n = t)
    ) and
    not exists(Attribute at | at.getName() = g.getId() and not at.getCtx() instanceof Load) and
    not exists(Call c |
      c.getFunc().(Name).getId() = "setattr" and c.getArg(1).(StringLiteral).getText() = g.getId()
    ) and
    not exists(Call c |
      c.getFunc().(Name).getId() = ["globals", "vars", "exec", "eval"] and
      c.getScope().getEnclosingModule() = g.getScope()
    )
  }

  private API::Node osPath(string name) {
    result = API::moduleImport(["os.path", "posixpath"]).getMember(name)
    or
    result = API::moduleImport("os").getMember("path").getMember(name)
  }

  private API::Node pathCtor() {
    result =
      API::moduleImport("pathlib").getMember(["Path", "PurePath", "PosixPath", "PurePosixPath"])
  }

  bindingset[t, s]
  private string joinValue(string t, string s) {
    if s.charAt(0) = "/"
    then result = s
    else
      if t.suffix(t.length() - 1) = "/"
      then result = t + s
      else result = t + "/" + s
  }

  /** `v` is an absolute POSIX path equal to its `normpath` and not `/` (T3, T4). */
  bindingset[v]
  private predicate normalizedAbsolute(string v) {
    v.charAt(0) = "/" and
    v != "/" and
    not exists(int i | i > 0 and v.splitAt("/", i) = ["", ".", ".."])
  }

  /** Static value of a T1 root expression (before the T3/T4 check). */
  private string rootValue(Expr e) {
    result = e.(StringLiteral).getText()
    or
    exists(GlobalVariable g | e.(Name).uses(g) | result = rootValue(moduleConstant(g)))
    or
    exists(Call c | c = e and c = pathCtor().getACall().asExpr() |
      not exists(c.getArg(1)) and
      not exists(c.getANamedArg()) and
      result = rootValue(c.getArg(0))
    )
    or
    exists(Call c | c = e and c = osPath("join").getACall().asExpr() |
      not exists(c.getArg(2)) and
      not exists(c.getANamedArg()) and
      result = joinValue(rootValue(c.getArg(0)), c.getArg(1).(StringLiteral).getText())
    )
    or
    exists(BinaryExpr b | b = e and b.getOp() instanceof Div |
      result = joinValue(rootValue(b.getLeft()), b.getRight().(StringLiteral).getText())
    )
    or
    exists(Call c | c = e and c = osPath(["normpath", "abspath"]).getACall().asExpr() |
      result = rootValue(c.getArg(0)) and normalizedAbsolute(result)
    )
  }

  /** `e` is a trusted root (T1-T4) with static value `result`. */
  string trustedRoot(Expr e) { result = rootValue(e) and normalizedAbsolute(result) }

  /* ------------------------------------------------- resource roots (SPEC_RESOURCE.md, scoped) */
  /** Test code (assumption S-TEST): ignored by the resource-root conditions only. */
  private predicate inTest(AstNode n) {
    exists(File f | f = n.getLocation().getFile() |
      f.getRelativePath().regexpMatch("(.*/)?(test|tests|testing)/.*") or
      f.getBaseName().regexpMatch("test_.*\\.py|.*_test\\.py|conftest\\.py")
    )
  }

  /** Like `moduleConstant`, but stores in test code are not considered (S-TEST). */
  private Expr scopedModuleConstant(GlobalVariable g) {
    exists(AssignStmt a, Name t |
      a.getScope() instanceof Module and
      not inTest(a) and
      t = a.getTarget(0) and
      not exists(a.getTarget(1)) and
      t.defines(g) and
      result = a.getValue() and
      forall(Name n | n.getVariable() = g and not n.getCtx() instanceof Load and not inTest(n) |
        n = t
      )
    ) and
    not exists(Attribute at |
      at.getName() = g.getId() and not at.getCtx() instanceof Load and not inTest(at)
    ) and
    not exists(Call c |
      c.getFunc().(Name).getId() = "setattr" and
      c.getArg(1).(StringLiteral).getText() = g.getId() and
      not inTest(c)
    ) and
    not exists(Call c |
      c.getFunc().(Name).getId() = ["globals", "vars", "exec", "eval"] and
      c.getScope().getEnclosingModule() = g.getScope()
    )
  }

  /** No write to `tempfile.tempdir` or to TMPDIR / TEMP / TMP with a literal key (outside tests). */
  private predicate tempdirIntact() {
    not exists(Attribute at |
      at.getName() = "tempdir" and
      not at.getCtx() instanceof Load and
      not inTest(at) and
      at.getObject() = API::moduleImport("tempfile").getAValueReachableFromSource().asExpr()
    ) and
    not exists(Subscript s |
      s.getIndex().(StringLiteral).getText() = ["TMPDIR", "TEMP", "TMP"] and
      not s.getCtx() instanceof Load and
      not inTest(s)
    ) and
    not exists(Call c |
      c.getFunc().(Attribute).getName() = ["putenv", "setdefault"] and
      c.getArg(0).(StringLiteral).getText() = ["TMPDIR", "TEMP", "TMP"] and
      not inTest(c)
    )
  }

  /** Value of a resource-root expression: a T1 value, or "$TMPDIR/…" built on `tempfile.gettempdir()`. */
  private string resourceValue(Expr e) {
    result = e.(StringLiteral).getText()
    or
    e = API::moduleImport("tempfile").getMember("gettempdir").getACall().asExpr() and
    not exists(e.(Call).getArg(0)) and
    tempdirIntact() and
    result = "$TMPDIR"
    or
    exists(GlobalVariable g | e.(Name).uses(g) | result = resourceValue(scopedModuleConstant(g)))
    or
    exists(Call c | c = e and c = pathCtor().getACall().asExpr() |
      not exists(c.getArg(1)) and
      not exists(c.getANamedArg()) and
      result = resourceValue(c.getArg(0))
    )
    or
    exists(Call c | c = e and c = osPath("join").getACall().asExpr() |
      not exists(c.getArg(2)) and
      not exists(c.getANamedArg()) and
      result = joinValue(resourceValue(c.getArg(0)), c.getArg(1).(StringLiteral).getText())
    )
    or
    exists(BinaryExpr b | b = e and b.getOp() instanceof Div |
      result = joinValue(resourceValue(b.getLeft()), b.getRight().(StringLiteral).getText())
    )
  }

  /** `r` names a dedicated directory: T3/T4 for a static value, or "$TMPDIR" plus at least one own segment. */
  bindingset[r]
  private predicate dedicated(string r) {
    normalizedAbsolute(r)
    or
    r.regexpMatch("\\$TMPDIR(/[^/]+)+") and
    not exists(int i | i > 0 and r.splitAt("/", i) = ["", ".", ".."])
  }

  /** `u` creates exactly the directory it names: `u.mkdir(…)`, `os.makedirs(u, …)`, `os.mkdir(u, …)`. */
  private predicate creation(Name u) {
    exists(Call c | c.getFunc().(Attribute).getObject() = u |
      c.getFunc().(Attribute).getName() = "mkdir"
    )
    or
    exists(Call c |
      c = API::moduleImport("os").getMember(["makedirs", "mkdir"]).getACall().asExpr()
    |
      c.getArg(0) = u
    )
  }

  /** `u` is a store use: creation, existence test, join root, or `dir=` of a tempfile function. */
  private predicate storeUse(Name u) {
    creation(u)
    or
    exists(Call c | c.getFunc().(Attribute).getObject() = u |
      c.getFunc().(Attribute).getName() = ["exists", "is_dir"] and not exists(c.getArg(0))
    )
    or
    exists(Call c | c = osPath(["exists", "isdir"]).getACall().asExpr() | c.getArg(0) = u)
    or
    exists(BinaryExpr b | b.getOp() instanceof Div | b.getLeft() = u)
    or
    exists(Call c | c = osPath("join").getACall().asExpr() |
      c.getArg(0) = u and not exists(c.getArg(2))
    )
    or
    exists(Call c, Keyword k |
      c =
        API::moduleImport("tempfile")
            .getMember(["mkstemp", "mkdtemp", "NamedTemporaryFile", "TemporaryDirectory"])
            .getACall()
            .asExpr() and
      k = c.getAKeyword() and
      k.getArg() = "dir" and
      k.getValue() = u
    )
  }

  /**
   * Module constant `g` is a resource root with value `root` (SPEC_RESOURCE §2, conditions 1-3a/b;
   * outside test code): a server-side, stable, dedicated directory that the program creates and
   * uses only as a store, and that no other module reads.
   */
  predicate resourceRoot(GlobalVariable g, string root) {
    root = resourceValue(scopedModuleConstant(g)) and
    dedicated(root) and
    exists(Name u | u.uses(g) and not inTest(u) | creation(u)) and
    forall(Name u | u.uses(g) and not inTest(u) | storeUse(u)) and
    not exists(Attribute at | at.getName() = g.getId() and not inTest(at)) and
    not exists(ImportMember im | im.getName() = g.getId() and not inTest(im)) and
    not exists(ImportStar s |
      not inTest(s) and
      s.getModule().(ImportExpr).getImportedModuleName() = g.getScope().(Module).getName()
    )
  }

  /* ------------------------------------------------------------------ values and edges */
  /**
   * Call `c` resolves to `f`; argument `k` binds parameter `k + offset` (`offset` 1 when the call
   * binds `self` or `cls`: a normal or class method called on an instance or class).
   */
  private predicate resolved(CallNode c, Function f, int offset) {
    exists(DataFlowDispatch::CallType t | DataFlowDispatch::resolveCall(c, f, t) |
      (
        t instanceof DataFlowDispatch::CallTypePlainFunction or
        t instanceof DataFlowDispatch::CallTypeStaticMethod or
        t instanceof DataFlowDispatch::CallTypeMethodAsPlainFunction
      ) and
      offset = 0
      or
      (
        t instanceof DataFlowDispatch::CallTypeNormalMethod or
        t instanceof DataFlowDispatch::CallTypeClassMethod
      ) and
      offset = 1
    )
  }

  /** The only function call `c` resolves to (overrides or dynamic calls resolve to none). */
  private Function callee(CallNode c, int offset) {
    resolved(c, result, offset) and strictcount(Function f, int o | resolved(c, f, o)) = 1
  }

  /**
   * An SSA variable with a definition node; for a phi, the merge point. Uses of one variable read
   * one value per execution of its definition. Value steps (`v = e`) only use non-phi variables.
   */
  private class Var extends SsaVariable {
    Var() { exists(this.getDefinition()) }
  }

  /** `n` reads the initial value of parameter `k` of its function. */
  private predicate paramUse(ControlFlowNode n, int k) {
    exists(Var v | n = v.getAUse() |
      v.getDefinition().getNode() = v.getDefinition().getScope().(Function).getArg(k)
    )
  }

  /** `inner` is `n` with `normcase(·)` / `str(·)` wrappers removed (identities on POSIX path values). */
  private predicate unwrap(ControlFlowNode n, ControlFlowNode inner) {
    inner = n
    or
    exists(API::CallNode c |
      n = c.asCfgNode() and c = [osPath("normcase"), API::builtin("str")].getACall()
    |
      unwrap(c.getArg(0).asCfgNode(), inner)
    )
  }

  /** `a` and `b` evaluate to the same value: uses of one variable, under the same wrappers. */
  private predicate sameValue(ControlFlowNode a, ControlFlowNode b) {
    exists(Var v, ControlFlowNode ia, ControlFlowNode ib |
      unwrap(a, ia) and unwrap(b, ib) and ia = v.getAUse() and ib = v.getAUse()
    )
  }

  /**
   * The branch edge `cond -> succ` is taken only when test `t` evaluated to `b`. The CFG branches
   * on the condition itself or, for `not t`, on the `not` (so `b` is flipped).
   */
  private predicate branch(ControlFlowNode cond, ControlFlowNode succ, ControlFlowNode t, boolean b) {
    exists(boolean v |
      succ = cond.getATrueSuccessor() and not succ = cond.getAFalseSuccessor() and v = true
      or
      succ = cond.getAFalseSuccessor() and not succ = cond.getATrueSuccessor() and v = false
    |
      t = cond and b = v
      or
      cond.getNode().(UnaryExpr).getOp() instanceof Not and
      t = cond.(UnaryExprNode).getOperand() and
      b = v.booleanNot()
    )
  }

  /**
   * `n` is `abspath(p)` (`kind` "abs") or `realpath(p)` / `Path(p).resolve()` ("real"),
   * possibly under `normcase` (identity on POSIX) or read through a variable.
   */
  private predicate normalized(ControlFlowNode n, string kind, ControlFlowNode p) {
    exists(API::CallNode c | n = c.asCfgNode() and not exists(c.getArg(1)) |
      c = osPath("abspath").getACall() and kind = "abs" and p = c.getArg(0).asCfgNode()
      or
      c = osPath("realpath").getACall() and kind = "real" and p = c.getArg(0).asCfgNode()
      or
      c = [osPath("normcase"), API::builtin("str")].getACall() and
      normalized(c.getArg(0).asCfgNode(), kind, p)
    )
    or
    // x.resolve(); for Path(p).resolve() the resolved value is that of p
    exists(CallNode r, ControlFlowNode recv |
      n = r and
      r.getFunction().(AttrNode).getName() = "resolve" and
      not exists(r.getArg(0)) and
      recv = r.getFunction().(AttrNode).getObject() and
      kind = "real"
    |
      exists(API::CallNode ctor | recv = ctor.asCfgNode() and ctor = pathCtor().getACall() |
        not exists(ctor.getArg(1)) and p = ctor.getArg(0).asCfgNode()
      )
      or
      not recv = pathCtor().getACall().asCfgNode() and p = recv
    )
    or
    exists(Var v | n = v.getAUse() and not exists(v.getAPhiInput()) |
      normalized(v.getDefinition().(DefinitionNode).getValue(), kind, p)
    )
  }

  /** Root `r` (normalized with `kind`) as "p<k>" (parameter k) or "=<value>" (trusted root). */
  private string rootRef(ControlFlowNode r, string kind) {
    exists(ControlFlowNode p | normalized(r, kind, p) |
      exists(int k | paramUse(p, k) | result = "p" + k)
      or
      result = "=" + trustedRoot(p.getNode())
    )
  }

  /**
   * Root `r` as a normalized root (`rootRef`) or as is: a parameter or a trusted root, possibly
   * under `str()`. A normalized value can start with `r + sep`, or equal `r`, only if `r` itself
   * is normalized, so a raw root is enough for those tests (not for `dirname(r) == r`).
   */
  private string anyRootRef(ControlFlowNode r, string kind) {
    result = rootRef(r, kind)
    or
    kind = ["abs", "real"] and
    (
      exists(int k | paramUse(r, k) | result = "p" + k)
      or
      result = "=" + trustedRoot(r.getNode())
      or
      exists(API::CallNode c | r = c.asCfgNode() and c = API::builtin("str").getACall() |
        result = anyRootRef(c.getArg(0).asCfgNode(), kind)
      )
    )
  }

  /** `n` is `r + os.sep` or `r + "/"`, possibly under `normcase` / `str`. */
  private predicate plusSep(ControlFlowNode n, ControlFlowNode r) {
    exists(BinaryExprNode b |
      unwrap(n, b) and b.getNode().getOp() instanceof Add and r = b.getLeft()
    |
      b.getRight() =
        [API::moduleImport("os").getMember("sep"), osPath("sep")]
            .getAValueReachableFromSource()
            .asCfgNode()
      or
      b.getRight().getNode().(StringLiteral).getText() = "/"
    )
  }

  /**
   * The edge `cond -> succ` is taken only when value `x` lies in the root `ref`, both normalized
   * with `abspath` (`basis` "lex") or both resolved (`basis` "can").
   */
  private predicate containEdge(
    ControlFlowNode cond, ControlFlowNode succ, ControlFlowNode x, string basis, string ref
  ) {
    exists(ControlFlowNode t, string kind |
      kind = "abs" and basis = "lex"
      or
      kind = "real" and basis = "can"
    |
      // x.startswith(r + os.sep)
      branch(cond, succ, t, true) and
      t.(CallNode).getFunction().(AttrNode).getName() = "startswith" and
      x = t.(CallNode).getFunction().(AttrNode).getObject() and
      not exists(t.(CallNode).getArg(1)) and
      normalized(x, kind, _) and
      exists(ControlFlowNode r | plusSep(t.(CallNode).getArg(0), r) | ref = anyRootRef(r, kind))
      or
      // x.is_relative_to(r) on resolved paths
      kind = "real" and
      branch(cond, succ, t, true) and
      t.(CallNode).getFunction().(AttrNode).getName() = "is_relative_to" and
      x = t.(CallNode).getFunction().(AttrNode).getObject() and
      not exists(t.(CallNode).getArg(1)) and
      normalized(x, kind, _) and
      ref = anyRootRef(t.(CallNode).getArg(0), kind)
      or
      // x == r, or x != r false
      kind = "abs" and
      exists(ControlFlowNode l, ControlFlowNode rr, Cmpop op, boolean b |
        t.(CompareNode).operands(l, op, rr) and
        branch(cond, succ, t, b) and
        (
          op instanceof Eq and b = true
          or
          op instanceof NotEq and b = false
        )
      |
        x = l and normalized(x, kind, _) and ref = anyRootRef(rr, kind)
        or
        x = rr and normalized(x, kind, _) and ref = anyRootRef(l, kind)
      )
    )
  }

  /** The edge is taken only when `dirname(r) == r`: root `ref` is "/", so every absolute value lies in it. */
  private predicate fsRootEdge(ControlFlowNode cond, ControlFlowNode succ, string ref) {
    exists(
      ControlFlowNode t, ControlFlowNode l, ControlFlowNode rr, Cmpop op, boolean b, API::CallNode d
    |
      t.(CompareNode).operands(l, op, rr) and
      branch(cond, succ, t, b) and
      (
        op instanceof Eq and b = true
        or
        op instanceof NotEq and b = false
      ) and
      d = osPath("dirname").getACall() and
      l = d.asCfgNode() and
      sameValue(d.getArg(0).asCfgNode(), rr) and
      ref = rootRef(rr, "abs")
    )
  }

  /**
   * The branch edge `cond -> succ` is taken only when atom `a` holds for the value of `subj`:
   * "relative", "nodotdot", or "c:<basis>:<root ref>" (containment).
   */
  private predicate atomEdge(
    ControlFlowNode cond, ControlFlowNode succ, ControlFlowNode subj, string a
  ) {
    // os.path.isabs(s) false
    exists(API::CallNode c | c = osPath("isabs").getACall() |
      branch(cond, succ, c.asCfgNode(), false) and subj = c.getArg(0).asCfgNode() and a = "relative"
    )
    or
    // Path(s).is_absolute() false, POSIX flavours only (PureWindowsPath("/x") is not absolute)
    exists(CallNode t, API::CallNode ctor |
      branch(cond, succ, t, false) and
      t.getFunction().(AttrNode).getName() = "is_absolute" and
      not exists(t.getArg(0)) and
      t.getFunction().(AttrNode).getObject() = ctor.asCfgNode() and
      ctor = pathCtor().getACall() and
      not exists(ctor.getArg(1)) and
      subj = ctor.getArg(0).asCfgNode() and
      a = "relative"
    )
    or
    // s.startswith("/") false
    exists(CallNode t |
      branch(cond, succ, t, false) and
      t.getFunction().(AttrNode).getName() = "startswith" and
      t.getArg(0).getNode().(StringLiteral).getText() = "/" and
      not exists(t.getArg(1)) and
      subj = t.getFunction().(AttrNode).getObject() and
      a = "relative"
    )
    or
    // ".." in s.split("/") false, or ".." in s false
    exists(ControlFlowNode t, ControlFlowNode left, ControlFlowNode right, Cmpop op, boolean b |
      branch(cond, succ, t, b) and
      t.(CompareNode).operands(left, op, right) and
      left.getNode().(StringLiteral).getText() = ".." and
      (
        op instanceof In and b = false
        or
        op instanceof NotIn and b = true
      ) and
      a = "nodotdot"
    |
      subj = right
      or
      right.(CallNode).getFunction().(AttrNode).getName() = "split" and
      right.(CallNode).getArg(0).getNode().(StringLiteral).getText() = "/" and
      not exists(right.(CallNode).getArg(1)) and
      subj = right.(CallNode).getFunction().(AttrNode).getObject()
    )
    or
    // the fact holds for the tested value x, also read without its normcase / str wrappers
    exists(ControlFlowNode x, string basis, string ref |
      containEdge(cond, succ, x, basis, ref) and unwrap(x, subj) and a = "c:" + basis + ":" + ref
    )
    or
    // a resolved containment check on x = resolve(p) also holds for p itself
    exists(ControlFlowNode x, string ref |
      containEdge(cond, succ, x, "can", ref) and normalized(x, "real", subj) and a = "c:can:" + ref
    )
  }

  /** Branch edges each of which establishes atom `a` for the value of `v`. */
  private predicate groupEdge(Var v, string a, ControlFlowNode cond, ControlFlowNode succ) {
    exists(ControlFlowNode subj | atomEdge(cond, succ, subj, a) and subj = v.getAUse())
    or
    exists(string ref | fsRootEdge(cond, succ, ref) and a = "c:lex:" + ref |
      normalized(v.getAUse(), "abs", _) and v.getDefinition().getScope() = cond.getScope()
    )
  }

  private predicate grouped(Var v, string a) { groupEdge(v, a, _, _) }

  /** `n` is reachable from the definition of `v` without any edge of the group (and without a new value). */
  private predicate reachAvoidingGroup(Var v, string a, ControlFlowNode n) {
    grouped(v, a) and
    n = v.getDefinition().getASuccessor() and
    not groupEdge(v, a, v.getDefinition(), n)
    or
    exists(ControlFlowNode m | reachAvoidingGroup(v, a, m) |
      n = m.getASuccessor() and not groupEdge(v, a, m, n) and n != v.getDefinition()
    )
  }

  /** A call whose normal completion may establish an atom for argument `subj` (syntactic). */
  private predicate callCandidate(ControlFlowNode cond, ControlFlowNode subj) {
    exists(API::CallNode c | c = API::moduleImport("uuid").getMember("UUID").getACall() |
      cond = c.asCfgNode() and subj = c.getArg(0).asCfgNode()
    )
    or
    exists(callee(cond, _)) and subj = cond.(CallNode).getArg(_)
  }

  /** `n` is reachable from the definition of `v` without the normal completion of call `cond`. */
  private predicate reachAvoidingCall(Var v, ControlFlowNode cond, ControlFlowNode n) {
    callCandidate(cond, v.getAUse()) and
    n = v.getDefinition().getASuccessor()
    or
    exists(ControlFlowNode m | reachAvoidingCall(v, cond, m) |
      n = m.getASuccessor() and
      not (m = cond and n = cond.getANormalSuccessor()) and
      n != v.getDefinition()
    )
  }

  /** Every `return` of `f` returns a use of `w`, and `f` cannot fall off its end. */
  private predicate returnsOnly(Function f, SsaVariable w) {
    exists(Return r | r.getScope() = f) and
    forall(Return r | r.getScope() = f | w.getAUse().getNode() = r.getValue()) and
    not exists(f.getFallthroughNode())
  }

  /* ------------------------------------------------------------------ validator summaries */
  /** `v` is the target of `f`'s summary: parameter `i` (its initial value) or, `i = -1`, the returned value. */
  private predicate targetVar(Function f, int i, Var v) {
    v.getDefinition().getNode() = f.getArg(i)
    or
    i = -1 and returnsOnly(f, v) and v.getDefinition().getScope() = f
  }

  /**
   * Summary of validator `f` (SPEC §4.1): a normal return guarantees atom `a` for parameter `i`
   * or, with `i = -1`, for the returned value. A root reference "p<k>" names parameter k.
   */
  predicate summary(Function f, int i, string a) {
    exists(Var v | targetVar(f, i, v) |
      grouped(v, a) and
      not exists(ControlFlowNode x | x = f.getANormalExit() | reachAvoidingGroup(v, a, x))
      or
      exists(ControlFlowNode cond | callAtom(cond, v.getAUse(), a) |
        not exists(ControlFlowNode x | x = f.getANormalExit() | reachAvoidingCall(v, cond, x))
      )
    )
  }

  /**
   * Atom `a` that the callee's summary for its parameter `i` (`-1`: the returned value) gives at
   * call `c`; a root reference to a parameter becomes the root of the matching argument.
   */
  private predicate atCall(ControlFlowNode c, int i, string a) {
    exists(string a0, int off | summary(callee(c, off), i, a0) |
      not a0.regexpMatch("c:[a-z]+:p[0-9]+") and a = a0
      or
      exists(string pre, ControlFlowNode arg |
        pre = a0.regexpCapture("(c:[a-z]+:)p([0-9]+)", 1) and
        arg = c.(CallNode).getArg(a0.regexpCapture("(c:[a-z]+:)p([0-9]+)", 2).toInt() - off)
      |
        a = pre + "=" + trustedRoot(arg.getNode())
        or
        exists(int m | paramUse(arg, m) | a = pre + "p" + m)
      )
    )
  }

  /** Call `cond` completes normally only when atom `a` holds for argument `subj`. */
  private predicate callAtom(ControlFlowNode cond, ControlFlowNode subj, string a) {
    exists(API::CallNode c | c = API::moduleImport("uuid").getMember("UUID").getACall() |
      cond = c.asCfgNode() and
      subj = c.getArg(0).asCfgNode() and
      not exists(c.getArg(1)) and
      not exists(c.getArgByName(_)) and
      a = "segment"
    )
    or
    exists(int k, int off |
      subj = cond.(CallNode).getArg(k) and exists(callee(cond, off)) and atCall(cond, k + off, a)
    )
  }

  /* ------------------------------------------------------------------ facts on values */
  /** Atom `a` holds at `n`: a call result (return summary) or a use after a passed check (§4.2). */
  private predicate atomAt(ControlFlowNode n, string a) {
    atCall(n, -1, a)
    or
    exists(Var v, ControlFlowNode cond |
      callAtom(cond, v.getAUse(), a) and n = v.getAUse() and not reachAvoidingCall(v, cond, n)
    )
    or
    exists(Var v | grouped(v, a) and n = v.getAUse() and not reachAvoidingGroup(v, a, n))
  }

  /** The only control-flow node of `e` (expressions copied by `finally` get no facts). */
  private ControlFlowNode only(Expr e) { result = unique(ControlFlowNode c | c.getNode() = e) }

  /** A string literal without a separator. */
  private predicate separatorFree(StringLiteral l) { not exists(l.getText().indexOf(["/", "\\"])) }

  /** `s` interpolates exactly one plain value `v`; every literal part is separator-free. */
  private predicate oneSlotFstring(Fstring s, Expr v) {
    (
      exists(FormattedValue fv | fv = s.getAValue() |
        v = fv.getValue() and not exists(fv.getConversion()) and not exists(fv.getFormatSpec())
      )
      or
      v = s.getAValue() and not v instanceof StringLiteral and not v instanceof FormattedValue
    ) and
    strictcount(Expr p | p = s.getAValue() and not p instanceof StringLiteral) = 1 and
    forall(StringLiteral l | l = s.getAValue() | separatorFree(l))
  }

  /** `n` carries `f`: "Segment" or "SafeRel" (SPEC §3, closed list of §4.3). */
  predicate fact(ControlFlowNode n, string f) {
    f = "Segment" and atomAt(n, "segment")
    or
    f = "SafeRel" and atomAt(n, "relative") and atomAt(n, "nodotdot")
    or
    f = "SafeRel" and fact(n, "Segment")
    or
    // SSA value step: a use of a non-phi variable assigned a value carrying the fact
    exists(Var v | n = v.getAUse() and not exists(v.getAPhiInput()) |
      fact(v.getDefinition().(DefinitionNode).getValue(), f)
    )
    or
    // Segment + separator-free literals: f"{v}.json", v + ".json", "x" + v
    f = "Segment" and
    (
      exists(Fstring s, Expr v | n = only(s) and oneSlotFstring(s, v) | fact(only(v), "Segment"))
      or
      exists(BinaryExprNode b | n = b and b.getNode().getOp() instanceof Add |
        fact(b.getLeft(), "Segment") and separatorFree(b.getRight().getNode())
        or
        fact(b.getRight(), "Segment") and separatorFree(b.getLeft().getNode())
      )
    )
    or
    // dirname / basename / normpath of SafeRel
    f = "SafeRel" and
    exists(API::CallNode c | c = osPath(["dirname", "basename", "normpath"]).getACall() |
      n = c.asCfgNode() and not exists(c.getArg(1)) and fact(c.getArg(0).asCfgNode(), "SafeRel")
    )
  }

  /** `n` is `os.path.join(root, rel)` (exactly two positional arguments) or `root / rel`. */
  private predicate joinParts(ControlFlowNode n, ControlFlowNode root, ControlFlowNode rel) {
    exists(API::CallNode c | c = osPath("join").getACall() |
      n = c.asCfgNode() and
      root = c.getArg(0).asCfgNode() and
      rel = c.getArg(1).asCfgNode() and
      not exists(c.getArg(2)) and
      not exists(c.getArgByName(_))
    )
    or
    n.(BinaryExprNode).getNode().getOp() instanceof Div and
    root = n.(BinaryExprNode).getLeft() and
    rel = n.(BinaryExprNode).getRight()
  }

  /** The only `return` of `f` (which cannot fall off its end) returns a contained value. */
  private predicate returnContained(Function f, string root, string basis, string via) {
    exists(Return r |
      r.getScope() = f and
      strictcount(Return x | x.getScope() = f) = 1 and
      not exists(f.getFallthroughNode())
    |
      contained(only(r.getValue()), root, basis, via)
    )
  }

  /**
   * ProvenContained: the value at `n` lies in trusted root `root`, on `basis` "lexical (A-SYM)" or
   * "canonical"; `via` is "check" (a containment check with that root) or "join" (a SafeRel or
   * Segment value joined under the root).
   */
  predicate contained(ControlFlowNode n, string root, string basis, string via) {
    exists(string a, string b | atomAt(n, a) |
      b = a.regexpCapture("c:([a-z]+):=(.*)", 1) and
      root = a.regexpCapture("c:([a-z]+):=(.*)", 2) and
      (
        b = "lex" and basis = "lexical (A-SYM)"
        or
        b = "can" and basis = "canonical"
      ) and
      via = "check"
    )
    or
    // os.path.join(B, v), B / v: B a trusted root and v SafeRel ("join"), or B a resource root
    // read directly and v a Segment ("join-segment", SPEC_RESOURCE condition 4)
    basis = "lexical (A-SYM)" and
    exists(ControlFlowNode rootNode, ControlFlowNode rel | joinParts(n, rootNode, rel) |
      via = "join" and root = trustedRoot(rootNode.getNode()) and fact(rel, "SafeRel")
      or
      via = "join-segment" and
      fact(rel, "Segment") and
      exists(GlobalVariable g | rootNode.getNode().(Name).uses(g) | resourceRoot(g, root))
    )
    or
    // a call to a function whose only return is contained (closed-list summary, SPEC 4.3 (b))
    returnContained(callee(n, _), root, basis, via)
    or
    exists(Var v | n = v.getAUse() and not exists(v.getAPhiInput()) |
      contained(v.getDefinition().(DefinitionNode).getValue(), root, basis, via)
    )
    or
    // kept by Path(), str(), os.fspath(); abspath() and normpath() keep lexical containment only
    // (they collapse ".." without following links, which can change a resolved path's target)
    exists(API::CallNode c |
      c = [pathCtor(), API::builtin("str"), API::moduleImport("os").getMember("fspath")].getACall()
      or
      c = osPath(["abspath", "normpath"]).getACall() and basis = "lexical (A-SYM)"
    |
      n = c.asCfgNode() and
      not exists(c.getArg(1)) and
      contained(c.getArg(0).asCfgNode(), root, basis, via)
    )
  }

  /**
   * Diagnostics only: call `c` reaches a validator whose summary atom `a0` checks containment in
   * its parameter root, but the argument `rootArg` is not a trusted root (so no fact is derived
   * at the sink); `kind` is "parameter" when the argument is a parameter of the caller.
   */
  predicate untrustedRootCall(ControlFlowNode c, string a0, Expr rootArg, string kind) {
    exists(ControlFlowNode arg, int off |
      summary(callee(c, off), _, a0) and
      arg = c.(CallNode).getArg(a0.regexpCapture("c:[a-z]+:p([0-9]+)", 1).toInt() - off) and
      rootArg = arg.getNode() and
      not exists(trustedRoot(rootArg)) and
      if paramUse(arg, _) then kind = "parameter" else kind = "other"
    )
  }

  private string locStr(AstNode n) {
    result = n.getLocation().getFile().getRelativePath() + ":" + n.getLocation().getStartLine()
  }

  /**
   * Diagnostics only: module constant `g` names a dedicated directory `root` (resource-root
   * conditions 1-2 hold); `detail` says whether conditions 3a/3b hold, with the evidence.
   */
  predicate resourceDiagnostic(GlobalVariable g, string root, string detail) {
    root = resourceValue(scopedModuleConstant(g)) and
    dedicated(root) and
    (
      resourceRoot(g, root) and
      detail =
        "resource root; created at " +
          concat(Name u | u.uses(g) and not inTest(u) and creation(u) | locStr(u), ", ")
      or
      not exists(Name u | u.uses(g) and not inTest(u) | creation(u)) and
      detail = "never created"
      or
      exists(Name u | u.uses(g) and not inTest(u) and not storeUse(u) |
        detail = "non-store use at " + locStr(u)
      )
      or
      exists(Attribute at | at.getName() = g.getId() and not inTest(at) |
        detail = "read by another module at " + locStr(at)
      )
      or
      exists(ImportMember im | im.getName() = g.getId() and not inTest(im) |
        detail = "imported at " + locStr(im)
      )
    )
  }

  /* ------------------------------------------------------------------ sink decision */
  private predicate declared(DataFlow::Node sink, string root) {
    exists(string file, string function | sinkAllowedRoot(file, function, root) |
      sink.getLocation().getFile().getRelativePath() = file and
      (function = "*" or sink.getScope().(Function).getName() = function)
    )
  }

  /**
   * AllowedRoot (SPEC §4.0, SPEC_RESOURCE.md): `root` is declared for `sink` by a contract; or no
   * contract covers `sink` and `root` is the root of a containment check on the sink value
   * itself (local contract), or a resource root the sink value is a flat entry of (resource
   * contract). A declared contract is authoritative: no other source adds to it.
   */
  predicate allowedRoot(DataFlow::Node sink, string root, string source) {
    declared(sink, root) and source = "declared"
    or
    not declared(sink, _) and
    (
      contained(sink.asCfgNode(), root, _, "check") and source = "local"
      or
      contained(sink.asCfgNode(), root, _, "join-segment") and
      resourceRoot(_, root) and
      source = "resource"
    )
  }

  /** Evidence level of a contract source (SPEC_RESOURCE §1): "proved" or "scoped". */
  bindingset[source]
  string level(string source) {
    source = ["declared", "local"] and result = "proved"
    or
    source = "resource" and result = "scoped"
  }

  /** The alert at `sink` is suppressed: ProvenContained(sink value, root) and AllowedRoot(sink, root). */
  predicate suppressedSink(DataFlow::Node sink, string root, string basis, string source) {
    exists(string via | contained(sink.asCfgNode(), root, basis, via) |
      allowedRoot(sink, root, source) and
      (
        source = "declared"
        or
        source = "local" and via = "check"
        or
        source = "resource" and via = "join-segment"
      )
    )
  }
}
