/**
 * Safety evidence for CodeQL Python taint queries — development version 0.1.
 *
 * Each predicate describes a data-flow node whose value is either provably not attacker
 * controlled, or has passed a check that the decision layer treats as safety evidence.
 * Mechanisms (the `mech` argument of `barrier`):
 *
 * - `constbranch`: code that never runs because a branch condition (if / if-expression /
 *   match) evaluates to a constant. Values: bounded integer arithmetic over literals and
 *   single-assignment locals, string literals, constant indexing into constant strings.
 * - `collection`: a read of a local list/dict element whose content is a literal, computed by
 *   simulating straight-line `append` / `pop` / keyed stores in one statement list.
 * - `guard`: a check that rejects dangerous input (`'..' in x`, `"'" in x`), a resolved path
 *   checked with `startswith`, or quote replacement before XPath construction.
 * - `route`: a segment of `request.path` that is fixed by the literal route of the handler.
 * - `header`: a value placed in the header/status position of a Flask response tuple, which is
 *   not part of the response body.
 *
 * No benchmark test IDs, file names or specific numeric constants appear here.
 */

import python
import semmle.python.dataflow.new.DataFlow

module SafetyEvidence {
  /* ---------------------------------------------------------------- constants */
  /** The value expression of the only assignment to the local read by `read`. */
  Expr singleDefinition(Name read) {
    exists(FastLocalVariable v, AssignStmt a, Name t |
      read.uses(v) and
      not v.isParameter() and
      not v.escapes() and
      not exists(Name d | d.deletes(v)) and
      t = a.getTarget(0) and
      not exists(a.getTarget(1)) and
      t.defines(v) and
      forall(Name store | store = v.getAStore() | store = t) and
      a.getScope() = read.getScope() and
      result = a.getValue() and
      exists(ControlFlowNode use | use.getNode() = read) and
      forall(ControlFlowNode use | use.getNode() = read |
        exists(ControlFlowNode def | def.getNode() = t and def.dominates(use))
      )
    )
  }

  /** Bounded integer value of `e` (every intermediate in [-10000, 10000]). */
  int intValue(Expr e) {
    result in [-10000 .. 10000] and
    (
      result = e.(IntegerLiteral).getValue()
      or
      result = intValue(singleDefinition(e))
      or
      exists(UnaryExpr u, int o | e = u and o = intValue(u.getOperand()) |
        u.getOp() instanceof UAdd and result = o
        or
        u.getOp() instanceof USub and result = -o
      )
      or
      exists(BinaryExpr b, int l, int r |
        e = b and l = intValue(b.getLeft()) and r = intValue(b.getRight())
      |
        b.getOp() instanceof Add and result = l + r
        or
        b.getOp() instanceof Sub and result = l - r
        or
        b.getOp() instanceof Mult and result = l * r
      )
    )
  }

  /** Constant string value of `e`. */
  string strValue(Expr e) {
    result = e.(StringLiteral).getText()
    or
    result = strValue(singleDefinition(e))
    or
    exists(Subscript s, string base, int i |
      e = s and
      base = strValue(s.getObject()) and
      i = intValue(s.getIndex()) and
      i >= 0 and
      i < base.length() and
      result = base.charAt(i)
    )
  }

  bindingset[l, r]
  private boolean intCompare(int l, string op, int r) {
    op = ">" and if l > r then result = true else result = false
    or
    op = ">=" and if l >= r then result = true else result = false
    or
    op = "<" and if l < r then result = true else result = false
    or
    op = "<=" and if l <= r then result = true else result = false
    or
    op = "==" and if l = r then result = true else result = false
    or
    op = "!=" and if l != r then result = true else result = false
  }

  /** Constant truth value of a condition. */
  boolean boolValue(Expr e) {
    exists(Compare c | e = c and not exists(c.getComparator(1)) |
      result = intCompare(intValue(c.getLeft()), c.getOp(0).getSymbol(), intValue(c.getComparator(0)))
      or
      exists(string l, string r | l = strValue(c.getLeft()) and r = strValue(c.getComparator(0)) |
        c.getOp(0) instanceof In and
        (if exists(r.indexOf(l)) then result = true else result = false)
        or
        c.getOp(0) instanceof NotIn and
        (if exists(r.indexOf(l)) then result = false else result = true)
        or
        c.getOp(0) instanceof Eq and (if l = r then result = true else result = false)
        or
        c.getOp(0) instanceof NotEq and (if l = r then result = false else result = true)
      )
    )
    or
    exists(UnaryExpr u | e = u and u.getOp() instanceof Not | result = boolValue(u.getOperand()).booleanNot())
  }

  /* ---------------------------------------------------------------- constbranch */
  private predicate literalCase(Case c, string v) {
    v = strValue(c.getPattern().(MatchLiteralPattern).getLiteral())
    or
    v = strValue(c.getPattern().(MatchOrPattern).getAPattern().(MatchLiteralPattern).getLiteral())
  }

  /** `c` only has literal (or or-of-literal) patterns, all with known values, and no guard. */
  private predicate fullyLiteralCase(Case c) {
    not exists(c.getGuard()) and
    (
      c.getPattern() instanceof MatchLiteralPattern and literalCase(c, _)
      or
      c.getPattern() instanceof MatchOrPattern and
      forall(Pattern p | p = c.getPattern().(MatchOrPattern).getAPattern() |
        exists(strValue(p.(MatchLiteralPattern).getLiteral()))
      )
    )
  }

  private predicate wildcardCase(Case c) {
    c.getPattern() instanceof MatchWildcardPattern and not exists(c.getGuard())
  }

  /** Index of the case selected when the subject of `m` is the constant `v`. */
  private int selectedCase(MatchStmt m, string v) {
    v = strValue(m.getSubject()) and
    result =
      min(int j |
        literalCase(m.getCase(j), v) and not exists(m.getCase(j).(Case).getGuard())
        or
        wildcardCase(m.getCase(j))
      ) and
    forall(int k | k in [0 .. result - 1] | fullyLiteralCase(m.getCase(k)))
  }

  /** A statement or expression that is never executed. */
  predicate deadRoot(AstNode root) {
    exists(If i, boolean v | v = boolValue(i.getTest()) |
      v = true and root = i.getOrelse().getAnItem()
      or
      v = false and root = i.getBody().getAnItem()
    )
    or
    exists(IfExp i, boolean v | v = boolValue(i.getTest()) |
      v = true and root = i.getOrelse()
      or
      v = false and root = i.getBody()
    )
    or
    exists(MatchStmt m, int sel, int j |
      sel = selectedCase(m, _) and
      exists(m.getCase(j)) and
      j != sel and
      root = m.getCase(j).(Case).getAStmt()
    )
  }

  predicate constBranchBarrier(DataFlow::Node n) {
    exists(AstNode root | deadRoot(root) and root.getAChildNode*() = n.asExpr())
  }

  /* ---------------------------------------------------------------- collection */
  private predicate mentions(Stmt s, Variable v) {
    exists(Name n | s.getAChildNode*() = n and (n.uses(v) or n.defines(v)))
  }

  private predicate localVar(Variable v) {
    v instanceof FastLocalVariable and not v.(FastLocalVariable).escapes()
  }

  private Call methodCallStmt(StmtList sl, int i, Variable v, string name) {
    result = sl.getItem(i).(ExprStmt).getValue() and
    result.getFunc().(Attribute).getName() = name and
    result.getFunc().(Attribute).getObject().(Name).uses(v)
  }

  private predicate listInit(StmtList sl, int i, Variable v) {
    localVar(v) and
    exists(AssignStmt a | a = sl.getItem(i) |
      a.getTarget(0).(Name).defines(v) and
      not exists(a.getTarget(1)) and
      not exists(a.getValue().(List).getAnElt())
    )
  }

  private predicate appendOp(StmtList sl, int i, Variable v, Expr arg) {
    exists(Call c | c = methodCallStmt(sl, i, v, "append") | arg = c.getArg(0) and not exists(c.getArg(1)))
  }

  /** `k = -1` stands for "last element" (no argument or literal -1). */
  private predicate popOp(StmtList sl, int i, Variable v, int k) {
    exists(Call c | c = methodCallStmt(sl, i, v, "pop") |
      not exists(c.getArg(0)) and k = -1
      or
      k = intValue(c.getArg(0)) and k >= -1 and not exists(c.getArg(1))
    )
  }

  private int listLen(StmtList sl, Variable v, int i) {
    listInit(sl, i, v) and result = 0
    or
    exists(int p | p = listLen(sl, v, i - 1) and p < 50 |
      appendOp(sl, i, v, _) and result = p + 1
      or
      exists(int k | popOp(sl, i, v, k) and p > 0 and k < p | result = p - 1)
      or
      not mentions(sl.getItem(i), v) and exists(sl.getItem(i)) and result = p
    )
  }

  private Expr listElem(StmtList sl, Variable v, int i, int j) {
    exists(int p | p = listLen(sl, v, i - 1) and exists(listLen(sl, v, i)) |
      appendOp(sl, i, v, result) and j = p
      or
      appendOp(sl, i, v, _) and j < p and result = listElem(sl, v, i - 1, j)
      or
      exists(int k | popOp(sl, i, v, k) |
        k = -1 and j < p - 1 and result = listElem(sl, v, i - 1, j)
        or
        k >= 0 and j < k and result = listElem(sl, v, i - 1, j)
        or
        k >= 0 and j >= k and j < p - 1 and result = listElem(sl, v, i - 1, j + 1)
      )
      or
      not mentions(sl.getItem(i), v) and result = listElem(sl, v, i - 1, j)
    )
  }

  private predicate dictInit(StmtList sl, int i, Variable v) {
    localVar(v) and
    exists(AssignStmt a | a = sl.getItem(i) |
      a.getTarget(0).(Name).defines(v) and
      not exists(a.getTarget(1)) and
      a.getValue() instanceof Dict and
      not exists(a.getValue().(Dict).getAnItem())
    )
  }

  private predicate dictStore(StmtList sl, int i, Variable v, string key, Expr value) {
    exists(AssignStmt a, Subscript t | a = sl.getItem(i) |
      t = a.getTarget(0) and
      not exists(a.getTarget(1)) and
      t.getObject().(Name).uses(v) and
      key = strValue(t.getIndex()) and
      value = a.getValue()
    )
  }

  /** Statement `i` keeps the dict state of `v` known (init, keyed store, or untouched). */
  private predicate dictKnown(StmtList sl, Variable v, int i) {
    dictInit(sl, i, v)
    or
    dictKnown(sl, v, i - 1) and
    (dictStore(sl, i, v, _, _) or not mentions(sl.getItem(i), v) and exists(sl.getItem(i)))
  }

  private Expr dictVal(StmtList sl, Variable v, int i, string key) {
    dictKnown(sl, v, i) and
    (
      dictStore(sl, i, v, key, result)
      or
      dictStore(sl, i, v, _, _) and not dictStore(sl, i, v, key, _) and result = dictVal(sl, v, i - 1, key)
      or
      not mentions(sl.getItem(i), v) and result = dictVal(sl, v, i - 1, key)
    )
  }

  private predicate constantExpr(Expr e) {
    exists(strValue(e)) or exists(intValue(e)) or e instanceof ImmutableLiteral
  }

  /** A read whose value is a literal stored in a simulated local list or dict. */
  predicate collectionRead(Expr read) {
    exists(StmtList sl, int r, Variable v, AssignStmt a |
      a = sl.getItem(r) and
      read = a.getValue() and
      (
        exists(Subscript s | s = read and s.getObject().(Name).uses(v) |
          exists(int k | k = intValue(s.getIndex()) and k >= 0 and constantExpr(listElem(sl, v, r - 1, k)))
          or
          constantExpr(dictVal(sl, v, r - 1, strValue(s.getIndex())))
        )
        or
        exists(Call g | g = read and g.getFunc().(Attribute).getName() = "get" |
          g.getFunc().(Attribute).getObject().(Name).uses(v) and
          constantExpr(dictVal(sl, v, r - 1, strValue(g.getArg(0))))
        )
      )
    )
  }

  predicate collectionBarrier(DataFlow::Node n) { collectionRead(n.asExpr()) }

  /* ---------------------------------------------------------------- guard */
  /** `tok` is a token whose presence the guard rejects, for the given CWE. */
  bindingset[tok]
  private predicate dangerousToken(string cwe, string tok) {
    cwe = "22" and exists(tok.indexOf(".."))
    or
    cwe = "643" and (tok = "'" or tok = "\"")
  }

  private predicate substringGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch, string cwe) {
    exists(Compare c, string tok |
      g.getNode() = c and
      not exists(c.getComparator(1)) and
      tok = strValue(c.getLeft()) and
      dangerousToken(cwe, tok) and
      node.getNode() = c.getComparator(0)
    |
      c.getOp(0) instanceof In and branch = false
      or
      c.getOp(0) instanceof NotIn and branch = true
    )
  }

  /** `p` is a single-assignment local holding a resolved/normalised path. */
  private predicate resolvedPath(Name p) {
    exists(Call c | c = singleDefinition(p) |
      c.getFunc().(Attribute).getName() = ["resolve", "realpath", "abspath", "normpath"]
    )
  }

  private predicate prefixGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    exists(Call sw, Name p |
      sw.getFunc().(Attribute).getName() = "startswith" and
      (
        sw.getFunc().(Attribute).getObject() = p
        or
        exists(Call s |
          s = sw.getFunc().(Attribute).getObject() and
          s.getFunc().(Name).getId() = "str" and
          s.getArg(0) = p
        )
      ) and
      resolvedPath(p) and
      node.getNode() = p
    |
      g.getNode() = sw and branch = true
      or
      exists(UnaryExpr u | u.getOp() instanceof Not and u.getOperand() = sw |
        g.getNode() = u and branch = false
      )
    )
  }

  private predicate guard22(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    substringGuard(g, node, branch, "22") or prefixGuard(g, node, branch)
  }

  private predicate guard643(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    substringGuard(g, node, branch, "643")
  }

  /**
   * The receiver of a path canonicalisation (`x.resolve()`, `realpath(x)`, ...) whose result is
   * stored in a single-assignment local that is then checked with `startswith`. Canonicalising
   * before a containment check is the standard mitigation; the canonicalisation call itself is not
   * treated as a dangerous file access. Uses of the result are covered by `prefixGuard`.
   */
  private predicate canonicalisedBeforeCheck(Expr receiver) {
    exists(Name p, Call c, DataFlow::GuardNode g, ControlFlowNode node |
      prefixGuard(g, node, _) and
      node.getNode() = p and
      c = singleDefinition(p)
    |
      receiver = c.getFunc().(Attribute).getObject() and c.getFunc().(Attribute).getName() = "resolve"
      or
      receiver = c.getArg(0) and c.getFunc().(Attribute).getName() = ["realpath", "abspath", "normpath"]
    )
  }

  predicate guardBarrier(DataFlow::Node n, string cwe) {
    cwe = "22" and n = DataFlow::BarrierGuard<guard22/3>::getABarrierNode()
    or
    cwe = "22" and canonicalisedBeforeCheck(n.asExpr())
    or
    cwe = "643" and n = DataFlow::BarrierGuard<guard643/3>::getABarrierNode()
    or
    // quote replacement before XPath construction
    cwe = "643" and
    exists(Call c |
      n.asExpr() = c and
      c.getFunc().(Attribute).getName() = "replace" and
      strValue(c.getArg(0)) = ["'", "\""]
    )
  }

  /* ---------------------------------------------------------------- route */
  private string routeLiteral(Function f) {
    exists(FunctionExpr fe, Call d |
      fe.getInnerScope() = f and
      d = fe.getADecorator() and
      d.getFunc().(Attribute).getName() = "route" and
      result = strValue(d.getArg(0))
    )
  }

  private predicate requestPathSplit(Expr e) {
    exists(Call split, Attribute path |
      (e = split or split = singleDefinition(e)) and
      split.getFunc().(Attribute).getName() = "split" and
      strValue(split.getArg(0)) = "/" and
      path = split.getFunc().(Attribute).getObject() and
      path.getName() = "path" and
      path.getObject().(Name).getId() = "request"
    )
  }

  predicate routeBarrier(DataFlow::Node n) {
    exists(Subscript s, Function f, int k |
      n.asExpr() = s and
      requestPathSplit(s.getObject()) and
      k = intValue(s.getIndex()) and
      k >= 0 and
      f = s.getScope() and
      exists(routeLiteral(f)) and
      forall(string route | route = routeLiteral(f) |
        exists(string seg | seg = route.splitAt("/", k) | not exists(seg.indexOf("<")))
      )
    )
  }

  /* ---------------------------------------------------------------- header */
  predicate headerBarrier(DataFlow::Node n) {
    exists(Tuple t, int i | i >= 1 and n.asExpr() = t.getElt(i) |
      exists(Call mr |
        mr.getArg(0) = t and
        (
          mr.getFunc().(Name).getId() = "make_response" or
          mr.getFunc().(Attribute).getName() = "make_response"
        )
      )
      or
      exists(Return r | r.getValue() = t)
    )
  }

  /* ---------------------------------------------------------------- all */
  predicate barrier(DataFlow::Node n, string mech, string cwe) {
    cwe = ["22", "78", "79", "643"] and
    (
      mech = "constbranch" and constBranchBarrier(n)
      or
      mech = "collection" and collectionBarrier(n)
      or
      mech = "route" and routeBarrier(n)
      or
      mech = "header" and cwe = "79" and headerBarrier(n)
    )
    or
    mech = "guard" and guardBarrier(n, cwe)
  }
}
