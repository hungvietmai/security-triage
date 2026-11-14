/**
 * Safety evidence for CodeQL Python taint queries — development version 0.2.
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

  /* ---------------------------------------------------------------- string context */
  /** `v` is the interpolated expression at position `i` of f-string `f` (both extractor shapes). */
  private predicate fstringSlot(Fstring f, int i, Expr v) {
    v = f.getValue(i).(FormattedValue).getValue()
    or
    v = f.getValue(i) and not v instanceof StringLiteral and not v instanceof FormattedValue
  }

  /** Literal text immediately before `v` where `v` is spliced into an f-string, `+` chain or `"".join` list. */
  string leftText(Expr v) {
    exists(Fstring f, int i | fstringSlot(f, i, v) | result = f.getValue(i - 1).(StringLiteral).getText())
    or
    exists(BinaryExpr add | add.getOp() instanceof Add and add.getRight() = v |
      result = add.getLeft().(StringLiteral).getText()
      or
      result = add.getLeft().(BinaryExpr).getRight().(StringLiteral).getText() and
      add.getLeft().(BinaryExpr).getOp() instanceof Add
    )
    or
    exists(List l, int i | l.getElt(i) = v and joinedList(l) | result = l.getElt(i - 1).(StringLiteral).getText())
  }

  /** Literal text immediately after `v`. */
  string rightText(Expr v) {
    exists(Fstring f, int i | fstringSlot(f, i, v) | result = f.getValue(i + 1).(StringLiteral).getText())
    or
    exists(BinaryExpr inner, BinaryExpr outer |
      inner.getOp() instanceof Add and inner.getRight() = v and
      outer.getOp() instanceof Add and outer.getLeft() = inner and
      result = outer.getRight().(StringLiteral).getText()
    )
    or
    exists(List l, int i | l.getElt(i) = v and joinedList(l) | result = l.getElt(i + 1).(StringLiteral).getText())
  }

  private predicate joinedList(List l) {
    exists(Call j | j.getFunc().(Attribute).getName() = "join" and j.getArg(0) = l |
      exists(strValue(j.getFunc().(Attribute).getObject()))
    )
  }

  /** `v` is spliced into a string literal delimited by quote character `q` on both sides. */
  predicate quotedContext(Expr v, string q) {
    q = ["'", "\""] and leftText(v).suffix(leftText(v).length() - 1) = q and rightText(v).charAt(0) = q
  }

  /**
   * `v` is spliced after a literal ending in "/" (a fixed directory prefix built by string
   * concatenation). An absolute value then stays below the prefix; with `os.path.join` or
   * pathlib `/` it would replace the prefix, so those constructions do not qualify.
   */
  predicate fixedPrefixContext(Expr v) { leftText(v).suffix(leftText(v).length() - 1) = "/" }

  /* ---------------------------------------------------------------- guard */
  private predicate substringGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch, string tok) {
    exists(Compare c |
      g.getNode() = c and
      not exists(c.getComparator(1)) and
      tok = strValue(c.getLeft()) and
      node.getNode() = c.getComparator(0)
    |
      c.getOp(0) instanceof In and branch = false
      or
      c.getOp(0) instanceof NotIn and branch = true
    )
  }

  private predicate dotdotGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    exists(string tok | substringGuard(g, node, branch, tok) | exists(tok.indexOf("..")))
  }

  private predicate singleQuoteGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    substringGuard(g, node, branch, "'")
  }

  private predicate doubleQuoteGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    substringGuard(g, node, branch, "\"")
  }

  /** `p` is a single-assignment local holding a canonicalised path. */
  private predicate resolvedPath(Name p) {
    exists(Call c | c = singleDefinition(p) |
      c.getFunc().(Attribute).getName() = ["resolve", "realpath", "abspath"]
    )
  }

  /** `e` is a directory prefix that ends with a separator: `B + os.sep`, `B + "/"`, f"{B}/". */
  private predicate separatorTerminated(Expr e) {
    exists(BinaryExpr add | e = add and add.getOp() instanceof Add |
      add.getRight().(Attribute).getName() = "sep" or strValue(add.getRight()) = "/"
    )
    or
    exists(Fstring f, int n | e = f and n = max(int i | exists(f.getValue(i))) |
      f.getValue(n).(StringLiteral).getText().suffix(f.getValue(n).(StringLiteral).getText().length() - 1) = "/"
    )
  }

  /** Component-wise containment check of a canonicalised path `p`. */
  private predicate containmentGuard(DataFlow::GuardNode g, ControlFlowNode node, boolean branch) {
    exists(Call check, Name p, Expr tested |
      resolvedPath(p) and
      node.getNode() = p and
      (
        // str(p).startswith(base + os.sep)   or   p.startswith(base + "/")
        check.getFunc().(Attribute).getName() = "startswith" and
        tested = check.getFunc().(Attribute).getObject() and
        (tested = p or tested.(Call).getFunc().(Name).getId() = "str" and tested.(Call).getArg(0) = p) and
        separatorTerminated(check.getArg(0))
        or
        // p.is_relative_to(base)
        check.getFunc().(Attribute).getName() = "is_relative_to" and
        check.getFunc().(Attribute).getObject() = p
      )
    |
      g.getNode() = check and branch = true
      or
      exists(UnaryExpr u | u.getOp() instanceof Not and u.getOperand() = check | g.getNode() = u and branch = false)
    )
  }

  /** A quote replacement whose replacement text does not contain the replaced quote. */
  private predicate quoteReplacement(Call c, string q) {
    c.getFunc().(Attribute).getName() = "replace" and
    q = strValue(c.getArg(0)) and
    q = ["'", "\""] and
    not exists(strValue(c.getArg(1)).indexOf(q)) and
    exists(strValue(c.getArg(1)))
  }

  /** A barrier for CWE `cwe` produced by a guard, with the kind of evidence. */
  predicate guardBarrier(DataFlow::Node n, string cwe, string kind) {
    cwe = "22" and
    n = DataFlow::BarrierGuard<dotdotGuard/3>::getABarrierNode() and
    fixedPrefixContext(n.asExpr()) and
    kind = "dotdot-reject+fixed-prefix"
    or
    cwe = "22" and
    n = DataFlow::BarrierGuard<containmentGuard/3>::getABarrierNode() and
    kind = "canonical-path+containment-check"
    or
    cwe = "643" and
    n = DataFlow::BarrierGuard<singleQuoteGuard/3>::getABarrierNode() and
    quotedContext(n.asExpr(), "'") and
    kind = "quote-reject+same-quote-literal"
    or
    cwe = "643" and
    n = DataFlow::BarrierGuard<doubleQuoteGuard/3>::getABarrierNode() and
    quotedContext(n.asExpr(), "\"") and
    kind = "quote-reject+same-quote-literal"
    or
    cwe = "643" and
    kind = "quote-replace+same-quote-literal" and
    exists(Call c, string q | quoteReplacement(c, q) |
      // inline: "...'" + x.replace("'", ...) + "'..."
      n.asExpr() = c and quotedContext(c, q)
      or
      // through a single-assignment local whose read is in the same quoted context
      exists(Name use | use = n.asExpr() and singleDefinition(use) = c and quotedContext(use, q))
    )
  }

  /**
   * Sink exclusion (not a barrier): the receiver of `x.resolve()` / argument of `realpath(x)` is
   * not itself a dangerous file access when the canonical result is containment-checked.
   */
  predicate excludedSink(DataFlow::Node sink, string mech, string cwe) {
    mech = "guard" and
    cwe = "22" and
    exists(Name p, Call c, DataFlow::GuardNode g, ControlFlowNode node |
      containmentGuard(g, node, _) and node.getNode() = p and c = singleDefinition(p)
    |
      sink.asExpr() = c.getFunc().(Attribute).getObject() and c.getFunc().(Attribute).getName() = "resolve"
      or
      sink.asExpr() = c.getArg(0) and c.getFunc().(Attribute).getName() = ["realpath", "abspath"]
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

  /** Segment `k` of every route through which `f` can run is the fixed text `seg`. */
  bindingset[k]
  private predicate fixedSegment(Function f, int k) {
    exists(routeLiteral(f)) and
    exists(string seg |
      seg = routeLiteral(f).splitAt("/", k) and
      forall(string route | route = routeLiteral(f) | route.splitAt("/", k) = seg) and
      not exists(seg.indexOf("<"))
    ) and
    // every call by name to f comes from a route handler whose segment k is the same text
    forall(Call c | c.getFunc().(Name).getId() = f.getName() |
      exists(Function g | g = c.getScope() |
        exists(routeLiteral(g)) and
        forall(string r1, string r2 | r1 = routeLiteral(f) and r2 = routeLiteral(g) |
          r1.splitAt("/", k) = r2.splitAt("/", k)
        )
      )
    )
  }

  predicate routeBarrier(DataFlow::Node n) {
    exists(Subscript s, int k |
      n.asExpr() = s and
      requestPathSplit(s.getObject()) and
      k = intValue(s.getIndex()) and
      k >= 0 and
      fixedSegment(s.getScope(), k)
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
      exists(Return r | r.getValue() = t and exists(routeLiteral(r.getScope())))
    )
  }

  /* ---------------------------------------------------------------- all */
  predicate barrierKind(DataFlow::Node n, string mech, string cwe, string kind) {
    cwe = ["22", "78", "79", "643"] and
    (
      mech = "constbranch" and constBranchBarrier(n) and kind = "dead-branch"
      or
      mech = "collection" and collectionBarrier(n) and kind = "constant-element"
      or
      mech = "route" and routeBarrier(n) and kind = "route-fixed-segment"
      or
      mech = "header" and cwe = "79" and headerBarrier(n) and kind = "response-header-position"
    )
    or
    mech = "guard" and guardBarrier(n, cwe, kind)
  }

  predicate barrier(DataFlow::Node n, string mech, string cwe) { barrierKind(n, mech, cwe, _) }
}
