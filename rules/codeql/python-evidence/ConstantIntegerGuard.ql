/**
 * @name Bounded constant integer branch evidence
 * @description Reports a constant comparison and the branch it selects when reached.
 *              This is evidence about the guard, never a safe-sink or suppression decision.
 * @kind table
 * @id security-triage/py/constant-integer-guard-evidence
 */

import python

/**
 * Only a single non-escaping fast local bound by a plain literal assignment.
 * Require the write to dominate every CFG occurrence of the read. No parameters,
 * globals, captured variables, augmented writes, aliases or phi reasoning.
 */
private IntegerLiteral singleLiteralDefinition(Name read) {
  exists(FastLocalVariable variable, AssignStmt assignment, Name target |
    read.uses(variable) and
    not variable.isParameter() and
    not variable.escapes() and
    not exists(Name deletion | deletion.deletes(variable)) and
    target = assignment.getTarget(0) and
    not exists(assignment.getTarget(1)) and
    target.defines(variable) and
    forall(Name store | store = variable.getAStore() | store = target) and
    assignment.getScope() = read.getScope() and
    result = assignment.getValue() and
    exists(ControlFlowNode use | use.getNode() = read) and
    forall(ControlFlowNode use | use.getNode() = read |
      exists(ControlFlowNode definition |
        definition.getNode() = target and definition.dominates(use)
      )
    )
  )
}

/**
 * Every intermediate value is within [-10000, 10000]. Each multiplication is
 * therefore at most 100000000 in magnitude, within QL's signed 32-bit integer
 * range before the result bound is checked. Large Python ints remain unknown.
 * No floating point, division, exponentiation, calls, attributes or coercions.
 */
private int boundedInteger(Expr expression) {
  result >= -10000 and
  result <= 10000 and
  (
    result = expression.(IntegerLiteral).getValue()
    or
    result = singleLiteralDefinition(expression.(Name)).getValue()
    or
    exists(UnaryExpr unary, int operand |
      expression = unary and
      operand = boundedInteger(unary.getOperand()) and
      (
        unary.getOp() instanceof UAdd and result = operand
        or
        unary.getOp() instanceof USub and result = -operand
      )
    )
    or
    exists(BinaryExpr binary, int left, int right |
      expression = binary and
      left = boundedInteger(binary.getLeft()) and
      right = boundedInteger(binary.getRight()) and
      (
        binary.getOp() instanceof Add and result = left + right
        or
        binary.getOp() instanceof Sub and result = left - right
        or
        binary.getOp() instanceof Mult and result = left * right
      )
    )
  )
}

bindingset[left, right]
private predicate comparison(int left, string operator, int right, boolean outcome) {
  operator = ">" and
  (
    left > right and outcome = true
    or
    left <= right and outcome = false
  )
  or
  operator = ">=" and
  (
    left >= right and outcome = true
    or
    left < right and outcome = false
  )
  or
  operator = "<" and
  (
    left < right and outcome = true
    or
    left >= right and outcome = false
  )
  or
  operator = "<=" and
  (
    left <= right and outcome = true
    or
    left > right and outcome = false
  )
  or
  operator = "==" and
  (
    left = right and outcome = true
    or
    left != right and outcome = false
  )
  or
  operator = "!=" and
  (
    left != right and outcome = true
    or
    left = right and outcome = false
  )
}

from
  If guard, Compare test, int left, int right, string operator, boolean outcome,
  string selectedBranch
where
  guard.getScope() instanceof Function and
  test = guard.getTest() and
  not exists(test.getComparator(1)) and
  left = boundedInteger(test.getLeft()) and
  right = boundedInteger(test.getComparator(0)) and
  operator = test.getOp(0).getSymbol() and
  comparison(left, operator, right, outcome) and
  (
    outcome = true and selectedBranch = "then"
    or
    outcome = false and selectedBranch = "else"
  )
select guard.getLocation().getFile().getRelativePath() as file,
  guard.getScope().(Function).getName() as function_name,
  test.getLocation().getStartLine() as guard_line,
  test.getLocation().getStartColumn() as guard_column, left as left_value,
  operator as comparison_operator, right as right_value, outcome as condition_value,
  selectedBranch as selected_branch
