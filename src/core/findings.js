let findings = []

export function addFinding(severity, module, title, detail, fix) {
  findings.push({ severity, module, title, detail, fix: fix ?? null })
}

export function getFindings() {
  return findings
}

export function clearFindings() {
  findings = []
}

export function calculateScore() {
  const weights = { CRITICAL: 15, HIGH: 8, MEDIUM: 3, LOW: 1 }
  const deduction = findings.reduce((sum, f) => sum + (weights[f.severity] ?? 0), 0)
  const score = Math.max(0, 100 - deduction)
  let grade
  if (score >= 90) grade = 'A'
  else if (score >= 75) grade = 'B'
  else if (score >= 60) grade = 'C'
  else if (score >= 45) grade = 'D'
  else grade = 'F'
  return { score, grade }
}
