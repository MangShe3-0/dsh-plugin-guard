import { lstat, open, readFile, readdir, realpath } from 'node:fs/promises'
import path from 'node:path'
import { RULES, SEVERITY_WEIGHT } from './rules.js'

const DEFAULT_LIMITS = Object.freeze({
  maxFiles: 1_000,
  maxFileBytes: 1_048_576,
  maxTotalBytes: 20_971_520,
  maxFindings: 500,
})

const SKIP_DIRECTORIES = new Set(['.git', 'node_modules', 'coverage', '.cache'])
const TEXT_EXTENSIONS = new Set([
  '', '.c', '.cc', '.cfg', '.conf', '.css', '.go', '.h', '.html', '.ini', '.java', '.js', '.json',
  '.jsx', '.md', '.mjs', '.mts', '.php', '.pl', '.properties', '.ps1', '.py', '.rb', '.rs', '.sh',
  '.sql', '.toml', '.ts', '.tsx', '.txt', '.vue', '.xml', '.yaml', '.yml', '.zsh',
])

function lineNumber(text, index) {
  let line = 1
  for (let cursor = 0; cursor < index; cursor += 1) if (text.charCodeAt(cursor) === 10) line += 1
  return line
}

function evidenceFor(text, index, length) {
  const start = Math.max(0, text.lastIndexOf('\n', index - 1) + 1)
  let end = text.indexOf('\n', index + length)
  if (end === -1) end = text.length
  const raw = text.slice(start, end).trim().replace(/\s+/gu, ' ')
  return raw.length > 240 ? `${raw.slice(0, 237)}...` : raw
}

function isProbablyBinary(buffer) {
  const sample = buffer.subarray(0, Math.min(buffer.length, 8_192))
  if (sample.includes(0)) return true
  let control = 0
  for (const byte of sample) if (byte < 9 || (byte > 13 && byte < 32)) control += 1
  return sample.length > 0 && control / sample.length > 0.08
}

async function readBounded(file, maxBytes) {
  const handle = await open(file, 'r')
  try {
    const buffer = Buffer.alloc(maxBytes + 1)
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0)
    return { buffer: buffer.subarray(0, Math.min(bytesRead, maxBytes)), truncated: bytesRead > maxBytes }
  } finally {
    await handle.close()
  }
}

async function collectFiles(root, limits) {
  const files = []
  const skipped = []
  const queue = [root]
  let totalBytes = 0

  while (queue.length > 0 && files.length < limits.maxFiles && totalBytes < limits.maxTotalBytes) {
    const current = queue.shift()
    const stat = await lstat(current)
    if (stat.isSymbolicLink()) {
      skipped.push({ path: current, reason: 'symbolic-link' })
      continue
    }
    if (stat.isDirectory()) {
      if (current !== root && SKIP_DIRECTORIES.has(path.basename(current))) {
        skipped.push({ path: current, reason: 'excluded-directory' })
        continue
      }
      const entries = await readdir(current, { withFileTypes: true })
      entries.sort((a, b) => a.name.localeCompare(b.name))
      for (const entry of entries) queue.push(path.join(current, entry.name))
      continue
    }
    if (!stat.isFile()) {
      skipped.push({ path: current, reason: 'not-regular-file' })
      continue
    }
    if (!TEXT_EXTENSIONS.has(path.extname(current).toLowerCase()) && path.basename(current) !== 'Dockerfile') {
      skipped.push({ path: current, reason: 'unsupported-or-binary-type' })
      continue
    }
    files.push({ path: current, size: stat.size })
    totalBytes += Math.min(stat.size, limits.maxFileBytes)
  }

  const incomplete = queue.length > 0
  if (incomplete) skipped.push({ path: root, reason: 'scan-budget-exhausted' })
  return { files, skipped, incomplete }
}

function makeFinding(rule, relativePath, text, match) {
  return {
    ruleId: rule.id,
    severity: rule.severity,
    category: rule.category,
    title: rule.title,
    file: relativePath,
    line: lineNumber(text, match.index ?? 0),
    evidence: evidenceFor(text, match.index ?? 0, match[0].length),
    recommendation: rule.recommendation,
  }
}

function scanText(relativePath, text) {
  const findings = []
  for (const rule of RULES) {
    const flags = rule.pattern.flags.includes('g') ? rule.pattern.flags : `${rule.pattern.flags}g`
    const pattern = new RegExp(rule.pattern.source, flags)
    for (const match of text.matchAll(pattern)) findings.push(makeFinding(rule, relativePath, text, match))
  }
  const longBase64 = /(?:['"`]|\b)([A-Za-z0-9+/]{400,}={0,2})(?:['"`]|\b)/gu
  for (const match of text.matchAll(longBase64)) {
    findings.push({
      ruleId: 'SC003', severity: 'medium', category: 'obfuscation', title: 'Large embedded encoded payload',
      file: relativePath, line: lineNumber(text, match.index ?? 0), evidence: '[large base64-like payload redacted]',
      recommendation: 'Require the payload to be supplied as a reviewable source or pinned artifact.',
    })
  }
  return findings
}

function scanPackageJson(relativePath, text) {
  if (path.basename(relativePath) !== 'package.json') return []
  const findings = []
  let pkg
  try {
    pkg = JSON.parse(text)
  } catch (error) {
    return [{
      ruleId: 'META001', severity: 'medium', category: 'manifest', title: 'Invalid package.json',
      file: relativePath, line: 1, evidence: String(error.message).slice(0, 240),
      recommendation: 'Reject malformed manifests; they prevent reliable dependency and activation review.',
    }]
  }

  const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts : {}
  for (const key of ['preinstall', 'install', 'postinstall', 'prepare']) {
    if (typeof scripts[key] === 'string') findings.push({
      ruleId: 'SC004', severity: key === 'prepare' ? 'medium' : 'high', category: 'supply-chain',
      title: `Package lifecycle script: ${key}`, file: relativePath, line: 1,
      evidence: `${key}: ${scripts[key].slice(0, 220)}`,
      recommendation: 'Inspect and run lifecycle scripts only for a commit-pinned package after explicit approval.',
    })
  }

  for (const section of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    const deps = pkg[section]
    if (!deps || typeof deps !== 'object') continue
    for (const [name, version] of Object.entries(deps)) {
      if (typeof version !== 'string') continue
      const unpinned = version === '*' || version === 'latest' || /^(?:git\+)?https?:/iu.test(version)
        || (/^(?:github:|git\+|https?:).*#/iu.test(version) && !/#[0-9a-f]{40}$/iu.test(version))
      if (unpinned) findings.push({
        ruleId: 'SC005', severity: 'medium', category: 'supply-chain', title: 'Unpinned dependency source',
        file: relativePath, line: 1, evidence: `${section}.${name}: ${version}`,
        recommendation: 'Pin registry packages to an exact version and Git sources to a full commit SHA.',
      })
    }
  }

  if (!pkg.dsh?.bundle?.patch) findings.push({
    ruleId: 'META002', severity: 'low', category: 'manifest', title: 'No DSH bundle patch declared',
    file: relativePath, line: 1, evidence: 'package.json does not declare dsh.bundle.patch',
    recommendation: 'Confirm whether this is actually an installable DSH plugin and review its activation path.',
  })
  return findings
}

function addCompoundFindings(findings) {
  const byFile = new Map()
  for (const finding of findings) {
    const ids = byFile.get(finding.file) ?? new Set()
    ids.add(finding.ruleId)
    byFile.set(finding.file, ids)
  }
  for (const [file, ids] of byFile) {
    if ((ids.has('EX001') || ids.has('EX003')) && ids.has('EX002')) findings.push({
      ruleId: 'EX004', severity: 'critical', category: 'data-exfiltration', title: 'Secret-to-network exfiltration chain',
      file, line: 1, evidence: 'Sensitive-data access and outbound transmission occur in the same file.',
      recommendation: 'Do not install until the data flow is manually proven safe and narrowly scoped.',
    })
    if (ids.has('CODE002') && ids.has('PI001')) findings.push({
      ruleId: 'PI004', severity: 'critical', category: 'prompt-injection', title: 'Instruction override combined with command execution',
      file, line: 1, evidence: 'Policy-override language and command execution occur in the same file.',
      recommendation: 'Do not install. Treat this combination as an executable prompt-injection path.',
    })
  }
}

function scoreFindings(findings, incomplete) {
  const grouped = new Map()
  for (const finding of findings) {
    const values = grouped.get(finding.ruleId) ?? []
    values.push(SEVERITY_WEIGHT[finding.severity] ?? 0)
    grouped.set(finding.ruleId, values)
  }
  let score = incomplete ? 10 : 0
  for (const values of grouped.values()) {
    values.sort((a, b) => b - a)
    score += values[0] ?? 0
    score += Math.round((values[1] ?? 0) * 0.35)
    score += Math.round((values[2] ?? 0) * 0.15)
  }
  return Math.min(100, score)
}

function verdictFor(score, findings, incomplete) {
  const critical = findings.some(finding => finding.severity === 'critical')
  const highRules = new Set(findings.filter(finding => finding.severity === 'high').map(finding => finding.ruleId)).size
  if (critical || highRules >= 2 || score >= 55) return 'DO_NOT_INSTALL'
  if (incomplete || highRules === 1 || score >= 21) return 'CAUTION'
  return 'REVIEWABLE'
}

export async function scanPlugin(target, options = {}) {
  const limits = { ...DEFAULT_LIMITS, ...(options.limits ?? {}) }
  const absolute = path.resolve(target)
  const root = await realpath(absolute)
  const rootStat = await lstat(root)
  const base = rootStat.isDirectory() ? root : path.dirname(root)
  const { files, skipped, incomplete } = await collectFiles(root, limits)
  const findings = []
  let scannedBytes = 0
  const scannedFiles = []

  for (const file of files) {
    if (findings.length >= limits.maxFindings) break
    const relative = path.relative(base, file.path) || path.basename(file.path)
    const { buffer, truncated } = await readBounded(file.path, limits.maxFileBytes)
    scannedBytes += buffer.length
    if (isProbablyBinary(buffer)) {
      skipped.push({ path: relative, reason: 'binary-content' })
      continue
    }
    const text = buffer.toString('utf8')
    scannedFiles.push({ path: relative, bytes: buffer.length, truncated })
    findings.push(...scanText(relative, text), ...scanPackageJson(relative, text))
  }

  addCompoundFindings(findings)
  const limitedFindings = findings.slice(0, limits.maxFindings)
  const scanIncomplete = incomplete || findings.length > limits.maxFindings || scannedFiles.some(file => file.truncated)
  const score = scoreFindings(limitedFindings, scanIncomplete)
  const verdict = verdictFor(score, limitedFindings, scanIncomplete)
  const counts = { critical: 0, high: 0, medium: 0, low: 0 }
  for (const finding of limitedFindings) counts[finding.severity] += 1

  return {
    schemaVersion: 1,
    scanner: 'dsh-plugin-guard',
    target: root,
    verdict,
    score,
    counts,
    scanComplete: !scanIncomplete,
    scannedFiles: scannedFiles.length,
    scannedBytes,
    skipped,
    findings: limitedFindings,
    limitations: [
      'Static analysis cannot prove a plugin is safe.',
      'The scanner does not execute code, follow symlinks, inspect binaries, or contact the network.',
      'Review dependency provenance and runtime behavior separately in a sandbox.',
    ],
  }
}

export function formatMarkdown(report) {
  const lines = [
    '# DSH Plugin Guard Report', '',
    `- Verdict: **${report.verdict}**`,
    `- Risk score: **${report.score}/100**`,
    `- Scan complete: **${report.scanComplete ? 'yes' : 'no'}**`,
    `- Files scanned: **${report.scannedFiles}**`,
    `- Findings: critical ${report.counts.critical}, high ${report.counts.high}, medium ${report.counts.medium}, low ${report.counts.low}`,
    '',
  ]
  if (report.findings.length === 0) lines.push('No known static patterns were found. This is not a guarantee of safety.', '')
  for (const finding of report.findings) {
    lines.push(
      `## ${finding.severity.toUpperCase()} · ${finding.ruleId} · ${finding.title}`,
      '',
      `- Location: \`${finding.file}:${finding.line}\``,
      `- Evidence: \`${finding.evidence.replace(/`/gu, '\\`')}\``,
      `- Recommendation: ${finding.recommendation}`,
      '',
    )
  }
  if (report.skipped.length > 0) {
    lines.push('## Skipped or excluded', '')
    for (const item of report.skipped.slice(0, 100)) lines.push(`- \`${item.path}\`: ${item.reason}`)
    lines.push('')
  }
  lines.push('## Limitations', '')
  for (const limitation of report.limitations) lines.push(`- ${limitation}`)
  return lines.join('\n')
}

export async function assertInsideAllowedRoots(target, roots) {
  const absolute = path.resolve(target)
  const targetStat = await lstat(absolute)
  if (targetStat.isSymbolicLink()) throw new Error('plugin_guard_scan: the target itself must not be a symbolic link')
  const resolved = await realpath(absolute)
  const allowed = await Promise.all(roots.map(async root => realpath(path.resolve(root))))
  const inside = allowed.some(root => resolved === root || resolved.startsWith(`${root}${path.sep}`))
  if (!inside) throw new Error(`plugin_guard_scan: target is outside allowed roots: ${allowed.join(', ')}`)
  return resolved
}

/**
 * Resolve a model-requested scan target against the current DSH session.
 * The session header cwd is validated by DSH at session creation and is the
 * only implicit root. Extra roots must be configured explicitly by the user.
 */
export async function resolveToolScanTarget(target, exec, extraRoots = []) {
  const workspaceRoot = exec?.agent?.session?.header?.cwd
  if (typeof workspaceRoot !== 'string' || !path.isAbsolute(workspaceRoot)) {
    throw new Error('plugin_guard_scan: current session has no validated workspace')
  }
  const candidate = path.isAbsolute(target) ? target : path.resolve(workspaceRoot, target)
  return assertInsideAllowedRoots(candidate, [workspaceRoot, ...extraRoots])
}
