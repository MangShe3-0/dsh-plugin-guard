#!/usr/bin/env node
import { formatMarkdown, scanPlugin } from '../lib/scanner.js'

const args = process.argv.slice(2)
const json = args.includes('--json')
const target = args.find(arg => !arg.startsWith('-'))

if (!target || args.includes('--help')) {
  console.log('Usage: dsh-plugin-guard <plugin-path> [--json]')
  console.log('Exit codes: 0=reviewable, 1=caution, 2=do not install, 3=scan failed')
  process.exit(target ? 0 : 3)
}

try {
  const report = await scanPlugin(target)
  console.log(json ? JSON.stringify(report, null, 2) : formatMarkdown(report))
  process.exitCode = report.verdict === 'DO_NOT_INSTALL' ? 2 : report.verdict === 'CAUTION' ? 1 : 0
} catch (error) {
  console.error(`dsh-plugin-guard: ${error instanceof Error ? error.message : String(error)}`)
  process.exitCode = 3
}
