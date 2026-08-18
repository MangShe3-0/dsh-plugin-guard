import { defineTool } from '@deepseek-ai/dsh-tools'
import { formatMarkdown, scanPlugin, assertInsideAllowedRoots } from './scanner.js'

export const name = 'plugin-guard'
export const inject = ['tools']

const parameters = {
  path: {
    type: 'string',
    required: true,
    description: 'Local plugin directory or text file to scan. The path must be inside the Harness workspace or DSH_PLUGIN_GUARD_ROOTS.',
  },
  format: {
    type: 'string',
    description: 'Report format: markdown (default) or json.',
  },
}

const outputSchema = {
  type: 'object',
  additionalProperties: false,
  properties: {
    verdict: { type: 'string', required: true },
    score: { type: 'number', required: true },
    scanComplete: { type: 'boolean', required: true },
    report: { type: 'string', required: true },
  },
}

function allowedRoots() {
  const configured = process.env.DSH_PLUGIN_GUARD_ROOTS
  if (!configured) return [process.cwd()]
  return [process.cwd(), ...configured.split(process.platform === 'win32' ? ';' : ':').filter(Boolean)]
}

export function apply(ctx) {
  ctx.tools.register(defineTool({
    name: 'plugin_guard_scan',
    description: 'Statically inspect an untrusted DeepSeek Harness plugin before installation. Read-only and offline: never executes the target, follows symlinks, or contacts the network.',
    parameters,
    output: {
      schema: outputSchema,
      render: (_args, value) => [{ type: 'text', text: value.report }],
    },
    execute: async args => {
      const target = await assertInsideAllowedRoots(args.path, allowedRoots())
      const result = await scanPlugin(target)
      const format = args.format === 'json' ? 'json' : 'markdown'
      return {
        verdict: result.verdict,
        score: result.score,
        scanComplete: result.scanComplete,
        report: format === 'json' ? JSON.stringify(result, null, 2) : formatMarkdown(result),
      }
    },
    presentCall: args => ({
      card: 'generic',
      title: 'Scan plugin safety',
      kind: 'other',
      rawInput: args,
    }),
  }))
}
