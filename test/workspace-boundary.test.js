import assert from 'node:assert/strict'
import { mkdtemp, mkdir, realpath } from 'node:fs/promises'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'
import * as scanner from '../lib/scanner.js'

function executionFor(cwd) {
  return {
    agent: {
      session: {
        header: { cwd },
      },
    },
  }
}

test('tool target resolves relative to the validated session workspace', async () => {
  assert.equal(typeof scanner.resolveToolScanTarget, 'function')
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-guard-workspace-'))
  const plugin = path.join(workspace, 'untrusted-plugin')
  await mkdir(plugin)

  const resolved = await scanner.resolveToolScanTarget(
    './untrusted-plugin',
    executionFor(workspace),
    [],
  )

  assert.equal(resolved, await realpath(plugin))
})

test('tool target fails closed without a session workspace', async () => {
  assert.equal(typeof scanner.resolveToolScanTarget, 'function')
  await assert.rejects(
    () => scanner.resolveToolScanTarget('.', {}, []),
    /current session has no validated workspace/,
  )
})

test('tool target rejects an absolute path outside the session workspace', async () => {
  assert.equal(typeof scanner.resolveToolScanTarget, 'function')
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-guard-workspace-'))
  const outside = await mkdtemp(path.join(os.tmpdir(), 'dsh-guard-outside-'))

  await assert.rejects(
    () => scanner.resolveToolScanTarget(outside, executionFor(workspace), []),
    /outside allowed roots/,
  )
})

test('explicit extra roots can allow a separate review inbox', async () => {
  assert.equal(typeof scanner.resolveToolScanTarget, 'function')
  const workspace = await mkdtemp(path.join(os.tmpdir(), 'dsh-guard-workspace-'))
  const reviewInbox = await mkdtemp(path.join(os.tmpdir(), 'dsh-guard-inbox-'))

  const resolved = await scanner.resolveToolScanTarget(
    reviewInbox,
    executionFor(workspace),
    [reviewInbox],
  )

  assert.equal(resolved, await realpath(reviewInbox))
})
