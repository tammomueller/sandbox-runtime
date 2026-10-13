import { describe, expect, test } from 'bun:test'
import { spawn } from 'node:child_process'
import type { Readable } from 'node:stream'
import { quote } from '../../src/utils/shell-quote.js'
import { whichSync } from '../../src/utils/which.js'
import {
  cleanupBwrapMountPoints,
  wrapCommandWithSandboxLinux,
} from '../../src/sandbox/linux-sandbox-utils.js'

// Requires Linux, tini, bubblewrap and the built seccomp helper. A caller may
// select a bwrap path whose AppArmor attachment permits nested user namespaces.
const initPath = whichSync('tini')
const node = whichSync('node')
describe.if(process.platform === 'linux' && !!initPath && !!node)(
  'caller-supervised Linux sandbox',
  () => {
    for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP'] as const) {
      test(
        'delivers ' + signal + ' once and preserves the handled exit status',
        async () => {
          const program =
            'let count = 0;' +
            'process.on(' +
            JSON.stringify(signal) +
            ', () => {' +
            'console.log("HANDLED", ++count);' +
            'setTimeout(() => process.exit(42), 100);});' +
            'console.log("READY");setInterval(() => {}, 1000);'
          const command = await wrapCommandWithSandboxLinux({
            command: 'exec ' + quote([node!, '-e', program]),
            needsNetworkRestriction: false,
            writeConfig: { allowOnly: [], denyWithinAllow: [] },
            initPath: initPath!,
            infoFd: 3,
            bwrapPath: process.env.SRT_TEST_BWRAP_PATH,
          })
          const child = spawn('exec ' + command, {
            shell: true,
            detached: true,
            stdio: ['ignore', 'pipe', 'pipe', 'pipe'],
          })
          let info = ''
          let output = ''
          let errors = ''
          let sent = false
          const deliver = (): void => {
            if (sent || !output.includes('READY')) return
            let pid: number
            try {
              pid = JSON.parse(info)['child-pid']
            } catch {
              return
            }
            if (!Number.isSafeInteger(pid) || pid <= 1) return
            sent = true
            process.kill(pid, signal)
          }
          child.stdout!.on('data', data => {
            output += data
            deliver()
          })
          child.stderr!.on('data', data => (errors += data))
          ;(child.stdio[3] as Readable).on('data', data => {
            info += data
            deliver()
          })
          const timer = setTimeout(() => child.kill('SIGKILL'), 5000)
          try {
            const code = await new Promise<number | null>((resolve, reject) => {
              child.once('error', reject)
              child.once('close', resolve)
            })
            expect({ code, errors }).toEqual({ code: 42, errors: '' })
            expect(sent).toBe(true)
            expect(output.match(/HANDLED/g)?.length).toBe(1)
          } finally {
            clearTimeout(timer)
            if (child.exitCode === null && child.signalCode === null)
              child.kill('SIGKILL')
            cleanupBwrapMountPoints()
          }
        },
        10000,
      )
    }
  },
)
