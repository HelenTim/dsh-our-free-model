import http from 'node:http'
import path from 'node:path'
import { Worker } from 'node:worker_threads'
import { foldForwardOutcome } from '../../../src/core/completion.js'
import { recordTurn, recordUsage } from '../../../src/store.js'

// 二维码登录页由渠道在服务端临时起一个只监听回环的小服务渲染，地址形如
// `http://127.0.0.1:<port>/raccoon/login`。公网部署时浏览器够不着这个端口，
// 因此把这类地址改写成主服务的公开地址，并在主监听器上按路径前缀转发。
const LOGIN_PAGE_MS = 15 * 60_000
const LOOPBACK_LOGIN = /^http:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)(\/[^?#]*)?/i

/** 改写登录地址；返回是否改写了任何一项。 */
function rewriteLoginUrls(value, publicBase, loginPages, depth = 0) {
  if (depth > 8 || value === null || typeof value !== 'object') return false
  let changed = false
  for (const [key, item] of Object.entries(value)) {
    if (typeof item === 'string') {
      const match = LOOPBACK_LOGIN.exec(item)
      if (match === null) continue
      const pathname = match[2] ?? '/'
      const segment = pathname.split('/').filter(part => part !== '')[0]
      if (segment === undefined) continue
      loginPages.set(`/${segment}/`, { port: Number(match[1]), until: Date.now() + LOGIN_PAGE_MS })
      value[key] = `${publicBase.replace(/\/+$/, '')}${pathname}${item.slice(match[0].length)}`
      changed = true
    } else if (rewriteLoginUrls(item, publicBase, loginPages, depth + 1)) {
      changed = true
    }
  }
  return changed
}

// CodeArts / LobsterAI / TRAE / Gemini 的回调地址由上游写死或校验成本机回环，
// 授权完成后浏览器会跳到用户自己机器上的 127.0.0.1，公网实例收不到授权码。
// 这些渠道的回调服务仍在服务端进程里监听，因此把浏览器地址栏里那条失败地址
// 回传过来，由主服务转发给对应的回环端口即可完成登录。
const LOOPBACK_CALLBACK = /^https?:\/\/(?:127\.0\.0\.1|localhost|\[::1\]):(\d+)(\/[^?#]*)?/i
const RELAY_MS = 30 * 60_000

/** 从登录地址里找出这次登录正在等待的回环回调端口与路径。 */
function callbackTarget(provider, loginUrl) {
  let url
  try { url = new URL(loginUrl) } catch { return undefined }
  // LobsterAI 把 redirect_uri 放在 `#/login?...` 的 hash 段里，不在 search 上。
  const hashQuery = url.hash.includes('?') ? url.hash.slice(url.hash.indexOf('?') + 1) : url.hash.slice(1)
  for (const params of [url.searchParams, new URLSearchParams(hashQuery)]) {
    for (const value of params.values()) {
      const match = LOOPBACK_CALLBACK.exec(value)
      if (match !== null) return { port: Number(match[1]), path: match[2] ?? '/' }
    }
  }
  // CodeArts 的 portal 只接受 `port`，回调地址由它自己拼成 127.0.0.1。
  if (provider === 'codearts') {
    const port = Number(url.searchParams.get('port'))
    if (Number.isInteger(port) && port > 0) return { port, path: '/oauth/callback' }
  }
  return undefined
}

/** 一实例一 Worker，避免原渠道业务的模块单例串目录、串账号。 */
export async function createChannelRuntime({ dataDir, logger = console, stats }) {
  const worker = new Worker(new URL('./worker.mjs', import.meta.url), {
    workerData: { dataDir },
    execArgv: process.execArgv.filter(arg => !arg.startsWith('--input-type')),
    env: { ...process.env, OFM_CODEARTS_CACHE_DIR: path.join(dataDir, 'channel-pack', 'codearts-cache') },
  })
  const pending = new Map()
  let sequence = 0
  let closed = false
  let closing
  let rows = []
  let providers = []
  const loginPages = new Map()
  const pendingLogins = new Map()
  let refreshing
  let refreshTimer
  let finishClose
  let failed
  let readyResolve, readyReject
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject })
  const rejectAll = error => {
    failed = error
    readyReject(error)
    for (const entry of pending.values()) entry.reject(error)
    pending.clear()
  }
  worker.on('error', rejectAll)
  worker.on('exit', code => {
    if (!closed) rejectAll(new Error(`渠道进程已退出（${code}）`))
    finishClose?.()
  })
  worker.on('message', message => {
    if (message.type === 'ready') { providers = message.providers; readyResolve(); return }
    if (message.type === 'log') { logger[message.level]?.(message.message); return }
    if (message.type === 'closed') { finishClose?.(); return }
    if (message.type === 'changed') {
      if (closed) return
      clearTimeout(refreshTimer)
      refreshTimer = setTimeout(() => { void refresh().catch(error => logger.warn?.(`渠道目录刷新失败：${error.message}`)) }, 200)
      refreshTimer.unref?.()
      return
    }
    const entry = pending.get(message.id)
    if (!entry) return
    if (message.type === 'chunk') {
      try { entry.onChunk?.(message.chunk) } catch (error) { entry.reject(error); worker.postMessage({ type: 'cancel', id: message.id }) }
    } else if (message.type === 'error') entry.reject(Object.assign(new Error(message.message), { statusCode: message.statusCode }))
    else entry.resolve(message.value)
  })
  function call(type, payload = {}, signal, onChunk, timeoutMs = 120000) {
    if (closed || failed) return Promise.reject(failed ?? new Error('渠道已停止'))
    if (signal?.aborted) return Promise.reject(signal.reason ?? new Error('请求已取消'))
    const id = ++sequence
    return new Promise((resolve, reject) => {
      const finish = fn => value => { clearTimeout(timer); signal?.removeEventListener('abort', abort); pending.delete(id); fn(value) }
      const abort = () => {
        worker.postMessage({ type: 'cancel', id })
        entry.reject(signal?.reason ?? new Error('渠道请求超时或已取消'))
      }
      const timer = setTimeout(abort, timeoutMs)
      timer.unref?.()
      const entry = { resolve: finish(resolve), reject: finish(reject), onChunk }
      pending.set(id, entry)
      signal?.addEventListener('abort', abort, { once: true })
      worker.postMessage({ type, id, ...payload })
    })
  }
  function refresh() {
    if (refreshing) return refreshing
    refreshing = call('models').then(value => { rows = value; return rows }).finally(() => { refreshing = undefined })
    return refreshing
  }
  const runtime = {
    get providers() { return providers },
    state() { return { state: failed ? 'failed' : 'ready', error: failed ? failed.message : '' } },
    publicModelRows: () => rows,
    refresh,
    handles: model => providers.some(provider => model.startsWith(`${provider}/`)),
    async rpc(body, signal, publicBase) {
      if (typeof body?.method !== 'string' || !Object.hasOwn(body, 'payload')) throw Object.assign(new Error('渠道请求缺少 method 或 payload'), { statusCode: 400 })
      const result = await call('rpc', { call: { method: body.method, payload: body.payload } }, signal, undefined, 10 * 60000)
      if (typeof publicBase === 'string' && /^https?:\/\//i.test(publicBase)) rewriteLoginUrls(result, publicBase, loginPages)
      if (body.method === 'account.create' && result?.ok === true && typeof result.value?.loginUrl === 'string') {
        const target = callbackTarget(body.payload?.provider, result.value.loginUrl)
        if (target !== undefined && typeof result.value.accountId === 'string') {
          pendingLogins.set(result.value.accountId, { ...target, until: Date.now() + RELAY_MS })
        }
      }
      return result
    },
    /**
     * 把用户从浏览器地址栏复制的回调地址转发给仍在等待的回环回调服务。
     * 只接受与本次登录端口、路径完全一致的回环地址，避免变成任意本机端口代理。
     */
    async relayLoginCallback({ accountId, url } = {}) {
      const now = Date.now()
      for (const [id, entry] of pendingLogins) if (entry.until <= now) pendingLogins.delete(id)
      const entry = pendingLogins.get(accountId)
      if (entry === undefined) throw Object.assign(new Error('没有等待中的登录，请先在渠道页重新发起登录'), { statusCode: 409 })
      let target
      try { target = new URL(String(url)) } catch { throw Object.assign(new Error('回调地址不是有效链接'), { statusCode: 400 }) }
      const host = target.hostname.toLowerCase()
      if (!/^https?:$/.test(target.protocol) || (host !== '127.0.0.1' && host !== 'localhost' && host !== '[::1]' && host !== '::1')) {
        throw Object.assign(new Error('回调地址必须指向 127.0.0.1 或 localhost'), { statusCode: 400 })
      }
      if (Number(target.port) !== entry.port || !target.pathname.startsWith(entry.path)) {
        throw Object.assign(new Error('回调地址与本次登录不匹配，请重新发起登录'), { statusCode: 400 })
      }
      return await new Promise((resolve, reject) => {
        const request = http.request({
          host: '127.0.0.1', port: entry.port, method: 'GET',
          path: `${target.pathname}${target.search}`,
          headers: { host: `127.0.0.1:${entry.port}` },
        }, answer => {
          const chunks = []
          let bytes = 0
          answer.on('data', chunk => { if (bytes < 4096) { chunks.push(chunk); bytes += chunk.length } })
          answer.on('error', error => reject(Object.assign(new Error(`回调转发失败：${error.message}`), { statusCode: 502 })))
          answer.on('end', () => {
            // 回调服务已消费这条链接；转发失败时保留记录，允许用正确地址重试。
            pendingLogins.delete(accountId)
            resolve({
              status: answer.statusCode ?? 0,
              body: Buffer.concat(chunks).toString('utf8').slice(0, 2000),
            })
          })
        })
        request.setTimeout(30_000, () => request.destroy(new Error('回调处理超时')))
        request.on('error', error => reject(Object.assign(new Error(`回调转发失败：${error.message}`), { statusCode: 502 })))
        request.end()
      })
    },
    /** 主监听器据此把登录页请求转发到渠道临时起的回环服务。 */
    loginTarget(pathname) {
      const now = Date.now()
      for (const [prefix, entry] of loginPages) if (entry.until <= now) loginPages.delete(prefix)
      for (const [prefix, entry] of loginPages) if (pathname.startsWith(prefix)) return entry
      return undefined
    },
    async complete(request, onChunk) {
      const outcome = { text: '', toolCalls: [], usage: undefined, truncated: false, error: undefined }
      const started = Date.now()
      let first = 0
      let ok = false
      try {
        const { signal, ...wire } = request
        await call('complete', { request: wire }, signal, chunk => {
          if (!first) first = Date.now()
          foldForwardOutcome(outcome, chunk)
          onChunk?.(chunk)
        }, 30 * 60000)
        ok = outcome.error === undefined
        return outcome
      } finally {
        if (!closed && stats) {
          const usage = outcome.usage
          recordUsage(stats, {
            model: request.model, at: Date.now(), input: usage?.prompt_tokens ?? 0, output: usage?.completion_tokens ?? 0,
            reasoning: usage?.completion_tokens_details?.reasoning_tokens ?? 0, cacheRead: usage?.prompt_tokens_details?.cached_tokens ?? 0,
            ok, origin: 'forward', ttftMs: first ? first - started : undefined,
            decodeMs: first ? Date.now() - first : 0, decodeTokens: usage?.completion_tokens ?? 0,
            noUsage: usage === undefined, elapsedMs: Date.now() - started, aborted: request.signal?.aborted === true,
          })
          recordTurn(stats, { model: request.model, ok, recovered: false })
        }
      }
    },
    close() {
      if (closing) return closing
      closed = true
      loginPages.clear()
      pendingLogins.clear()
      clearTimeout(refreshTimer)
      rejectAll(new Error('渠道正在停止'))
      closing = (async () => {
        let timer
        await new Promise(resolve => {
          finishClose = resolve
          worker.postMessage({ type: 'close' })
          timer = setTimeout(resolve, 1500)
        })
        clearTimeout(timer)
        await worker.terminate()
      })()
      return closing
    },
  }
  try {
    const timeout = setTimeout(() => readyReject(new Error('渠道初始化超时')), 30000)
    try { await ready } finally { clearTimeout(timeout) }
    runtime.ready = refresh().catch(error => { if (!closed) logger.warn?.(`渠道启动清单刷新失败：${error.message}`) })
    return runtime
  } catch (error) { await runtime.close(); throw error }
}
