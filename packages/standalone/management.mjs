import crypto from 'node:crypto'
import fs from 'node:fs'
import http from 'node:http'
import { buildStats } from '../../src/core/stats.js'
import { generateKey } from '../../src/forward.js'
import { structuralRejection } from '../../src/trust.js'
import { openLoginTerminal } from './login-terminal.mjs'
import { publicModelVisibility, validateModelVisibility, isModelHidden } from '../../src/store.js'

const PREFIX = '/api/management'
const BOOTSTRAP_MS = 10 * 60_000
const SESSION_MS = 8 * 60 * 60_000
const MAX_BODY_BYTES = 16 * 1024
const ASSETS = new Map([
  ['/', ['index.html', 'text/html; charset=utf-8']],
])
const SECURITY_HEADERS = {
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'content-security-policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
}

function fail(statusCode, message) {
  return Object.assign(new Error(message), { statusCode })
}

function matches(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string' || expected === '') return false
  const left = Buffer.from(actual)
  const right = Buffer.from(expected)
  return left.length === right.length && crypto.timingSafeEqual(left, right)
}

async function readBody(req, limit = MAX_BODY_BYTES) {
  if (!String(req.headers['content-type'] ?? '').toLowerCase().startsWith('application/json')) {
    throw fail(415, '请求必须使用 application/json')
  }
  let bytes = 0
  const chunks = []
  for await (const chunk of req) {
    bytes += chunk.length
    if (bytes > limit) throw fail(413, '请求内容过大')
    chunks.push(chunk)
  }
  let value
  try { value = JSON.parse(Buffer.concat(chunks).toString('utf8')) } catch { throw fail(400, '请求不是有效 JSON') }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw fail(400, '请求必须是 JSON 对象')
  return value
}

function validateSettings(patch) {
  const visibility = validateModelVisibility(patch)
  const booleans = new Set(['enabled', 'exposeRegionModels', 'streamRecovery', 'standaloneProbe', 'standaloneLanEnabled'])
  const numbers = { probeIntervalMinutes: [1, 1440], defaultMaxTokens: [512, 131072], standaloneLanPort: [0, 65535] }
  const result = {}
  for (const [key, value] of Object.entries(patch)) {
    if (Object.hasOwn(visibility, key)) { result[key] = visibility[key]; continue }
    if (booleans.has(key)) {
      if (typeof value !== 'boolean') throw fail(400, `${key} 必须是布尔值`)
    } else if (Object.hasOwn(numbers, key)) {
      const [min, max] = numbers[key]
      if (!Number.isInteger(value) || value < min || value > max) throw fail(400, `${key} 必须是 ${min} 到 ${max} 的整数`)
    } else throw fail(400, `不支持的设置字段：${key}`)
    result[key] = value
  }
  return result
}

export function managementSettings(value) {
  return {
    ...publicModelVisibility(value),
    enabled: value.enabled !== false,
    exposeRegionModels: value.exposeRegionModels !== false,
    streamRecovery: value.streamRecovery !== false,
    standaloneProbe: value.standaloneProbe === true,
    standaloneLanEnabled: value.standaloneLanEnabled === true,
    standaloneLanPort: value.standaloneLanPort ?? 0,
    probeIntervalMinutes: value.probeIntervalMinutes ?? 15,
    defaultMaxTokens: value.defaultMaxTokens ?? 32768,
  }
}

/** 管理读写要求鉴权；登录恢复仅允许同源页面触发固定本机动作。 */
export function createManagement({ stores, runtime, channels, eac, info, onSettingsChanged, loginTerminal = openLoginTerminal, publicOrigin = null, publicMode = false }) {
  const publicHttps = publicOrigin?.protocol === 'https:'
  const cookieFlags = `HttpOnly; SameSite=Strict${publicHttps ? '; Secure' : ''}`
  // 登录弹窗页（/raccoon/*、/wechat/*）由渠道在回环端口上渲染、经主监听器转发，
  // 不在 /api/management 之下；Cookie 必须覆盖全站，弹窗与页内轮询才带得上会话。
  const cookiePath = '/'
  const expectedOrigin = req => {
    if (publicOrigin !== null) return new URL(`${publicHttps ? 'https' : 'http'}://${req.headers.host}`).origin
    if (publicMode) {
      const proto = String(req.headers['x-forwarded-proto'] ?? '').split(',')[0].trim().toLowerCase()
      return new URL(`${proto === 'https' ? 'https' : 'http'}://${req.headers.host}`).origin
    }
    return new URL(`http://${req.headers.host}`).origin
  }
  let bootstrap = { token: crypto.randomBytes(32).toString('base64url'), until: Date.now() + BOOTSTRAP_MS }
  const sessions = new Map()
  let cookieName
  let closed = false
  let terminalOpening = false
  let terminalOpenedAt = null
  const loginPlatform = process.platform === 'darwin' ? 'macos' : process.platform === 'win32' ? 'windows' : 'unsupported'
  const assets = new Map([...ASSETS].map(([url, [file, type]]) => [
    url, { type, body: file === 'index.html'
      ? Buffer.from(fs.readFileSync(new URL(`./web/${file}`, import.meta.url), 'utf8')
        .replace('data-login-platform="unsupported"', `data-login-platform="${loginPlatform}"`))
      : fs.readFileSync(new URL(`./web/${file}`, import.meta.url)) },
  ]))
  // 只公开构建清单中经过路径校验的 JS/CSS，绝不按请求路径读取磁盘。
  const manifest = JSON.parse(fs.readFileSync(new URL('./web/assets.json', import.meta.url), 'utf8'))
  if (!Array.isArray(manifest) || manifest.some(name => typeof name !== 'string' || !/^[\w-]+\.(js|css)$/.test(name))) {
    throw new Error('独立端资源清单无效')
  }
  for (const name of manifest) assets.set(`/assets/${name}`, {
    type: name.endsWith('.css') ? 'text/css; charset=utf-8' : 'text/javascript; charset=utf-8',
    body: fs.readFileSync(new URL(`./web/${name}`, import.meta.url)),
  })
  const json = (res, status, payload, headers = {}) => {
    res.writeHead(status, { ...SECURITY_HEADERS, 'content-type': 'application/json; charset=utf-8', ...headers })
    res.end(JSON.stringify(payload))
  }
  const HOP_BY_HOP = new Set(['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'])
  /**
   * 转发渠道登录页。Raccoon / Loomy 的二维码页由渠道在服务端临时起的回环服务
   * 渲染，公网部署时浏览器够不着那个随机端口，只能经主监听器按已登记的前缀转发。
   * 该页面能完成一次账号登录，所以必须已登录管理页；会话 Cookie 是 host-only
   * 且 SameSite=Strict，跨站请求带不上，鉴权本身就挡住了 CSRF。
   */
  const proxyLoginPage = (req, res, port) => new Promise(resolve => {
    const headers = {}
    for (const [name, value] of Object.entries(req.headers)) {
      if (!HOP_BY_HOP.has(name) && name !== 'host') headers[name] = value
    }
    const upstream = http.request({ host: '127.0.0.1', port, path: req.url, method: req.method, headers }, answer => {
      const out = { 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' }
      for (const [name, value] of Object.entries(answer.headers)) {
        if (!HOP_BY_HOP.has(name)) out[name] = value
      }
      res.writeHead(answer.statusCode ?? 502, out)
      answer.pipe(res)
      answer.on('end', resolve)
    })
    upstream.setTimeout(30_000, () => upstream.destroy(new Error('登录页响应超时')))
    upstream.on('error', () => {
      if (!res.destroyed && !res.headersSent) json(res, 502, { error: '登录页面已关闭，请重新发起登录' })
      else res.destroy()
      resolve()
    })
    res.once('close', () => upstream.destroy())
    req.pipe(upstream)
  })
  // 同名 Cookie 可能同时存在多条（例如旧版本 Path=/api/management 的那条），
  // 浏览器按路径长度排序，只读第一条会把过期会话当成未登录，因此逐个检查。
  const cookieValues = req => {
    const name = `${cookieName}=`
    return String(req.headers.cookie ?? '').split(';')
      .map(value => value.trim())
      .filter(value => value.startsWith(name))
      .map(value => value.slice(name.length))
  }
  const clearCookie = () => [
    `${cookieName}=; Path=${cookiePath}; ${cookieFlags}; Max-Age=0`,
    `${cookieName}=; Path=${PREFIX}; ${cookieFlags}; Max-Age=0`,
  ]
  const pruneSessions = () => {
    for (const [id, until] of sessions) if (until <= Date.now()) sessions.delete(id)
  }
  const authenticated = req => {
    const bearer = /^Bearer (.+)$/i.exec(String(req.headers.authorization ?? ''))?.[1]
    if (matches(bearer, stores.settings.get().forwardKey)) return true
    pruneSessions()
    return cookieValues(req).some(id => sessions.has(id))
  }
  const persist = patch => {
    const previous = stores.settings.get()
    stores.settings.update(patch)
    stores.settings.flush()
    if (stores.settings.writeFailed) {
      // 不向页面谎报保存成功；保留原运行配置并由后续写入重试落盘。
      stores.settings.value = previous
      throw fail(500, '无法保存设置，请检查数据目录权限和磁盘空间')
    }
  }
  const summary = req => {
    const state = runtime.state()
    const available = stores.availability.get()
    const routable = new Set(runtime.publicModelRows().map(entry => entry.id))
    return {
      ...info(req),
      channels: channels?.state(),
      eacAuth: eac?.cached(),
      settings: managementSettings(stores.settings.get()),
      catalogSyncedAt: stores.settings.get().catalogSyncedAt ?? 0,
      probedAt: available.at ?? 0,
      catalog: state.catalog.map(entry => ({
        id: entry.id, name: entry.name, channel: entry.channel ?? 'anonymous',
        vision: entry.vision === true, reasoning: entry.reasoning === true || (entry.reasoning !== null && typeof entry.reasoning === 'object'),
        contextWindow: entry.contextWindow ?? entry.context_window, maxOutput: entry.maxOutput ?? entry.max_tokens,
        routable: routable.has(entry.id),
        hiddenByUser: isModelHidden(entry, state.settings),
        hiddenByGroup: isModelHidden(entry, { ...state.settings, hiddenModelIds: [] }),
        availability: entry.channel ? 'listed' : available.results?.[entry.id]?.state ?? 'unknown',
        ttftMs: available.results?.[entry.id]?.ttftMs ?? null,
      })),
    }
  }

  async function route(req, res, pathname) {
    const method = req.method ?? 'GET'
    if (method === 'POST' && pathname === `${PREFIX}/login/terminal`) {
      // 此入口发生在登录前，必须有浏览器的同源 Origin，拒绝跨站和无来源调用。
      if (req.headers.origin !== expectedOrigin(req) ||
          req.headers['sec-fetch-site'] !== 'same-origin') {
        throw fail(403, '请从本机登录页面点击获取令牌')
      }
      const body = await readBody(req)
      if (Object.keys(body).length !== 0) throw fail(400, '获取令牌不接受路径或命令参数')
      if (terminalOpening || (terminalOpenedAt !== null && Date.now() - terminalOpenedAt < 30_000)) {
        throw fail(429, '已请求打开终端，请检查弹出的窗口，30 秒后可重试')
      }
      terminalOpening = true
      try {
        await loginTerminal(info().dataDir)
        terminalOpenedAt = Date.now()
        json(res, 200, { ok: true })
      } finally { terminalOpening = false }
      return
    }
    if (method === 'POST' && pathname === `${PREFIX}/session`) {
      const body = await readBody(req)
      const validBootstrap = bootstrap !== null && bootstrap.until > Date.now() && matches(body.bootstrapToken, bootstrap.token)
      if (!validBootstrap && !matches(body.key, stores.settings.get().forwardKey)) throw fail(401, '登录链接已失效或 API Key 不正确')
      pruneSessions()
      if (sessions.size >= 64) throw fail(429, '管理会话过多，请稍后重试')
      if (validBootstrap) bootstrap = null
      const id = crypto.randomBytes(32).toString('base64url')
      sessions.set(id, Date.now() + SESSION_MS)
      json(res, 200, { ok: true }, {
        'set-cookie': [
          `${cookieName}=${id}; Path=${cookiePath}; ${cookieFlags}; Max-Age=${SESSION_MS / 1000}`,
          `${cookieName}=; Path=${PREFIX}; ${cookieFlags}; Max-Age=0`,
        ],
      })
      return
    }
    if (!authenticated(req)) throw fail(401, '请先登录管理页面')
    if (method === 'POST' && pathname === `${PREFIX}/logout`) {
      await readBody(req)
      for (const id of cookieValues(req)) sessions.delete(id)
      json(res, 200, { ok: true }, { 'set-cookie': clearCookie() })
    } else if (method === 'GET' && pathname === `${PREFIX}/summary`) {
      json(res, 200, summary(req))
    } else if (method === 'GET' && pathname === `${PREFIX}/stats`) {
      json(res, 200, buildStats(stores.stats.get(), runtime.catalog))
    } else if (method === 'POST' && pathname === `${PREFIX}/channels/rpc` && channels) {
      // 渠道备份导入包含多账号凭据，仍限制总大小，但不能套设置表单的 16KB。
      const body = await readBody(req, 8 * 1024 * 1024)
      if (body.method === 'login.callback') {
        // 本机回环回调型登录（CodeArts / LobsterAI / TRAE / Gemini）：
        // 浏览器打不开 127.0.0.1 上的回调，用户把地址栏里那条链接粘贴回来。
        json(res, 200, { ok: true, value: await channels.relayLoginCallback(body.payload) })
      } else if (body.method === 'gateway.getEnabled' || body.method === 'gateway.setEnabled') {
        if (body.method === 'gateway.setEnabled') {
          if (typeof body.payload?.enabled !== 'boolean') throw fail(400, 'enabled 必须是布尔值')
          persist({ enabled: body.payload.enabled })
          await onSettingsChanged()
        }
        const base = new URL(info(req).baseUrl)
        json(res, 200, { ok: true, value: {
          enabled: stores.settings.get().enabled !== false, running: stores.settings.get().enabled !== false,
          blockedByEnv: false, address: { host: base.hostname, port: Number(base.port || (base.protocol === 'https:' ? 443 : 80)) },
          apiKey: { value: stores.settings.get().forwardKey, path: `${info().dataDir}/settings.json`, fromEnv: false },
          models: runtime.publicModelRows(), modelsSource: 'catalog',
        } })
      } else {
        const controller = new AbortController()
        const abort = () => controller.abort()
        res.once('close', abort)
        try { json(res, 200, await channels.rpc(body, controller.signal, info(req).baseUrl)) }
        finally { res.removeListener('close', abort) }
      }
    } else if (eac && pathname.startsWith(`${PREFIX}/eac/`)) {
      const params = new URL(req.url, 'http://localhost').searchParams
      const route = pathname.slice(PREFIX.length)
      let result
      if (method === 'GET' && route === '/eac/status') result = await eac.status()
      else if (method === 'GET' && route === '/eac/login/poll') result = await eac.poll(params.get('link') ?? '')
      else if (method === 'GET' && route === '/eac/pool') result = await eac.pool()
      else if (method === 'POST') {
        await readBody(req)
        if (route === '/eac/login/start') result = await eac.start()
        else if (route === '/eac/login/cancel') result = eac.cancel(params.get('link') ?? '')
        else if (route === '/eac/logout') result = await eac.logout()
      }
      if (result === undefined) throw fail(404, 'EAC 接口不存在')
      if (result.error) throw fail(502, result.error)
      if (result.ok === false) throw fail(500, '无法移除本地授权')
      json(res, 200, result)
    } else if (method === 'POST' && pathname === `${PREFIX}/settings`) {
      const patch = validateSettings(await readBody(req))
      persist(patch)
      await onSettingsChanged()
      json(res, 200, { settings: managementSettings(stores.settings.get()), lan: info().lan })
    } else if (method === 'GET' && pathname === `${PREFIX}/lan/key`) {
      json(res, 200, { key: stores.settings.get().standaloneLanKey ?? '' })
    } else if (method === 'POST' && pathname === `${PREFIX}/lan/key/rotate`) {
      const body = await readBody(req)
      if (body.confirm !== true || Object.keys(body).length !== 1) throw fail(400, 'LAN key rotation requires only confirm: true')
      persist({ standaloneLanKey: generateKey() })
      json(res, 200, { key: stores.settings.get().standaloneLanKey })
    } else if (method === 'GET' && pathname === `${PREFIX}/key`) {
      json(res, 200, { key: stores.settings.get().forwardKey })
    } else if (method === 'POST' && pathname === `${PREFIX}/key/rotate`) {
      const body = await readBody(req)
      if (body.confirm !== true) throw fail(400, '请确认轮换 API Key')
      const kept = cookieValues(req).map(id => [id, sessions.get(id)]).filter(([, until]) => until !== undefined)
      persist({ forwardKey: generateKey() })
      // 仅当前管理会话保留；旧密钥与其他会话立即失效。
      sessions.clear()
      for (const [id, until] of kept) sessions.set(id, until)
      bootstrap = null
      json(res, 200, { key: stores.settings.get().forwardKey })
    } else if (method === 'POST' && pathname === `${PREFIX}/models/refresh`) {
      const body = await readBody(req)
      if (body.probe !== undefined && typeof body.probe !== 'boolean') throw fail(400, 'probe 必须是布尔值')
      await runtime.refreshCatalog({ probe: body.probe === true, force: body.probe === true })
      json(res, 200, summary(req))
    } else if (method === 'POST' && pathname === `${PREFIX}/models/test`) {
      const body = await readBody(req)
      if (stores.settings.get().enabled === false) throw fail(503, '推理服务已暂停，请先在服务设置中启用')
      if (typeof body.model !== 'string' || body.model.length > 300) throw fail(400, '请选择有效模型')
      const controller = new AbortController()
      const abort = () => controller.abort()
      res.once('close', abort)
      const deadline = setTimeout(abort, 60_000)
      deadline.unref?.()
      const started = Date.now()
      try {
        const outcome = await runtime.complete({
          model: body.model, signal: controller.signal,
          openAi: { messages: [{ role: 'user', content: 'Reply with OK.' }], max_tokens: 64 },
        })
        if (outcome.error) throw fail(502, outcome.error)
        json(res, 200, { ok: true, text: outcome.text.slice(0, 2000), latencyMs: Date.now() - started })
      } finally {
        clearTimeout(deadline)
        res.removeListener('close', abort)
      }
    } else throw fail(404, '管理接口不存在')
  }

  return {
    setPort(port) { cookieName = `ofm_management_${port}` },
    get bootstrapFragment() { return bootstrap === null ? '' : `#login=${bootstrap.token}` },
    async handleRequest(req, res) {
      const pathname = new URL(req.url ?? '/', 'http://localhost').pathname
      const asset = assets.get(pathname)
      const isApi = pathname === PREFIX || pathname.startsWith(`${PREFIX}/`)
      const loginPage = !asset && !isApi ? channels?.loginTarget?.(pathname) : undefined
      if (!asset && !isApi && loginPage === undefined) return false
      // 不接受插件专用 dsh-app Referer；独立管理只允许本页面的 HTTP(S) 来源。
      const referer = req.headers.referer
      const origin = req.headers.origin
      const malformedSource = [referer, origin].some(value => value !== undefined && (
        typeof value !== 'string' || !/^https?:\/\//i.test(value)
      ))
      if (closed || !cookieName) json(res, 503, { error: '服务正在停止或启动' })
      // 登录页与静态资源不含任何凭据，从任意来源打开都安全；跨站链接的顶层
      // 导航会带 Sec-Fetch-Site: cross-site，不能因此把登录页挡在门外。
      // 同源围栏只保护管理 API。
      else if (asset) {
        if (req.method !== 'GET' && req.method !== 'HEAD') json(res, 405, { error: '资源仅支持 GET 或 HEAD' })
        else {
          res.writeHead(200, { ...SECURITY_HEADERS, 'content-type': asset.type })
          res.end(req.method === 'HEAD' ? undefined : asset.body)
        }
      } else if (loginPage !== undefined) {
        // 登录弹窗由管理页 window.open 打开，Cookie 已随同源导航送达；
        // 这里不再套 Origin 围栏（弹窗可能带 about:blank Referer），
        // 以 host-only 会话 Cookie 作为唯一判据。
        if (!authenticated(req)) {
          // 旧会话的 Cookie 只覆盖 /api/management，弹窗带不上；把弹窗送回管理页，
          // 重新登录后新的全站 Cookie 才会随弹窗与页内轮询发送。
          res.writeHead(302, { ...SECURITY_HEADERS, location: '/' })
          res.end()
        } else await proxyLoginPage(req, res, loginPage.port)
      } else if (malformedSource ||
        structuralRejection(req, {
          allowPublic: publicMode, trustProxy: publicMode, publicHostname: publicOrigin?.hostname,
        }) !== undefined) {
        json(res, 403, { error: '管理接口仅允许同源访问' })
      } else {
        try { await route(req, res, pathname) } catch (error) {
          if (!res.destroyed && !res.headersSent) json(res, error.statusCode ?? 500, {
            error: error.statusCode ? error.message : '管理操作失败，请查看服务日志',
          })
        }
      }
      return true
    },
    dispose() { closed = true; bootstrap = null; sessions.clear() },
  }
}
