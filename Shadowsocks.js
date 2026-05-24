import { connect } from 'cloudflare:sockets';

const CFG = {
  pw: 'test123',
  psk: 'YWJjZGVmZ2hpamtsbW5vcA==',
  method: 'aes-256-gcm'
};

// ==================== 模式定义（模式名字清晰） ====================
const MODES = {
  daily: {
    name: "日常模式",           // ← 模式名字
    maxChunk: 0x3fff,           // 16383 字节
    useRandomIP: true
  },
  max: {
    name: "最大模式",           // ← 模式名字
    maxChunk: 0x7fff,           // 32767 字节
    useRandomIP: false
  }
};

const proxyIPs = [
  '1.1.1.1',     // 默认优选IP列表
  '8.8.8.8',
  // '104.16.0.0', // 可继续添加
];

let currentMode = 'daily';
let proxyIP = '';
// =====================================================

const C = {
  none: { k: 16, iv: 0, aead: 0, s: 0, none: 1 },
  plain: { k: 16, iv: 0, aead: 0, s: 0, none: 1 },
  'aes-128-gcm': { k: 16, iv: 16, aead: 1, tag: 16 },
  'aes-192-gcm': { k: 24, iv: 24, aead: 1, tag: 16 },
  'aes-256-gcm': { k: 32, iv: 32, aead: 1, tag: 16 },
  'chacha20-ietf-poly1305': { k: 32, iv: 32, aead: 1, tag: 16, cc: 1 },
  'xchacha20-ietf-poly1305': { k: 32, iv: 32, aead: 1, tag: 16, xc: 1 },
  'chacha20-ietf': { k: 32, iv: 12, s: 1, st: 'cc' },
  'xchacha20': { k: 32, iv: 24, s: 1, st: 'xc' },
  'aes-128-ctr': { k: 16, iv: 16, s: 1, st: 'ctr' },
  'aes-192-ctr': { k: 24, iv: 16, s: 1, st: 'ctr' },
  'aes-256-ctr': { k: 32, iv: 16, s: 1, st: 'ctr' },
  'aes-128-cfb': { k: 16, iv: 16, s: 1, st: 'cfb' },
  'aes-192-cfb': { k: 24, iv: 16, s: 1, st: 'cfb' },
  'aes-256-cfb': { k: 32, iv: 16, s: 1, st: 'cfb' },
  'rc4-md5': { k: 16, iv: 16, s: 1, st: 'rc4' },
  '2022-blake3-aes-128-gcm': { k: 16, iv: 16, aead: 1, tag: 16, b3: 1 },
  '2022-blake3-aes-256-gcm': { k: 32, iv: 32, aead: 1, tag: 16, b3: 1 },
  '2022-blake3-chacha20-poly1305': { k: 32, iv: 32, aead: 1, tag: 16, b3: 1, cc: 1 }
};

const I = C[CFG.method];
const enc = new TextEncoder();
const dec = new TextDecoder();

const evp = async (pw, kl) => {
  const p = enc.encode(pw);
  let k = new Uint8Array(0);
  let pv = new Uint8Array(0);
  while (k.length < kl) {
    const d = new Uint8Array(pv.length + p.length);
    d.set(pv); d.set(p, pv.length);
    pv = new Uint8Array(await crypto.subtle.digest('MD5', d));
    const nk = new Uint8Array(k.length + pv.length);
    nk.set(k); nk.set(pv, k.length);
    k = nk;
  }
  return k.slice(0, kl);
};

const u16be = (d, o) => (d[o] << 8) | d[o + 1];
const put16 = (d, o, v) => { d[o] = (v >> 8) & 255; d[o + 1] = v & 255; };

const cat = (...xs) => {
  const r = new Uint8Array(xs.reduce((n, x) => n + x.length, 0));
  let o = 0;
  for (const x of xs) { r.set(x, o); o += x.length; }
  return r;
};

const parseAddr = d => {
  if (d.length < 1) return null;
  const t = d[0];
  if (t === 1) {
    if (d.length < 7) return null;
    return { h: `\( {d[1]}. \){d[2]}.\( {d[3]}. \){d[4]}`, p: u16be(d, 5), o: 7 };
  } else if (t === 3) {
    const l = d[1];
    if (d.length < 4 + l) return null;
    return { h: dec.decode(d.slice(2, 2 + l)), p: u16be(d, 2 + l), o: 4 + l };
  } else if (t === 4) {
    if (d.length < 19) return null;
    const pts = [];
    for (let i = 0; i < 8; i++) pts.push(((d[1 + i*2] << 8) | d[2 + i*2]).toString(16));
    return { h: `[${pts.join(':')}]`, p: u16be(d, 17), o: 19 };
  }
  return null;
};

class AEAD {
  constructor(key) { this.key = key; this.nonce = new Uint8Array(12); this.ck = null; }
  async init() {
    this.ck = await crypto.subtle.importKey('raw', this.key, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }
  inc() {
    for (let i = 0; i < this.nonce.length; i++) {
      this.nonce[i]++; if (this.nonce[i]) break;
    }
  }
  async enc(d) {
    const c = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: this.nonce, tagLength: 128 }, this.ck, d);
    this.inc();
    return new Uint8Array(c);
  }
  async dec(d) {
    try {
      const p = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: this.nonce, tagLength: 128 }, this.ck, d);
      this.inc();
      return new Uint8Array(p);
    } catch { return null; }
  }
}

class SS {
  constructor() {
    this.mk = null; this.enc = null; this.dec = null;
    this.buf = new Uint8Array(0); this.plen = -1;
  }
  async init() { this.mk = await evp(CFG.pw, I.k); }

  async decData(data) {
    this.buf = cat(this.buf, data);
    const out = [];
    if (!this.dec) {
      if (this.buf.length < I.iv) return { c: [] };
      const salt = this.buf.slice(0, I.iv);
      this.buf = this.buf.slice(I.iv);
      this.dec = new AEAD(cat(this.mk, salt).slice(0, I.k));
      await this.dec.init();
    }
    while (true) {
      if (this.plen < 0) {
        const ls = 2 + I.tag;
        if (this.buf.length < ls) break;
        const lp = await this.dec.dec(this.buf.slice(0, ls));
        if (!lp) return { c: out, e: 'len' };
        this.plen = u16be(lp, 0);
        this.buf = this.buf.slice(ls);
      }
      const ps = this.plen + I.tag;
      if (this.buf.length < ps) break;
      const pp = await this.dec.dec(this.buf.slice(0, ps));
      if (!pp) return { c: out, e: 'pay' };
      out.push(pp);
      this.buf = this.buf.slice(ps);
      this.plen = -1;
    }
    return { c: out };
  }

  async encData(data) {
    let pf = new Uint8Array(0);
    if (!this.enc) {
      const salt = crypto.getRandomValues(new Uint8Array(I.iv));
      this.enc = new AEAD(cat(this.mk, salt).slice(0, I.k));
      await this.enc.init();
      pf = salt;
    }
    const mx = MODES[currentMode].maxChunk;
    const cks = [];
    for (let i = 0; i < data.length; i += mx) {
      const ck = data.subarray(i, Math.min(i + mx, data.length));
      const lb = new Uint8Array(2);
      put16(lb, 0, ck.length);
      cks.push(await this.enc.enc(lb));
      cks.push(await this.enc.enc(ck));
    }
    return cat(pf, ...cks);
  }
}

const handleWS = async ws => {
  const ss = new SS();
  await ss.init();
  let tcp = null, writer = null, connected = false;

  const close = () => {
    writer?.releaseLock().catch(() => {});
    tcp?.close().catch(() => {});
    ws.close().catch(() => {});
  };

  ws.addEventListener('message', async e => {
    try {
      const { c, e: err } = await ss.decData(new Uint8Array(e.data));
      if (err) return close();

      for (const ck of c) {
        if (!connected) {
          connected = true;
          const a = parseAddr(ck);
          if (!a) return close();

          const connectHost = proxyIP || a.h;
          tcp = connect({ hostname: connectHost, port: a.p });
          writer = tcp.writable.getWriter();

          const first = ck.slice(a.o);
          if (first.length) await writer.write(first);

          (async () => {
            try {
              const reader = tcp.readable.getReader();
              while (true) {
                const { value, done } = await reader.read();
                if (done) break;
                if (value?.length) ws.send(await ss.encData(value));
              }
            } catch {}
            close();
          })();
        } else if (writer) {
          await writer.write(ck);
        }
      }
    } catch { close(); }
  });

  ws.addEventListener('close', close);
  ws.addEventListener('error', close);
};

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.toLowerCase();

    // ==================== 路径选择逻辑 ====================
    if (path === '/max' || path === '/maximum') {
      currentMode = 'max';
    } else if (path === '/daily' || path === '/') {
      currentMode = 'daily';
    }

    // 通过路径设置指定 ProxyIP
    if (path.startsWith('/proxy/')) {
      const ip = path.slice(7).trim();
      if (ip === 'clear' || ip === '') {
        proxyIP = '';
      } else {
        proxyIP = ip;
      }
    }
    // =====================================================

    // 环境变量或查询参数优先级更高
    if (env.MODE) currentMode = env.MODE.toLowerCase();
    if (url.searchParams.get('mode')) currentMode = url.searchParams.get('mode').toLowerCase();

    if (!MODES[currentMode]) currentMode = 'daily';

    // 设置 ProxyIP
    if (env.PROXYIP || env.proxyIP) {
      proxyIP = env.PROXYIP || env.proxyIP;
    } else if (proxyIP === '' && MODES[currentMode].useRandomIP && proxyIPs.length > 0) {
      proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
    } else if (proxyIP === '' && !MODES[currentMode].useRandomIP && proxyIPs.length > 0) {
      proxyIP = proxyIPs[0];
    }

    const up = req.headers.get('Upgrade');
    if (up === 'websocket') {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      handleWS(server);
      return new Response(null, { status: 101, webSocket: client });
    }

    // 状态页面显示
    return new Response(
`Shadowsocks Worker Running

当前模式: ${MODES[currentMode].name}
分包大小: ${MODES[currentMode].maxChunk} 字节
ProxyIP: ${proxyIP || '直连'}

使用方法：
/          → 日常模式
/max       → 最大模式
/proxy/1.2.3.4 → 设置指定IP
/proxy/clear   → 清除ProxyIP
?mode=max  → 查询参数切换
`,
      {
        status: 200,
        headers: { 'content-type': 'text/plain;charset=utf-8' }
      }
    );
  }
};
