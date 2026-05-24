import { connect } from 'cloudflare:sockets';

const CFG = {
  pw: 'test123',
  method: 'aes-256-gcm',
  proxyIP: 'ProxyIP.HK.CMLiussss.net',
  maxChunk: 0x3fff
};

const enc = new TextEncoder();
const dec = new TextDecoder();

const METHODS = {
  'none': { key: 0, salt: 0, none: true },
  'aes-128-gcm': { key: 16, salt: 16 },
  'aes-192-gcm': { key: 24, salt: 24 },
  'aes-256-gcm': { key: 32, salt: 32 },
  'chacha20-ietf-poly1305': { key: 32, salt: 32 }
};

const INFO = METHODS[CFG.method];
if (!INFO) throw new Error('Unsupported cipher');

const concat = (...arrs) => {
  const len = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
};

const u16 = (b, o = 0) => (b[o] << 8) | b[o + 1];

const put16 = (b, o, v) => {
  b[o] = (v >> 8) & 255;
  b[o + 1] = v & 255;
};

async function evpBytesToKey(password, keyLen) {
  const pass = enc.encode(password);
  let key = new Uint8Array(0);
  let prev = new Uint8Array(0);

  while (key.length < keyLen) {
    const input = new Uint8Array(prev.length + pass.length);
    input.set(prev);
    input.set(pass, prev.length);

    prev = new Uint8Array(
      await crypto.subtle.digest('MD5', input)
    );

    key = concat(key, prev);
  }

  return key.slice(0, keyLen);
}

async function hkdf(key, salt, info, len) {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    key,
    'HKDF',
    false,
    ['deriveBits']
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-1',
      salt,
      info
    },
    keyMaterial,
    len * 8
  );

  return new Uint8Array(bits);
}

class AEAD {
  constructor(key) {
    this.key = key;
    this.nonce = new Uint8Array(12);
    this.cryptoKey = null;
  }

  async init() {
    this.cryptoKey = await crypto.subtle.importKey(
      'raw',
      this.key,
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
  }

  increment() {
    for (let i = this.nonce.length - 1; i >= 0; i--) {
      this.nonce[i]++;
      if (this.nonce[i] !== 0) break;
    }
  }

  async encrypt(data) {
    const out = new Uint8Array(
      await crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: this.nonce,
          tagLength: 128
        },
        this.cryptoKey,
        data
      )
    );

    this.increment();
    return out;
  }

  async decrypt(data) {
    try {
      const out = new Uint8Array(
        await crypto.subtle.decrypt(
          {
            name: 'AES-GCM',
            iv: this.nonce,
            tagLength: 128
          },
          this.cryptoKey,
          data
        )
      );

      this.increment();
      return out;
    } catch {
      return null;
    }
  }
}

class Shadowsocks {
  constructor() {
    this.masterKey = null;
    this.encoder = null;
    this.decoder = null;
    this.buffer = new Uint8Array(0);
    this.payloadLength = -1;
  }

  async init() {
    if (!INFO.none) {
      this.masterKey = await evpBytesToKey(CFG.pw, INFO.key);
    }
  }

  async createEncoder() {
    const salt = crypto.getRandomValues(new Uint8Array(INFO.salt));

    const subkey = await hkdf(
      this.masterKey,
      salt,
      enc.encode('ss-subkey'),
      INFO.key
    );

    this.encoder = new AEAD(subkey);
    await this.encoder.init();

    return salt;
  }

  async createDecoder(salt) {
    const subkey = await hkdf(
      this.masterKey,
      salt,
      enc.encode('ss-subkey'),
      INFO.key
    );

    this.decoder = new AEAD(subkey);
    await this.decoder.init();
  }

  async encrypt(data) {
    if (INFO.none) return data;

    let prefix = new Uint8Array(0);

    if (!this.encoder) {
      prefix = await this.createEncoder();
    }

    const chunks = [];

    for (let i = 0; i < data.length; i += CFG.maxChunk) {
      const chunk = data.subarray(i, i + CFG.maxChunk);

      const lenBuf = new Uint8Array(2);
      put16(lenBuf, 0, chunk.length);

      const [encLen, encChunk] = await Promise.all([
        this.encoder.encrypt(lenBuf),
        this.encoder.encrypt(chunk)
      ]);

      chunks.push(encLen, encChunk);
    }

    return concat(prefix, ...chunks);
  }

  async decrypt(data) {
    this.buffer = concat(this.buffer, data);

    const out = [];

    if (!this.decoder) {
      if (this.buffer.length < INFO.salt) {
        return { chunks: [] };
      }

      const salt = this.buffer.slice(0, INFO.salt);
      this.buffer = this.buffer.slice(INFO.salt);

      await this.createDecoder(salt);
    }

    while (true) {
      if (this.payloadLength < 0) {
        if (this.buffer.length < 18) break;

        const encLen = this.buffer.slice(0, 18);
        const lenBuf = await this.decoder.decrypt(encLen);

        if (!lenBuf) {
          return { error: true, chunks: out };
        }

        this.payloadLength = u16(lenBuf);
        this.buffer = this.buffer.slice(18);
      }

      const packetLen = this.payloadLength + 16;

      if (this.buffer.length < packetLen) break;

      const encPayload = this.buffer.slice(0, packetLen);

      const payload = await this.decoder.decrypt(encPayload);

      if (!payload) {
        return { error: true, chunks: out };
      }

      out.push(payload);

      this.buffer = this.buffer.slice(packetLen);
      this.payloadLength = -1;
    }

    return { chunks: out };
  }
}

function parseAddress(data) {
  if (!data?.length) return null;

  const type = data[0];

  if (type === 1) {
    if (data.length < 7) return null;

    return {
      host: `${data[1]}.${data[2]}.${data[3]}.${data[4]}`,
      port: u16(data, 5),
      offset: 7
    };
  }

  if (type === 3) {
    const len = data[1];

    if (data.length < len + 4) return null;

    return {
      host: dec.decode(data.slice(2, 2 + len)),
      port: u16(data, 2 + len),
      offset: len + 4
    };
  }

  if (type === 4) {
    if (data.length < 19) return null;

    const parts = [];

    for (let i = 0; i < 8; i++) {
      parts.push(
        ((data[1 + i * 2] << 8) | data[2 + i * 2]).toString(16)
      );
    }

    return {
      host: parts.join(':'),
      port: u16(data, 17),
      offset: 19
    };
  }

  return null;
}

async function handleWebSocket(ws) {
  const ss = new Shadowsocks();
  await ss.init();

  let tcp = null;
  let writer = null;
  let closed = false;
  let connected = false;

  const close = async () => {
    if (closed) return;
    closed = true;

    try {
      writer?.releaseLock();
    } catch {}

    try {
      tcp?.close();
    } catch {}

    try {
      if (ws.readyState === 1) {
        ws.close();
      }
    } catch {}
  };

  ws.addEventListener('message', async evt => {
    if (closed) return;

    try {
      const data = new Uint8Array(evt.data);

      const { chunks, error } = await ss.decrypt(data);

      if (error) {
        await close();
        return;
      }

      for (const chunk of chunks) {
        if (!connected) {
          connected = true;

          const addr = parseAddress(chunk);

          if (!addr) {
            await close();
            return;
          }

          const hostname = CFG.proxyIP || addr.host;

          tcp = connect({
            hostname,
            port: addr.port
          });

          await tcp.opened;

          writer = tcp.writable.getWriter();

          const payload = chunk.slice(addr.offset);

          if (payload.length) {
            await writer.write(payload);
          }

          (async () => {
            const reader = tcp.readable.getReader();

            try {
              while (true) {
                const { done, value } = await reader.read();

                if (done) break;

                if (!value || ws.readyState !== 1) break;

                const encrypted = await ss.encrypt(value);

                ws.send(encrypted);
              }
            } catch {}
            finally {
              try {
                reader.releaseLock();
              } catch {}

              await close();
            }
          })();
        } else {
          if (writer) {
            await writer.write(chunk);
          }
        }
      }
    } catch {
      await close();
    }
  });

  ws.addEventListener('close', () => {
    close();
  });

  ws.addEventListener('error', () => {
    close();
  });
}

export default {
  async fetch(req) {
    if (req.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();

      const client = pair[0];
      const server = pair[1];

      server.accept();

      handleWebSocket(server).catch(() => {
        try {
          server.close();
        } catch {}
      });

      return new Response(null, {
        status: 101,
        webSocket: client
      });
    }

    return new Response('Hello world!', {
      headers: {
        'Content-Type': 'text/plain;charset=utf-8'
      }
    });
  }
};
