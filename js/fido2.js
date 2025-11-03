// public/js/fido2.js — 等价优化版（保持对外接口不变，增强健壮性与可读性）

/* ===================== 配置与常量 ===================== */

// RP_ID：默认使用当前域名；如需强绑定线上域，在此兜底
const PROD_HOST = 'lucas556.github.io';
export const RP_ID   = (location.hostname === PROD_HOST) ? PROD_HOST : location.hostname;
export const RP_NAME = 'HD Wallet Init';
const USERNAME      = 'wallet-user';

// WebAuthn 超时
const GET_TIMEOUT    = 60_000;
const CREATE_TIMEOUT = 120_000;

// 本地存储键（仅存放 cred rawId 的 hex）
const CRED_STORAGE_KEY = 'fido2_cred';

// HKDF info 常量（派生 AES-256-GCM 用）
const HKDF_INFO = 'wallet-priv-bundle-v1';

// 统一编码器
const te = new TextEncoder();
const td = new TextDecoder();

/* ===================== 工具函数 ===================== */

export function loadCredHex() {
  try { return localStorage.getItem(CRED_STORAGE_KEY) || null; } catch { return null; }
}
export function saveCredHex(hex) {
  try { localStorage.setItem(CRED_STORAGE_KEY, String(hex)); } catch {}
}
export function clearCredHex() {
  try { localStorage.removeItem(CRED_STORAGE_KEY); } catch {}
}

function ab2hex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
function hex2ab(hex) {
  const s = String(hex).replace(/^0x/i, '').replace(/\s+/g, '');
  if (s.length % 2) throw new TypeError('hex length must be even');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out.buffer;
}
function toU8(input) {
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer);
  if (typeof input === 'string') return new Uint8Array(hex2ab(input));
  throw new TypeError('expect hex string or (ArrayBuffer|TypedArray)');
}
function toHex(u8) {
  const a = (u8 instanceof Uint8Array) ? u8 : new Uint8Array(u8);
  let s = '';
  for (const x of a) s += x.toString(16).padStart(2, '0');
  return s;
}
function explain(e) {
  const s = (e && (e.message || e.name)) || String(e);
  if (/not allowed|abort|timeout|operation timed/i.test(s)) return '用户取消或操作超时';
  if (/prf/i.test(s)) return '此浏览器或安全钥匙不支持 WebAuthn PRF';
  if (/unsupported/i.test(s)) return '浏览器不支持 WebAuthn';
  return s;
}

/* ===================== WebAuthn 安全封装 ===================== */

async function safeCredentialsGet(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.get) {
    throw new Error('WebAuthn not supported in this browser.');
  }
  const copy = { ...opts };
  if (copy && 'mediation' in copy) delete copy.mediation; // 兼容部分 UA
  return navigator.credentials.get(copy);
}

async function safeCredentialsCreate(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.create) {
    throw new Error('WebAuthn not supported in this browser.');
  }
  return navigator.credentials.create(opts);
}

/* ===================== 静默探测：可发现凭证 ===================== */
/** 静默探测本域的 discoverable credential，成功返回 hex，失败/无返回 null */
export async function discoverCredentialHex() {
  const cached = loadCredHex();
  if (cached) return cached;
  try {
    const cred = await safeCredentialsGet({
      publicKey: {
        rpId: RP_ID,
        userVerification: 'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: GET_TIMEOUT
        // 不设 allowCredentials：让设备枚举 discoverable 凭证
      }
    });
    if (cred?.rawId) {
      const hex = ab2hex(cred.rawId);
      saveCredHex(hex);
      return hex;
    }
  } catch {
    // 忽略所有异常，表示没有
  }
  return null;
}

/* ===================== 注册新凭证（可发现 + PRF 探测） ===================== */
export async function registerNewCredential() {
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const publicKey = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USERNAME, displayName: USERNAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -8 },   // Ed25519
      { type: 'public-key', alg: -257 }  // RS256
    ],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    timeout: CREATE_TIMEOUT,
    attestation: 'none',
    // 仅用于探测 PRF 支持（设备可忽略）
    extensions: { prf: { eval: { first: new Uint8Array(32).buffer } } }
  };
  let cred;
  try {
    cred = await safeCredentialsCreate({ publicKey });
  } catch (e) {
    throw new Error(explain(e));
  }
  if (!cred?.rawId) throw new Error('credential create failed');
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { created: true, id_hex: idHex };
}

/* ===================== 有则用，无则注册（UI 交互版） ===================== */
export async function ensureCredentialWithChoice() {
  // 1) 先用缓存
  const cached = loadCredHex();
  if (cached) return { ok: true, id_hex: cached, created: false };

  // 2) 静默探测
  const found = await discoverCredentialHex();
  if (found) {
    const useExisting = confirm(
      `检测到本域已有凭证（${found.slice(0, 16)}…）。\n是否使用该凭证？\n取消 = 注册新的。`
    );
    if (useExisting) return { ok: true, id_hex: found, created: false };
    // 用户选择注册新凭证
    clearCredHex();
  }

  // 3) 注册新凭证
  const reg = await registerNewCredential();
  return { ok: true, id_hex: reg.id_hex, created: true };
}

/* ===================== PRF → HKDF → AES-GCM Key ===================== */

async function prfToAesKey(prfBytes, saltU8, infoStr = HKDF_INFO) {
  // prfBytes: ArrayBuffer (32 bytes)
  const keyMaterial = await crypto.subtle.importKey('raw', prfBytes, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltU8, info: te.encode(infoStr) },
    keyMaterial, 256
  );
  return crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/* ===================== 用“已知盐”派生 KEK（解锁时用） ===================== */
export async function deriveKEKWithSalt(credHex, salt, info = HKDF_INFO) {
  const saltU8 = toU8(salt);
  const saltBuf = saltU8.buffer; // 有些 UA 要求 ArrayBuffer
  const credId = credHex || loadCredHex();
  if (!credId) throw new Error('No credential available.');

  let cred;
  try {
    cred = await safeCredentialsGet({
      publicKey: {
        rpId: RP_ID,
        userVerification: 'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        allowCredentials: [{ type: 'public-key', id: hex2ab(credId) }],
        timeout: GET_TIMEOUT,
        extensions: { prf: { eval: { first: saltBuf } } } // 关键：传 ArrayBuffer
      }
    });
  } catch (e) {
    throw new Error(explain(e));
  }

  const ext = (typeof cred.getClientExtensionResults === 'function')
    ? cred.getClientExtensionResults()
    : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) throw new Error('This authenticator or browser does not support WebAuthn PRF.');

  const kek = await prfToAesKey(prfRes, saltU8, info);
  return { kek, rp_id: RP_ID, info, credential_id: credId };
}

/* ===================== 随机盐派生 KEK（生成时用） ===================== */
export async function deriveKEK({ autoRegister = true, info = HKDF_INFO } = {}) {
  let credHex = loadCredHex();
  if (!credHex) {
    if (autoRegister) {
      const { id_hex } = await ensureCredentialWithChoice();
      credHex = id_hex;
    } else {
      credHex = await discoverCredentialHex();
      if (!credHex) throw new Error('No credential available.');
    }
  }
  const salt = crypto.getRandomValues(new Uint8Array(32));        // 生成随机 salt（需上层保存）
  const { kek } = await deriveKEKWithSalt(credHex, salt, info);   // 走统一派生逻辑
  return {
    kek,
    salt,                           // Uint8Array
    rp_id: RP_ID,
    info,
    credential_id: credHex,
    toHex                            // 便于上层保存 salt/nonce/ciphertext
  };
}

/* ===================== AES-GCM 字符串加/解密 ===================== */

export async function aesGcmEncryptStr(key, text) {
  if (!text) return null;
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, te.encode(text));
  return { nonce: toHex(iv), ciphertext: toHex(new Uint8Array(ct)) };
}

export async function aesGcmDecryptStr(key, { nonce, ciphertext }) {
  const iv = toU8(nonce);
  const ct = toU8(ciphertext);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return td.decode(pt);
}
