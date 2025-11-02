// js/fido2.js — 与 init.html 对齐的完整版本
// 提供这些导出：
// ensureCredentialWithChoice, deriveKEK, deriveKEKWithSalt,
// aesGcmEncryptStr, aesGcmDecryptStr

const RP_ID   = "lucas556.github.io";
const RP_NAME = 'HD Wallet Init';
const USER_NAME = 'local-user';
const STORAGE_KEY = 'fido2_cred_hex';

const enc = new TextEncoder();
const dec = new TextDecoder();

/* ---------- 小工具 ---------- */
function ab2hex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
function hex2ab(hex) {
  const s = hex.replace(/^0x/i, '');
  if (s.length % 2) throw new Error('bad hex');
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i*2, i*2+2), 16);
  return out.buffer;
}
function hex2u8(hex) { return new Uint8Array(hex2ab(hex)); }
function u8tohex(u8) { return ab2hex(u8.buffer); }

/* ---------- 本地缓存凭证 id（十六进制） ---------- */
export function loadCredHex()  { try { return localStorage.getItem(STORAGE_KEY) || null; } catch { return null; } }
export function saveCredHex(h) { try { localStorage.setItem(STORAGE_KEY, h); } catch {} }
export function clearCredHex() { try { localStorage.removeItem(STORAGE_KEY); } catch {} }

/* ---------- WebAuthn 安全封装 ---------- */
async function safeGet(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.get)
    throw new Error('WebAuthn not supported in this browser.');
  if (opts && 'mediation' in opts) delete opts.mediation;
  return navigator.credentials.get(opts);
}
async function safeCreate(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.create)
    throw new Error('WebAuthn not supported in this browser.');
  return navigator.credentials.create(opts);
}

/* ---------- 发现已有可用凭证（失败返回 null） ---------- */
async function tryDiscoverExistingCredential() {
  try {
    const cred = await safeCredentialsGet({
      publicKey: {
        rpId: RP_ID,
        userVerification: 'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
        // 不设置 allowCredentials：让浏览器枚举“可发现凭证”（resident/discoverable credentials）
      },
      // 这行很关键：允许不打断式发现；没有就返回 null，不会把流程卡死
      mediation: 'optional'
    });
    if (cred && cred.id) {
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  } catch (e) {
    // NotAllowedError / InvalidStateError / NotSupported 都当作“无凭证”
  }
  return null;
}

/* ---------- 注册新凭证（需要支持 PRF） ---------- */
// ===== 注册新凭证（不要在 create() 中放 PRF）=====
export async function registerNewCredential() {
  const userId = crypto.getRandomValues(new Uint8Array(16));

  const pubKey = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER_NAME, displayName: USER_NAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    // 常见算法足够；过多奇怪 alg 反而导致兼容性问题
    pubKeyCredParams: [
      { type: 'public-key', alg: -7   }, // ES256
      { type: 'public-key', alg: -257 }  // RS256（兜底）
    ],
    // 强制 residentKey，才能“可发现”
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'preferred'
    },
    attestation: 'none'
    // 注意：这里不要放 prf 扩展
  };

  const cred = await safeCredentialsCreate({ publicKey: pubKey });
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { created: true, id_hex: idHex };
}

/* ---------- 有则用，无则询问/注册 ---------- */
export async function ensureCredentialWithChoice() {
  // 1) 先用缓存
  const cached = loadCredHex();
  if (cached) return { ok: true, id_hex: cached, created: false };

  // 2) 再尝试“静默发现”已有凭证
  const found = await tryDiscoverExistingCredential();
  if (found) {
    // 给用户一次选择权：用现有还是新建
    const useExisting = confirm(`检测到本域已有凭证（${found.slice(0,16)}…）。\n是否使用该凭证？\n取消 = 注册新的。`);
    if (useExisting) return { ok: true, id_hex: found, created: false };
    clearCredHex();
  }

  // 3) 找不到就自动注册（create），避免“not registered with this website”
  const reg = await registerNewCredential();
  return { ok: true, id_hex: reg.id_hex, created: true };
}

/* ---------- PRF + HKDF 生成 AES-GCM KEK（给定 cred 与 salt） ---------- */
async function deriveKEKWithIdHex(credHex, saltU8, infoStr) {
  const cred = await safeGet({
    publicKey: {
      rpId: RP_ID,
      userVerification: 'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: hex2ab(credHex) }],
      timeout: 60000,
      extensions: { prf: { eval: { first: saltU8 } } }
    }
  });

  const ext = typeof cred.getClientExtensionResults === 'function'
    ? cred.getClientExtensionResults()
    : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) throw new Error('This security key does not support PRF.');

  const keyMat = await crypto.subtle.importKey('raw', prfRes, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltU8, info: enc.encode(infoStr) },
    keyMat, 256
  );
  return crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

/* ---------- 导出：派生新 KEK（随机 salt） ---------- */
export async function deriveKEK({ autoRegister = true } = {}) {
  const info = 'wallet-priv-bundle-v1';
  const salt = crypto.getRandomValues(new Uint8Array(32));

  let credHex = loadCredHex();
  if (!credHex) {
    if (autoRegister) {
      const res = await ensureCredentialWithChoice();
      credHex = res.id_hex;
    } else {
      credHex = await tryDiscoverExistingCredential();
      if (!credHex) throw new Error('No credential available.');
    }
  }

  try {
    const kek = await deriveKEKWithIdHex(credHex, salt, info);
    return {
      kek,
      salt,
      rp_id: RP_ID,
      info,
      credential_id: credHex,
      toHex: (u8) => u8tohex(new Uint8Array(u8))
    };
  } catch (e) {
    const msg = (e && (e.message || e.name || '')) + '';
    const likelyNotRegistered = /not\s*registered|invalidstate|notallowed/i.test(msg);
    if (autoRegister && likelyNotRegistered) {
      clearCredHex();
      const reg = await registerNewCredential();
      const kek = await deriveKEKWithIdHex(reg.id_hex, salt, info);
      return {
        kek,
        salt,
        rp_id: RP_ID,
        info,
        credential_id: reg.id_hex,
        toHex: (u8) => u8tohex(new Uint8Array(u8))
      };
    }
    throw e;
  }
}

/* ---------- 新增导出：使用已知 salt/cred 重新派生 KEK（用于解密时） ---------- */
export async function deriveKEKWithSalt(saltHex, credentialHex) {
  const info = 'wallet-priv-bundle-v1';
  const credHex = credentialHex || loadCredHex();
  if (!credHex) throw new Error('No credential id for KEK re-derivation.');
  const saltU8 = hex2u8(saltHex);
  const kek = await deriveKEKWithIdHex(credHex, saltU8, info);
  return { kek, rp_id: RP_ID, info, credential_id: credHex };
}

/* ---------- AES-GCM 封装（字符串） ---------- */
export async function aesGcmEncryptStr(key, text) {
  if (!text) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  return {
    nonce: u8tohex(iv),
    ciphertext: u8tohex(new Uint8Array(ct))
  };
}

export async function aesGcmDecryptStr(key, ivHex, ctHex) {
  const iv = hex2u8(ivHex);
  const ct = hex2u8(ctHex);
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return dec.decode(ptBuf);
}
