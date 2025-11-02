// public/js/fido2.js  — 安全兜底版（不会在模块顶层抛错）
const RP_ID   = location.hostname;
const RP_NAME = 'HD Wallet Init';
const USER_NAME = 'local-user';
const STORAGE_KEY = 'fido2_cred_hex';

export function loadCredHex() { try { return localStorage.getItem(STORAGE_KEY) || null; } catch { return null; } }
export function saveCredHex(hex) { try { localStorage.setItem(STORAGE_KEY, hex); } catch {} }
export function clearCredHex() { try { localStorage.removeItem(STORAGE_KEY); } catch {} }

function ab2hex(buf){ const b=new Uint8Array(buf); let s=''; for(const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function hex2ab(hex){ const s=hex.replace(/^0x/i,''); const out=new Uint8Array(s.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(s.slice(i*2,i*2+2),16); return out.buffer; }
const enc = new TextEncoder();
const dec = new TextDecoder();

// 便捷：hex <-> Uint8Array
function hexToU8(h){ h=h.replace(/^0x/i,''); const u=new Uint8Array(h.length/2); for(let i=0;i<u.length;i++) u[i]=parseInt(h.slice(i*2,i*2+2),16); return u; }
function u8ToHex(u){ return [...u].map(b=>b.toString(16).padStart(2,'0')).join(''); }

async function safeCredentialsGet(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.get) {
    throw new Error('WebAuthn not supported in this browser.');
  }
  if (opts && 'mediation' in opts) delete opts.mediation; // 某些浏览器不认识 mediation
  try { return await navigator.credentials.get(opts); }
  catch (e) { return Promise.reject(e); }
}

async function safeCredentialsCreate(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.create) {
    throw new Error('WebAuthn not supported in this browser.');
  }
  try { return await navigator.credentials.create(opts); }
  catch (e) { return Promise.reject(e); }
}

// 尝试发现已有凭证（失败就返回 null，绝不在顶层 throw）
async function tryDiscoverExistingCredential() {
  try {
    const cred = await safeCredentialsGet({
      publicKey: {
        rpId: RP_ID,
        userVerification: 'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
        // 不设 allowCredentials：让设备枚举可发现凭证
      }
    });
    if (cred && cred.id) {
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  } catch (_) {
    // 可能出现“not registered with this website”等，忽略当作无
  }
  return null;
}

// 注册新凭证（resident key + PRF 探测）
export async function registerNewCredential() {
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER_NAME, displayName: USER_NAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { alg: -7, type: 'public-key' },   // ES256
      { alg: -8, type: 'public-key' },   // Ed25519
      { alg: -257, type: 'public-key' }  // RS256
    ],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    attestation: 'none',
    extensions: { prf: { eval: { first: new Uint8Array(32) } } }
  };
  const cred = await safeCredentialsCreate({ publicKey: pubKey });
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { created: true, id_hex: idHex };
}

// 有则用，无则注册；如发现旧的也可让用户选择新建
export async function ensureCredentialWithChoice() {
  const cached = loadCredHex();
  if (cached) return { ok: true, id_hex: cached, created: false };

  const found = await tryDiscoverExistingCredential();
  if (found) {
    const useExisting = confirm(`检测到本域已有凭证（${found.slice(0,16)}…）。\n是否使用该凭证？\n取消 = 注册新的。`);
    if (useExisting) return { ok: true, id_hex: found, created: false };
    clearCredHex();
  }
  const reg = await registerNewCredential();
  return { ok: true, id_hex: reg.id_hex, created: true };
}

async function deriveKEKWithIdHex(credHex, saltU8, infoStr) {
  const cred = await safeCredentialsGet({
    publicKey: {
      rpId: RP_ID,
      userVerification: 'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: hex2ab(credHex) }],
      timeout: 60000,
      extensions: { prf: { eval: { first: saltU8 } } }
    }
  });

  const getExt = typeof cred.getClientExtensionResults === 'function'
    ? cred.getClientExtensionResults()
    : {};
  const prfRes = getExt?.prf?.results?.first;
  if (!prfRes) throw new Error('This security key does not support PRF.');

  const keyMaterial = await crypto.subtle.importKey('raw', prfRes, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltU8, info: enc.encode(infoStr) },
    keyMaterial, 256
  );
  const kek = await crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt','decrypt']);
  return kek;
}

/**
 * deriveKEK({ autoRegister = true, saltHex? })
 * - 默认生成随机 salt；传入 saltHex 可复用既有盐（例如解密已存密文）
 */
export async function deriveKEK({ autoRegister = true, saltHex = null } = {}) {
  const info = 'wallet-priv-bundle-v1';
  const salt = saltHex ? hexToU8(saltHex) : crypto.getRandomValues(new Uint8Array(32));

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
      kek, salt, rp_id: RP_ID, info, credential_id: credHex,
      toHex: u8ToHex
    };
  } catch (e) {
    const msg = (e && (e.message || e.name || '')) + '';
    const likelyNotRegistered = /not\s*registered|invalidstate|notallowed/i.test(msg);
    if (autoRegister && likelyNotRegistered) {
      clearCredHex();
      const reg = await registerNewCredential();
      const kek = await deriveKEKWithIdHex(reg.id_hex, salt, info);
      return {
        kek, salt, rp_id: RP_ID, info, credential_id: reg.id_hex,
        toHex: u8ToHex
      };
    }
    throw e;
  }
}

// AES-GCM 加密/解密（字符串）
export async function aesGcmEncryptStr(key, text) {
  if (!text) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  return { nonce: u8ToHex(iv), ciphertext: u8ToHex(new Uint8Array(ct)) };
}

export async function aesGcmDecryptStr(key, { nonce, ciphertext }) {
  if (!ciphertext) return '';
  const iv = hexToU8(nonce);
  const ct = hexToU8(ciphertext);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return dec.decode(pt);
}
