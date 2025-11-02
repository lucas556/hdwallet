// public/js/fido2.js —— 与 init.html 对齐的完整实现（支持 PRF / HKDF / AES-GCM）

const RP_ID   = "lucas556.github.io";
const RP_NAME = 'HD Wallet Init';
const USER_NAME = 'user';
const CRED_STORAGE_KEY = 'fido2_cred_hex';

const te = new TextEncoder();

/* ---------- 小工具 ---------- */
export function loadCredHex() { try { return localStorage.getItem(CRED_STORAGE_KEY) || null; } catch { return null; } }
export function saveCredHex(hex) { try { localStorage.setItem(CRED_STORAGE_KEY, String(hex)); } catch {} }
export function clearCredHex() { try { localStorage.removeItem(CRED_STORAGE_KEY); } catch {} }

function ab2hex(buf){
  const b = new Uint8Array(buf);
  let s=''; for (const x of b) s += x.toString(16).padStart(2,'0'); return s;
}
function hex2ab(hex){
  const s = String(hex).replace(/^0x/i,'').replace(/\s+/g,'');
  if (s.length % 2) throw new TypeError('hex length must be even');
  const out = new Uint8Array(s.length/2);
  for (let i=0;i<out.length;i++) out[i] = parseInt(s.slice(i*2,i*2+2), 16);
  return out.buffer;
}
function toU8(input){
  if (input instanceof Uint8Array) return input;
  if (input instanceof ArrayBuffer) return new Uint8Array(input);
  if (ArrayBuffer.isView(input)) return new Uint8Array(input.buffer);
  if (typeof input === 'string') return new Uint8Array(hex2ab(input));
  throw new TypeError('salt must be hex string or (ArrayBuffer|TypedArray)');
}

/* ---------- 安全封装的 WebAuthn 调用 ---------- */
async function safeCredentialsGet(opts){
  if (!('credentials' in navigator) || !navigator.credentials?.get) {
    throw new Error('WebAuthn not supported in this browser.');
  }
  // 有些 UA 对未知字段很敏感，删除 mediation 以免 TypeError
  if (opts && 'mediation' in opts) delete opts.mediation;
  try { return await navigator.credentials.get(opts); }
  catch (e) { throw e; }
}
async function safeCredentialsCreate(opts){
  if (!('credentials' in navigator) || !navigator.credentials?.create) {
    throw new Error('WebAuthn not supported in this browser.');
  }
  try { return await navigator.credentials.create(opts); }
  catch (e) { throw e; }
}

/* ---------- 尝试发现既有可发现凭证（不会 throw） ---------- */
async function tryDiscoverExistingCredential() {
  try {
    const cred = await safeCredentialsGet({
      publicKey: {
        rpId: RP_ID,
        userVerification: 'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
        // 不设置 allowCredentials: 让设备自行枚举 discoverable credentials
      }
    });
    if (cred && cred.id) {
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  } catch (_) { /* 忽略，表示没找到 */ }
  return null;
}

/* ---------- 注册新凭证（discoverable + PRF 探测） ---------- */
export async function registerNewCredential() {
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pk = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER_NAME, displayName: USER_NAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },   // ES256
      { type: 'public-key', alg: -8 },   // Ed25519
      { type: 'public-key', alg: -257 }  // RS256
    ],
    authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
    timeout: 120000,
    attestation: 'none',
    // 仅用于探测 PRF 支持（设备可忽略）
    extensions: { prf: { eval: { first: new Uint8Array(32).buffer } } }
  };
  const cred = await safeCredentialsCreate({ publicKey: pk });
  if (!cred?.rawId) throw new Error('credential create failed');
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { created: true, id_hex: idHex };
}

/* ---------- 有则用，无则注册 ---------- */
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

/* ---------- PRF → HKDF → AES-GCM key ---------- */
async function prfToAesKey(prfBytes, saltU8, infoStr){
  // prfBytes 是 ArrayBuffer（32字节）
  const keyMaterial = await crypto.subtle.importKey('raw', prfBytes, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltU8, info: te.encode(infoStr) },
    keyMaterial, 256
  );
  return crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt','decrypt']);
}

/* ---------- 用已知盐（hex/U8）派生 KEK：解锁时用 ---------- */
export async function deriveKEKWithSalt(credHex, salt, info = 'wallet-priv-bundle-v1') {
  const saltU8 = toU8(salt);                       // 统一为 U8
  const saltBuf = saltU8.buffer;                   // 某些 UA 只认 ArrayBuffer
  const credId = credHex || loadCredHex();
  if (!credId) throw new Error('No credential available.');

  const cred = await safeCredentialsGet({
    publicKey: {
      rpId: RP_ID,
      userVerification: 'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type: 'public-key', id: hex2ab(credId) }], // ArrayBuffer
      timeout: 60000,
      extensions: { prf: { eval: { first: saltBuf } } }               // 关键：传 ArrayBuffer
    }
  });

  const ext = typeof cred.getClientExtensionResults === 'function'
    ? cred.getClientExtensionResults()
    : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) {
    throw new Error('This authenticator or browser does not support WebAuthn PRF.');
  }
  const kek = await prfToAesKey(prfRes, saltU8, info);
  return { kek, rp_id: RP_ID, info, credential_id: credId };
}

/* ---------- 生成时：随机盐 + 自动（复用/注册） ---------- */
export async function deriveKEK({ autoRegister = true, info = 'wallet-priv-bundle-v1' } = {}) {
  let credHex = loadCredHex();
  if (!credHex) {
    if (autoRegister) {
      const { id_hex } = await ensureCredentialWithChoice();
      credHex = id_hex;
    } else {
      credHex = await tryDiscoverExistingCredential();
      if (!credHex) throw new Error('No credential available.');
    }
  }
  // 生成随机 salt（返回给上层保存）
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const ret = await deriveKEKWithSalt(credHex, salt, info);
  return { ...ret, salt, toHex: (u8) => [...new Uint8Array(u8)].map(b=>b.toString(16).padStart(2,'0')).join('') };
}

/* ---------- AES-GCM 字符串加/解密 ---------- */
export async function aesGcmEncryptStr(key, text){
  if (!text) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, te.encode(text));
  return {
    nonce: [...iv].map(b=>b.toString(16).padStart(2,'0')).join(''),
    ciphertext: [...new Uint8Array(ct)].map(b=>b.toString(16).padStart(2,'0')).join('')
  };
}
export async function aesGcmDecryptStr(key, { nonce, ciphertext }){
  const iv  = toU8(nonce);
  const ct  = toU8(ciphertext);
  const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}
