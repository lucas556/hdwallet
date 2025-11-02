// js/fido2.js — 与 init.html 配套的 FIDO2 帮助库（安全兜底版）

const RP_ID     = location.hostname;
const RP_NAME   = 'HD Wallet Init';
const USER_NAME = 'local-user';
const STORAGE_KEY = 'fido2_cred_hex';

export function loadCredHex() { try { return localStorage.getItem(STORAGE_KEY) || null; } catch { return null; } }
export function saveCredHex(hex) { try { localStorage.setItem(STORAGE_KEY, hex); } catch {} }
export function clearCredHex() { try { localStorage.removeItem(STORAGE_KEY); } catch {} }

const enc = new TextEncoder();
const dec = new TextDecoder();

function ab2hex(buf){ const b=new Uint8Array(buf); let s=''; for(const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function hex2ab(hex){
  const s = (hex||'').replace(/^0x/i,'');
  if (s.length % 2) throw new Error('hex length must be even');
  const out=new Uint8Array(s.length/2);
  for(let i=0;i<out.length;i++) out[i]=parseInt(s.slice(i*2,i*2+2),16);
  return out.buffer;
}

async function safeCredentialsGet(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.get) {
    throw new Error('This browser does not support WebAuthn (navigator.credentials.get).');
  }
  // 某些浏览器不认识 mediation，删除以避免 TypeError
  if (opts && 'mediation' in opts) delete opts.mediation;
  try { return await navigator.credentials.get(opts); }
  catch (e) { return Promise.reject(e); }
}

async function safeCredentialsCreate(opts) {
  if (!('credentials' in navigator) || !navigator.credentials?.create) {
    throw new Error('This browser does not support WebAuthn (navigator.credentials.create).');
  }
  try { return await navigator.credentials.create(opts); }
  catch (e) { return Promise.reject(e); }
}

/** 让设备枚举“可发现凭证”以尝试找到本域下的一个可用凭证 */
async function tryDiscoverExistingCredential() {
  try {
    const cred = await safeCredentialsGet({
      publicKey: {
        rpId: RP_ID,
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        userVerification: 'preferred',
        // 不设 allowCredentials: 让设备弹出列表供选择（discoverable credentials）
        timeout: 60000
      }
    });
    if (cred?.rawId) {
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  } catch {
    // 常见报错如“not registered with this website”或 NotAllowedError：忽略，按无凭证处理
  }
  return null;
}

/** 注册一个新的“可发现凭证”，并测试 PRF 扩展可用性 */
export async function registerNewCredential() {
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    rp:   { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER_NAME, displayName: USER_NAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type: 'public-key', alg: -7   }, // ES256
      { type: 'public-key', alg: -8   }, // Ed25519（部分设备不支持也没关系）
      { type: 'public-key', alg: -257 }  // RS256
    ],
    authenticatorSelection: {
      residentKey: 'required',
      userVerification: 'preferred',
      requireResidentKey: true
    },
    attestation: 'none',
    // 提前声明 PRF，用一个占位 eval，确保设备具备 PRF 能力
    extensions: { prf: { eval: { first: new Uint8Array(32) } } },
    timeout: 60000
  };

  const cred = await safeCredentialsCreate({ publicKey: pubKey });
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { created: true, id_hex: idHex };
}

/** 有则用，无则注册；若发现旧的可提示是否复用 */
export async function ensureCredentialWithChoice() {
  // 1) 缓存有的话直接用
  const cached = loadCredHex();
  if (cached) return { ok: true, id_hex: cached, created: false };

  // 2) 尝试发现一个可用的旧凭证
  const found = await tryDiscoverExistingCredential();
  if (found) {
    const useExisting = confirm(`检测到本域已有凭证（${found.slice(0,16)}…）。\n是否使用该凭证？\n取消 = 注册新的。`);
    if (useExisting) return { ok: true, id_hex: found, created: false };
    clearCredHex();
  }

  // 3) 注册一个新的
  const reg = await registerNewCredential();
  return { ok: true, id_hex: reg.id_hex, created: true };
}

/** 使用给定 cred id + salt + info，从 FIDO2 PRF 经过 HKDF 派生出 AES-GCM KEK */
async function deriveKEKWithIdHex(credHex, saltU8, infoStr) {
  const cred = await safeCredentialsGet({
    publicKey: {
      rpId: RP_ID,
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      userVerification: 'preferred',
      allowCredentials: [{ type: 'public-key', id: hex2ab(credHex) }],
      timeout: 60000,
      extensions: { prf: { eval: { first: saltU8 } } }
    }
  });

  // 读取扩展结果（不同浏览器存在差异）
  const ext = typeof cred.getClientExtensionResults === 'function'
    ? cred.getClientExtensionResults()
    : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) {
    throw new Error('This security key does not support WebAuthn PRF (HMAC-Secret).');
  }

  // HKDF 派生 256-bit，然后作为 AES-GCM key（不可导出）
  const keyMaterial = await crypto.subtle.importKey('raw', prfRes, { name: 'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltU8, info: enc.encode(infoStr) },
    keyMaterial, 256
  );
  return crypto.subtle.importKey('raw', new Uint8Array(bits), { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
}

/**
 * 对外：派生 KEK
 * @param {object} opts
 *   - autoRegister: boolean = true   // 没有可用凭证时是否自动注册
 *   - saltHex: 可选，若指定，则复用该 salt（用于解密场景）
 */
export async function deriveKEK({ autoRegister = true, saltHex = null } = {}) {
  const info = 'wallet-priv-bundle-v1';
  const salt = saltHex ? new Uint8Array(hex2ab(saltHex)) : crypto.getRandomValues(new Uint8Array(32));

  let credHex = loadCredHex();
  if (!credHex) {
    if (autoRegister) {
      const res = await ensureCredentialWithChoice();
      credHex = res.id_hex;
    } else {
      credHex = await tryDiscoverExistingCredential();
      if (!credHex) throw new Error('No credential available for this RP ID.');
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
      toHex: (u8)=>[...new Uint8Array(u8)].map(b=>b.toString(16).padStart(2,'0')).join('')
    };
  } catch (e) {
    // 兜底：常见于“not registered”/“InvalidStateError”/“NotAllowedError”
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
        toHex: (u8)=>[...new Uint8Array(u8)].map(b=>b.toString(16).padStart(2,'0')).join('')
      };
    }
    throw e;
  }
}

/** AES-GCM: 明文字符串 → { nonce, ciphertext }(hex) */
export async function aesGcmEncryptStr(key, text) {
  if (!text) return null;
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(text));
  const hex = [...new Uint8Array(ct)].map(b=>b.toString(16).padStart(2,'0')).join('');
  const ivh = [...iv].map(b=>b.toString(16).padStart(2,'0')).join('');
  return { nonce: ivh, ciphertext: hex };
}

/** AES-GCM: {nonce, ciphertext}(hex) → 明文字符串（备用，若后续要解密展示） */
export async function aesGcmDecryptToString(key, obj) {
  if (!obj?.nonce || !obj?.ciphertext) throw new Error('bad ciphertext object');
  const iv = new Uint8Array(hex2ab(obj.nonce));
  const data = new Uint8Array(hex2ab(obj.ciphertext));
  const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  return dec.decode(ptBuf);
}
