// public/js/fido2.js — 完整版（与 init.html 配套）

/* ---------- 常量 & 小工具 ---------- */
export const RP_ID   = "lucas556.github.io";
const RP_NAME = 'HD Wallet Init';
const USER_NAME = 'local-user';
const CACHE_CRED = 'fido2_cred_hex';

const enc = new TextEncoder();
const dec = new TextDecoder();

function ab2hex(buf){ const b=new Uint8Array(buf); let s=''; for (const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function hex2ab(hex){ const s=hex.replace(/^0x/i,''); const out=new Uint8Array(s.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(s.slice(i*2,i*2+2),16); return out.buffer; }

export function loadCredHex(){ try{ return localStorage.getItem(CACHE_CRED)||null; }catch{ return null; } }
export function saveCredHex(h){ try{ localStorage.setItem(CACHE_CRED,h); }catch{} }
export function clearCredHex(){ try{ localStorage.removeItem(CACHE_CRED); }catch{} }

/* ---------- 安全封装的 WebAuthn 调用 ---------- */
async function safeCredentialsGet(opts){
  if (!('credentials' in navigator) || !navigator.credentials?.get)
    throw new Error('WebAuthn not supported in this browser.');
  // 个别旧浏览器不认识 mediation，会抛 TypeError；但多数现代浏览器已支持
  try { return await navigator.credentials.get(opts); }
  catch (e) { throw e; }
}

async function safeCredentialsCreate(opts){
  if (!('credentials' in navigator) || !navigator.credentials?.create)
    throw new Error('WebAuthn not supported in this browser.');
  try { return await navigator.credentials.create(opts); }
  catch (e) { throw e; }
}

/* ---------- 发现已有凭证（可发现/resident） ---------- */
async function tryDiscoverExistingCredential(){
  try{
    const cred = await safeCredentialsGet({
      // 关键：允许“静默发现”，有就返回；无就不打断
      mediation: 'optional',
      publicKey: {
        rpId: RP_ID,
        userVerification: 'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
        // 不填 allowCredentials -> 让浏览器枚举 discoverable credentials
      }
    });
    if (cred?.rawId){
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  }catch(_){ /* 没有就当无 */ }
  return null;
}

/* ---------- 注册新凭证（不要在 create() 里放 PRF） ---------- */
export async function registerNewCredential(){
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    rp:    { id: RP_ID, name: RP_NAME },
    user:  { id: userId, name: USER_NAME, displayName: USER_NAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type:'public-key', alg: -7   }, // ES256
      { type:'public-key', alg: -257 }  // RS256（兜底）
    ],
    authenticatorSelection: {
      residentKey: 'required',
      requireResidentKey: true,
      userVerification: 'preferred'
    },
    attestation: 'none'
    // 注意：PRF 不放在 create()；仅在 get() 时评估
  };

  const cred = await safeCredentialsCreate({ publicKey: pubKey });
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { created:true, id_hex:idHex };
}

/* ---------- 有则用，无则注册 ---------- */
export async function ensureCredentialWithChoice(){
  // 1) 先用缓存
  const cached = loadCredHex();
  if (cached) return { ok:true, id_hex:cached, created:false };

  // 2) 再尝试静默发现
  const found = await tryDiscoverExistingCredential();
  if (found){
    const useExisting = confirm(`检测到本域已有凭证（${found.slice(0,16)}…）。\n是否使用该凭证？\n取消 = 注册新的。`);
    if (useExisting) return { ok:true, id_hex:found, created:false };
    clearCredHex();
  }

  // 3) 找不到就注册
  const reg = await registerNewCredential();
  return { ok:true, id_hex:reg.id_hex, created:true };
}

/* ---------- PRF + HKDF → KEK（支持传入已有 salt） ---------- */
async function deriveKEKWithIdHexAndSalt(credHex, saltU8, infoStr){
  const cred = await safeCredentialsGet({
    publicKey: {
      rpId: RP_ID,
      userVerification: 'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type:'public-key', id: hex2ab(credHex) }],
      timeout: 60000,
      extensions: { prf: { eval: { first: saltU8 } } }
    }
  });

  const ext = typeof cred.getClientExtensionResults === 'function'
    ? cred.getClientExtensionResults() : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) throw new Error('This security key does not support PRF.');

  const material = await crypto.subtle.importKey('raw', prfRes, { name:'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name:'HKDF', hash:'SHA-256', salt: saltU8, info: enc.encode(infoStr) },
    material, 256
  );
  return await crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt','decrypt']);
}

/** 
 * 供 init.html 使用的“带 salt 的 KEK 派生” 
 * @param {Uint8Array} saltU8 - 32字节盐
 * @param {string|null} credHex - 16进制凭证ID（可选）
 * @param {string} infoStr - HKDF info（默认 wallet-priv-bundle-v1）
 */
export async function deriveKEKWithSalt(saltU8, credHex=null, infoStr='wallet-priv-bundle-v1'){
  let idHex = credHex || loadCredHex();
  if (!idHex){
    const res = await ensureCredentialWithChoice();
    idHex = res.id_hex;
  }
  return await deriveKEKWithIdHexAndSalt(idHex, saltU8, infoStr);
}

// 兼容老代码：无参 deriveKEK()，内部随机生成 salt，返回结构与旧版一致
export async function deriveKEK() {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const kek  = await deriveKEKWithSalt(salt);  // 复用我们已经导出的函数
  const toHex = (u8) => [...new Uint8Array(u8)].map(b=>b.toString(16).padStart(2,'0')).join('');
  return {
    kek,
    salt,
    rp_id: RP_ID,
    info: 'wallet-priv-bundle-v1',
    credential_id: loadCredHex() || '',
    toHex
  };
}

/* ---------- AES-GCM（字符串） ---------- */
export async function aesGcmEncryptStr(key, text){
  if (!text) return null;
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, enc.encode(text));
  const hex = [...new Uint8Array(ct)].map(b=>b.toString(16).padStart(2,'0')).join('');
  const ivh = [...iv].map(b=>b.toString(16).padStart(2,'0')).join('');
  return { nonce: ivh, ciphertext: hex };
}

export async function aesGcmDecryptStr(key, nonceHex, ciphertextHex){
  const iv  = new Uint8Array(nonceHex.match(/.{1,2}/g).map(h=>parseInt(h,16)));
  const ct  = new Uint8Array(ciphertextHex.match(/.{1,2}/g).map(h=>parseInt(h,16)));
  const pt  = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return dec.decode(pt);
}
