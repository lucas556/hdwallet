// js/fido2.js —— 与 init.html 对齐的最小实现（PRF→HKDF→AES-GCM）

const RP_ID   = "lucas556.github.io";       // 你的 GitHub Pages 域
const RP_NAME = "HD Wallet Init";
const USER_NAME = "wallet-user";
const CRED_STORAGE_KEY = "fido2_cred";

const te = new TextEncoder();

/* ---------- 本地存/取凭证 id(hex) ---------- */
export function loadCredHex() { try { return localStorage.getItem(CRED_STORAGE_KEY) || null; } catch { return null; } }
export function saveCredHex(hex) { try { localStorage.setItem(CRED_STORAGE_KEY, String(hex)); } catch {} }
export function clearCredHex() { try { localStorage.removeItem(CRED_STORAGE_KEY); } catch {} }

/* ---------- 小工具 ---------- */
function ab2hex(buf){ const b=new Uint8Array(buf); let s=''; for (const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function hex2ab(hex){ const s=String(hex).replace(/^0x/i,'').replace(/\s+/g,''); const out=new Uint8Array(s.length/2); for(let i=0;i<out.length;i++) out[i]=parseInt(s.slice(i*2,i*2+2),16); return out.buffer; }
function toU8(x){ if(x instanceof Uint8Array) return x; if(x instanceof ArrayBuffer) return new Uint8Array(x); if(ArrayBuffer.isView(x)) return new Uint8Array(x.buffer); if(typeof x==='string') return new Uint8Array(hex2ab(x)); throw new TypeError('bad bytes'); }

/* ---------- 安全封装的 WebAuthn ---------- */
async function safeCredentialsGet(opts){
  if(!('credentials' in navigator) || !navigator.credentials?.get) throw new Error('WebAuthn not supported.');
  if (opts && 'mediation' in opts) delete opts.mediation;
  return navigator.credentials.get(opts);
}
async function safeCredentialsCreate(opts){
  if(!('credentials' in navigator) || !navigator.credentials?.create) throw new Error('WebAuthn not supported.');
  return navigator.credentials.create(opts);
}

/* ---------- 枚举可发现凭证（没找到返回 null） ---------- */
async function tryDiscoverExistingCredential() {
  try{
    const cred = await safeCredentialsGet({
      publicKey:{
        rpId: RP_ID,
        userVerification:'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
      }
    });
    if (cred?.rawId) {
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  }catch{}
  return null;
}

/* ---------- 注册一个“可发现”凭证，并探测 PRF ---------- */
export async function ensureCredentialWithChoice() {
  // 先尝试找已有
  const found = await tryDiscoverExistingCredential();
  if (found) { saveCredHex(found); return { ok:true, id_hex:found, created:false }; }

  // 无则注册
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pk = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER_NAME, displayName: USER_NAME },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type:'public-key', alg:-7 },   // ES256
      { type:'public-key', alg:-8 },   // Ed25519
      { type:'public-key', alg:-257 }, // RS256
    ],
    authenticatorSelection: { residentKey:'required', userVerification:'preferred' },
    attestation: 'none',
    timeout: 120000,
    // 仅用于探测 PRF 支持（设备可忽略）
    extensions: { prf: { eval: { first: new Uint8Array(32).buffer } } }
  };
  const cred = await safeCredentialsCreate({ publicKey: pk });
  if (!cred?.rawId) throw new Error('Credential create failed.');
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return { ok:true, id_hex:idHex, created:true };
}

/* ---------- PRF→HKDF→AES-GCM key ---------- */
async function prfToAesKey(prfBytes, saltU8, infoStr){
  const keyMaterial = await crypto.subtle.importKey('raw', prfBytes, { name:'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt:saltU8, info:te.encode(infoStr) }, keyMaterial, 256);
  return crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt','decrypt']);
}

/* ---------- 使用“指定”的 credential + 给定 salt 派生 KEK（强制同一把钥匙） ---------- */
export async function deriveKEKWithSalt(credHex, salt, info='wallet-priv-bundle-v1'){
  if (!credHex) throw new Error('No credential selected.');
  const saltBuf = toU8(salt).buffer; // 有些 UA 只接受 ArrayBuffer
  const cred = await safeCredentialsGet({
    publicKey:{
      rpId: RP_ID,
      userVerification: 'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type:'public-key', id: hex2ab(credHex) }], // 只允许步骤A选择的这把
      timeout: 60000,
      extensions: { prf: { eval: { first: saltBuf } } }
    }
  });
  const ext = typeof cred.getClientExtensionResults==='function' ? cred.getClientExtensionResults() : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) throw new Error('This authenticator/browser does not support WebAuthn PRF.');
  const kek = await prfToAesKey(toU8(prfRes), toU8(salt), info);
  return { kek, rp_id: RP_ID, info, credential_id: credHex };
}

/* ---------- 生成：用“指定的 credential” + 随机 salt 派生 KEK ---------- */
export async function deriveKEKWithNewSaltForCred(credHex, info='wallet-priv-bundle-v1'){
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const base = await deriveKEKWithSalt(credHex, salt, info);
  return { ...base, salt, toHex:(u8)=>[...new Uint8Array(u8)].map(b=>b.toString(16).padStart(2,'0')).join('') };
}

/* ---------- AES-GCM（字符串） ---------- */
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
  const iv = toU8(nonce);
  const ct = toU8(ciphertext);
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}
