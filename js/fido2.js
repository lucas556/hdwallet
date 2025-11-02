// js/fido2.js —— FIDO2 PRF + HKDF → AES-GCM（仅导出用到的函数）

const RP_ID   = location.hostname || "lucas556.github.io";
const RP_NAME = 'HD Wallet Init';
const USER    = 'wallet-user';

const te = new TextEncoder();

/* ---------- 工具 ---------- */
function ab2hex(buf){ const b=new Uint8Array(buf); let s=''; for(const x of b) s+=x.toString(16).padStart(2,'0'); return s; }
function hex2ab(hex){ const s = String(hex).replace(/^0x/i,'').replace(/\s+/g,''); const u8=new Uint8Array(s.length/2); for(let i=0;i<u8.length;i++) u8[i]=parseInt(s.slice(i*2,i*2+2),16); return u8.buffer; }
function toU8(x){
  if (x instanceof Uint8Array) return x;
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  if (ArrayBuffer.isView(x)) return new Uint8Array(x.buffer);
  if (typeof x === 'string') return new Uint8Array(hex2ab(x));
  throw new TypeError('expect hex string or (ArrayBuffer|TypedArray)');
}

async function safeGet(opts){
  if (!('credentials' in navigator) || !navigator.credentials?.get) throw new Error('WebAuthn get() not supported');
  if (opts && 'mediation' in opts) delete opts.mediation;
  return navigator.credentials.get(opts);
}
async function safeCreate(opts){
  if (!('credentials' in navigator) || !navigator.credentials?.create) throw new Error('WebAuthn create() not supported');
  return navigator.credentials.create(opts);
}

/* ---------- 注册（可发现凭证，顺便探测 PRF） ---------- */
export async function ensureCredentialWithChoice() {
  // 先尝试让设备枚举已有凭证
  try{
    const cred = await safeGet({
      publicKey:{
        rpId: RP_ID,
        userVerification:'preferred',
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
      }
    });
    if (cred?.rawId) {
      return { ok:true, id_hex: ab2hex(cred.rawId), created:false };
    }
  }catch{ /* ignore */ }

  // 枚举失败则创建一个新的
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER, displayName: USER },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type:'public-key', alg:-7   }, // ES256
      { type:'public-key', alg:-8   }, // Ed25519
      { type:'public-key', alg:-257 }  // RS256
    ],
    authenticatorSelection: { residentKey:'required', userVerification:'preferred' },
    timeout: 120000,
    attestation: 'none',
    // 仅用于探测 PRF 支持（设备可忽略）
    extensions: { prf:{ eval:{ first: new Uint8Array(32).buffer } } }
  };
  const cred = await safeCreate({ publicKey: pubKey });
  if (!cred?.rawId) throw new Error('create credential failed');
  return { ok:true, id_hex: ab2hex(cred.rawId), created:true };
}

/* ---------- PRF → HKDF → AES-GCM Key ---------- */
async function prfToKek(prfBytes, saltU8, infoStr){
  const km = await crypto.subtle.importKey('raw', prfBytes, { name:'HKDF' }, false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name:'HKDF', hash:'SHA-256', salt:saltU8, info:te.encode(infoStr) }, km, 256);
  return crypto.subtle.importKey('raw', new Uint8Array(bits), 'AES-GCM', false, ['encrypt','decrypt']);
}

/* ---------- 直接派生 KEK（生成阶段：随机 salt） ---------- */
export async function deriveKEK() {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const cred = await safeGet({
    publicKey:{
      rpId: RP_ID,
      userVerification:'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: 90000,
      // 不给 allowCredentials：让设备可枚举/新建
      extensions: { prf:{ eval:{ first: salt.buffer } } }
    }
  });

  const ext = typeof cred.getClientExtensionResults==='function' ? cred.getClientExtensionResults() : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) throw new Error('This authenticator/browser does not support WebAuthn PRF.');

  const kek = await prfToKek(prfRes, salt, 'wallet-priv-bundle-v1');
  return {
    kek,
    salt,                                       // Uint8Array(32)
    rp_id: RP_ID,
    info: 'wallet-priv-bundle-v1',
    credential_id: ab2hex(cred.rawId),
    toHex: (u8)=>[...new Uint8Array(u8)].map(b=>b.toString(16).padStart(2,'0')).join('')
  };
}

/* ---------- 用已知 salt 再次派生 KEK（解锁阶段） ---------- */
export async function deriveKEKWithSalt(credHex, saltHexOrU8) {
  const saltU8 = toU8(saltHexOrU8);
  const cred = await safeGet({
    publicKey:{
      rpId: RP_ID,
      userVerification:'preferred',
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      timeout: 90000,
      allowCredentials: [{ type:'public-key', id: hex2ab(credHex) }],
      extensions: { prf:{ eval:{ first: saltU8.buffer } } }
    }
  });

  const ext = typeof cred.getClientExtensionResults==='function' ? cred.getClientExtensionResults() : {};
  const prfRes = ext?.prf?.results?.first;
  if (!prfRes) throw new Error('PRF extension not available.');

  const kek = await prfToKek(prfRes, saltU8, 'wallet-priv-bundle-v1');
  return { kek };
}

/* ---------- AES-GCM 字符串加/解密 ---------- */
export async function aesGcmEncryptStr(key, text){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, te.encode(text));
  return {
    nonce: [...iv].map(b=>b.toString(16).padStart(2,'0')).join(''),
    ciphertext: [...new Uint8Array(ct)].map(b=>b.toString(16).padStart(2,'0')).join('')
  };
}
export async function aesGcmDecryptStr(key, enc){
  const iv = toU8(enc.nonce);
  const ct = toU8(enc.ciphertext);
  const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
  return new TextDecoder().decode(pt);
}
