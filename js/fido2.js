// public/js/fido2.js —— 精简对齐版（仅导出被 init.html 使用的函数）

const RP_ID   = location.hostname || "lucas556.github.io";
const RP_NAME = "HD Wallet Init";
const USER    = "wallet-user";
const CRED_KEY = "fido2_cred_id";

const te = new TextEncoder();

/* ---------- 持久化本域凭证 id ---------- */
export function loadCredHex(){ try{ return localStorage.getItem(CRED_KEY) || null; } catch { return null; } }
export function saveCredHex(hex){ try{ localStorage.setItem(CRED_KEY, String(hex)); } catch {} }
export function clearCredHex(){ try{ localStorage.removeItem(CRED_KEY); } catch {} }

/* ---------- 小工具 ---------- */
function ab2hex(buf){ const b=new Uint8Array(buf); let s=""; for(const x of b) s+=x.toString(16).padStart(2,"0"); return s; }
function hex2ab(hex){
  const s=String(hex).replace(/^0x/i,"").replace(/\s+/g,"");
  if(s.length%2) throw new TypeError("hex length must be even");
  const out=new Uint8Array(s.length/2);
  for(let i=0;i<out.length;i++) out[i]=parseInt(s.slice(i*2,i*2+2),16);
  return out.buffer;
}
function toU8(input){
  if(input instanceof Uint8Array) return input;
  if(input instanceof ArrayBuffer) return new Uint8Array(input);
  if(ArrayBuffer.isView(input))   return new Uint8Array(input.buffer);
  if(typeof input==="string")     return new Uint8Array(hex2ab(input));
  throw new TypeError("salt/hex must be ArrayBuffer(View) or hex string");
}

/* ---------- 安全封装 WebAuthn ---------- */
async function safeGet(opts){
  if(!("credentials" in navigator) || !navigator.credentials?.get)
    throw new Error("WebAuthn not supported in this browser.");
  if(opts && "mediation" in opts) delete opts.mediation;
  return navigator.credentials.get(opts);
}
async function safeCreate(opts){
  if(!("credentials" in navigator) || !navigator.credentials?.create)
    throw new Error("WebAuthn not supported in this browser.");
  return navigator.credentials.create(opts);
}

/* ---------- 发现可发现凭证（不抛错） ---------- */
async function tryDiscover(){
  try{
    const cred = await safeGet({
      publicKey:{
        rpId: RP_ID,
        userVerification: "preferred",
        challenge: crypto.getRandomValues(new Uint8Array(32)),
        timeout: 60000
        // 不给 allowCredentials，让设备枚举 discoverable credentials
      }
    });
    if(cred?.rawId){
      const idHex = ab2hex(cred.rawId);
      saveCredHex(idHex);
      return idHex;
    }
  }catch{ /* ignore */ }
  return null;
}

/* ---------- 注册新凭证（discoverable） ---------- */
async function registerNew(){
  const userId = crypto.getRandomValues(new Uint8Array(16));
  const pubKey = {
    rp: { id: RP_ID, name: RP_NAME },
    user: { id: userId, name: USER, displayName: USER },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [
      { type:"public-key", alg:-7 },   // ES256
      { type:"public-key", alg:-8 },   // Ed25519
      { type:"public-key", alg:-257 }  // RS256
    ],
    authenticatorSelection: { residentKey:"required", userVerification:"preferred" },
    attestation: "none",
    timeout: 120000,
    // PRF 探测：设备可能忽略；不影响注册
    extensions: { prf: { eval: { first: new Uint8Array(32).buffer } } }
  };
  const cred = await safeCreate({ publicKey: pubKey });
  if(!cred?.rawId) throw new Error("credential create failed");
  const idHex = ab2hex(cred.rawId);
  saveCredHex(idHex);
  return idHex;
}

/* ---------- 对外：有则用，无则注册 ---------- */
export async function ensureCredentialWithChoice(){
  let id = loadCredHex();
  if(id) return { ok:true, id_hex:id, created:false };

  const found = await tryDiscover();
  if(found){
    const use = confirm(`检测到本域已有凭证（${found.slice(0,16)}…）。\n是否使用该凭证？\n取消 = 注册新的。`);
    if(use){ return { ok:true, id_hex:found, created:false }; }
    clearCredHex();
  }
  id = await registerNew();
  return { ok:true, id_hex:id, created:true };
}

/* ---------- PRF → HKDF → AES-GCM ---------- */
async function prfToAesKey(prfBytes, saltU8, info){
  const hkdf = await crypto.subtle.importKey("raw", prfBytes, { name:"HKDF" }, false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name:"HKDF", hash:"SHA-256", salt:saltU8, info: te.encode(info) },
    hkdf, 256
  );
  return crypto.subtle.importKey("raw", new Uint8Array(bits), "AES-GCM", false, ["encrypt","decrypt"]);
}

/**
 * 用“已知 salt + 指定/缓存的 credential id”派生 AES-GCM key
 * @param {string|null} credHex  指定凭证 id（十六进制）；null 则用本地缓存
 * @param {Uint8Array|ArrayBuffer|string} salt  支持 U8/AB/hex
 * @param {string} info HKDF info
 */
export async function deriveKEKWithSalt(credHex, salt, info="wallet-priv-bundle-v1"){
  const credId = credHex || loadCredHex();
  if(!credId) throw new Error("No credential available.");
  const saltU8  = toU8(salt);
  const saltBuf = saltU8.buffer; // 某些 UA 只认 ArrayBuffer

  const assertion = await safeGet({
    publicKey:{
      rpId: RP_ID,
      userVerification: "preferred",
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      allowCredentials: [{ type:"public-key", id: hex2ab(credId) }],
      timeout: 60000,
      extensions: { prf: { eval: { first: saltBuf } } } // PRF 输入即 salt
    }
  });

  const ext = typeof assertion.getClientExtensionResults==="function"
    ? assertion.getClientExtensionResults() : {};
  const prfRes = ext?.prf?.results?.first;
  if(!prfRes) throw new Error("Authenticator/Browser does not support WebAuthn PRF.");

  const kek = await prfToAesKey(prfRes, saltU8, info);
  return { kek, credential_id: credId };
}

/* ---------- AES-GCM 字符串加/解密 ---------- */
export async function aesGcmEncryptStr(key, text){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, te.encode(text));
  return {
    nonce: [...iv].map(b=>b.toString(16).padStart(2,"0")).join(""),
    ciphertext: [...new Uint8Array(ct)].map(b=>b.toString(16).padStart(2,"0")).join("")
  };
}
export async function aesGcmDecryptStr(key, enc){
  const iv = toU8(enc.nonce);
  const ct = toU8(enc.ciphertext);
  const pt = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt);
}
