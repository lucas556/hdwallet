// js/hdwallet-core.js
// 依赖（单源 ESM，无 FIDO2）
import { generateMnemonic, mnemonicToSeedSync } from 'https://esm.sh/@scure/bip39@1.2.2';
import { wordlist as english } from 'https://esm.sh/@scure/bip39@1.2.2/wordlists/english.js';
import { HDKey } from 'https://esm.sh/ethereum-cryptography@2.1.3/hdkey.js';
import { sha256 } from 'https://esm.sh/@noble/hashes@1.4.0/sha256';
import { ripemd160 } from 'https://esm.sh/@noble/hashes@1.4.0/ripemd160';
import { bech32 } from 'https://esm.sh/bech32@2.0.0';
import bs58check from 'https://esm.sh/bs58check@3.0.1';

export const HARDENED = 0x80000000 >>> 0;

// 版本常量（主网）
export const VERSION = {
  xpub: 0x0488B21E, xprv: 0x0488ADE4,
  zpub: 0x04b24746, zprv: 0x04b2430c,
};

// 前三层硬化到分支
export const DEFAULT_PATHS = {
  ETH:  "m/44'/60'/0'",
  BTC:  "m/84'/0'/0'",
  EOS:  "m/44'/194'/0'",
  TRON: "m/44'/195'/0'",
};

const toHex = u8 => [...u8].map(b=>b.toString(16).padStart(2,'0')).join('');
const wipeBytes = u8 => { try{ u8?.fill?.(0); }catch{} };

// ----- Base58Check 解析/换版本（xpub/xprv ↔ zpub/zprv） -----
function parseExtKeyBytes(extKey){
  const payload = bs58check.decode(extKey);
  if (payload.length !== 78) throw new Error('扩展密钥 payload 应为 78 字节');
  const isPriv = payload[45] === 0x00;
  const isPub  = payload[45] === 0x02 || payload[45] === 0x03;
  if (!isPriv && !isPub) throw new Error('非法扩展密钥');
  return { payload, isPriv, isPub };
}
function safeSwapVersion(extKey, newVer, expect){
  const { payload, isPriv, isPub } = parseExtKeyBytes(extKey);
  if (expect==='pub' && !isPub)  throw new Error('期望公钥扩展，但给了私钥');
  if (expect==='prv' && !isPriv) throw new Error('期望私钥扩展，但给了公钥');
  payload[0]=(newVer>>>24)&0xff; payload[1]=(newVer>>>16)&0xff;
  payload[2]=(newVer>>>8)&0xff;  payload[3]=(newVer>>>0)&0xff;
  return bs58check.encode(payload);
}
const toZpub = xpub => safeSwapVersion(xpub, VERSION.zpub, 'pub');
const toZprv = xprv => safeSwapVersion(xprv, VERSION.zprv, 'prv');

// ----- 路径 -----
export function normalizePath(s){
  let p = String(s||'').trim().replace(/^M\b/,'m').replace(/([0-9])h/gi,"$1'");
  if (!/^m(\/\d+'?)*$/.test(p)) throw new Error('非法路径: ' + s);
  return p;
}
export function deriveByPath(seed, path){
  const p = normalizePath(path);
  let node = HDKey.fromMasterSeed(seed);
  for (const seg of p.split('/').slice(1)){
    const hardened = seg.endsWith("'");
    const idx = parseInt(seg.replace("'",""),10);
    if (!Number.isInteger(idx) || idx<0) throw new Error('路径段非法: ' + seg);
    node = hardened ? node.deriveChild((idx|HARDENED)>>>0) : node.deriveChild(idx);
  }
  return node;
}

// ----- 助记词 -----
export function genMnemonic(strengthBits = 128){
  return generateMnemonic(english, strengthBits, len => {
    const u = new Uint8Array(len); crypto.getRandomValues(u); return u;
  });
}
export const splitWords = m => String(m||'').trim().split(/\s+/).filter(Boolean);
export const mnemonicToSeed = (m, pass='') => mnemonicToSeedSync(m, pass);

// ----- 导出分支（含 xprv/xpub；BTC 用 z* 显示） -----
export function exportBranches(seed, paths=DEFAULT_PATHS){
  const out = {};
  // ETH
  {
    const n = deriveByPath(seed, paths.ETH);
    out.ETH = { path: normalizePath(paths.ETH), xprv: n.privateExtendedKey||null, xpub: n.publicExtendedKey };
  }
  // BTC（显示 zprv/zpub）
  {
    const n = deriveByPath(seed, paths.BTC);
    const xprv = n.privateExtendedKey||null;
    const xpub = n.publicExtendedKey;
    out.BTC = { path: normalizePath(paths.BTC), xprv_z: xprv?toZprv(xprv):null, xpub_z: toZpub(xpub) };
  }
  // EOS
  {
    const n = deriveByPath(seed, paths.EOS);
    out.EOS = { path: normalizePath(paths.EOS), xprv: n.privateExtendedKey||null, xpub: n.publicExtendedKey };
  }
  // TRON
  {
    const n = deriveByPath(seed, paths.TRON);
    out.TRON = { path: normalizePath(paths.TRON), xprv: n.privateExtendedKey||null, xpub: n.publicExtendedKey };
  }
  return out;
}

// -----（可选）离线密码备份：PBKDF2+AES-GCM -----
async function pbkdf2Key(password, salt, iters=200_000){
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), {name:'PBKDF2'}, false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name:'PBKDF2', hash:'SHA-256', salt, iterations: iters},
    base,
    {name:'AES-GCM', length:256},
    false, ['encrypt','decrypt']
  );
}
export async function createPasswordBackupBlob(mnemonic, password){
  const TE = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await pbkdf2Key(password, salt);
  const pt   = TE.encode(mnemonic);
  const ct   = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, pt));
  const payload = {
    version:1, alg:'AES-GCM',
    kdf:{ name:'PBKDF2', hash:'SHA-256', iterations:200000, salt:toHex(salt) },
    iv: toHex(iv),
    ciphertext: btoa(String.fromCharCode(...ct)),
    note:'ciphertext = AES-GCM(mnemonic); not storing mnemonic in cleartext'
  };
  wipeBytes(ct); wipeBytes(pt);
  return { blob:new Blob([JSON.stringify(payload,null,2)],{type:'application/json'}), payload };
}

// 强密码：≥8 且需字母+数字+特殊字符
export function validatePasswordStrict(pw){
  if (typeof pw!=='string' || pw.length<8) return {ok:false, reason:'长度至少 8 位'};
  if (!/[A-Za-z]/.test(pw)) return {ok:false, reason:'需至少 1 个字母'};
  if (!/\d/.test(pw))       return {ok:false, reason:'需至少 1 个数字'};
  if (!/[^A-Za-z0-9]/.test(pw)) return {ok:false, reason:'需至少 1 个特殊字符'};
  return {ok:true, reason:'OK'};
}

// —— BTC bech32（若页面想即时校验地址，可复用）——
export function btcP2WPKHFromXpub(xpubOrZpub, index=0){
  const x = xpubOrZpub.startsWith('zpub') ? (()=>{
    // 把 zpub 还原回 xpub 再走 HDKey
    const raw = bs58check.decode(xpubOrZpub);
    raw[0]=(VERSION.xpub>>>24)&255; raw[1]=(VERSION.xpub>>>16)&255; raw[2]=(VERSION.xpub>>>8)&255; raw[3]=VERSION.xpub&255;
    return bs58check.encode(raw);
  })() : xpubOrZpub;

  const child = HDKey.fromExtendedKey(x).deriveChild(index);
  const pub33 = child.publicKey; // 已压缩
  const h160  = ripemd160(sha256(pub33));
  const words = bech32.toWords(h160);
  words.unshift(0x00);
  return bech32.encode('bc', words);
}