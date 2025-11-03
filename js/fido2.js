<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>助记词初始化（注册新 FIDO2 凭证）</title>
  <style>
    :root{
      --bg:#0b1220;--card:#0f1724;--muted:#9ca3af;--text:#e5e7eb;
      --accent:#60a5fa;--good:#10b981;--bad:#ef4444;--line:#1f2937;
    }
    html,body{background:var(--bg);color:var(--text);margin:0;font:16px/1.55 system-ui,-apple-system,Segoe UI,Roboto,PingFang SC,Microsoft YaHei,sans-serif;}
    .wrap{max-width:980px;margin:32px auto;padding:18px}
    h1{margin:0 0 12px}
    .card{background:var(--card);border:1px solid rgba(255,255,255,0.06);border-radius:14px;padding:18px;margin-bottom:18px;box-shadow:0 8px 24px rgba(0,0,0,.35)}
    .row{display:flex;align-items:center;gap:12px;margin:12px 0;flex-wrap:wrap}
    .muted{color:var(--muted)}
    .ok{color:var(--good)} .err{color:var(--bad)}
    .btn{
      background:linear-gradient(180deg,#0f172a,#091427);
      border:1px solid rgba(255,255,255,0.08);
      color:var(--text);padding:10px 14px;border-radius:12px;cursor:pointer
    }
    .btn:hover{filter:brightness(1.06)}
    .btn[disabled]{opacity:.45;cursor:not-allowed}

    /* 助记词网格 */
    .grid{display:grid;grid-template-columns:repeat(3,1fr);gap:10px}
    .cell{
      background:linear-gradient(180deg,#071226,#0b1526);
      border:1px dashed rgba(255,255,255,.06);border-radius:12px;padding:10px;
      display:flex;align-items:center;gap:10px;min-height:44px
    }
    .badge{width:26px;height:26px;border-radius:999px;background:#0b1328;display:grid;place-items:center;color:#9fb4d9}

    /* 整块遮挡（覆盖在网格上） */
    .mnemo-box{position:relative}
    .mnemo-mask{
      position:absolute;inset:10px;display:flex;align-items:center;justify-content:center;
      background:radial-gradient(ellipse at center, rgba(15,23,42,.78) 0%, rgba(2,6,23,.9) 100%);
      border:1px dashed #334155;border-radius:14px;backdrop-filter:blur(6px)
    }
    .mask-inner{display:flex;flex-direction:column;align-items:center;gap:10px}
    .mask-btn{
      display:flex;align-items:center;gap:10px;border-radius:999px;padding:12px 16px;
      border:1px solid #1f2a44;background:#0b1328;color:#cfe1ff;cursor:pointer;
      box-shadow:0 8px 22px rgba(0,0,0,.28);user-select:none
    }
    .hint{text-align:center;color:#9aa4b4}

    @media (max-width:700px){ .grid{grid-template-columns:repeat(2,1fr)} }
  </style>
</head>
<body>
  <div class="wrap">
    <h1>助记词初始化（注册新 FIDO2 凭证 → 生成即加密）</h1>

    <!-- A. 仅注册新凭证 -->
    <div class="card">
      <h3>步骤 A：注册新的本域 FIDO2 凭证</h3>
      <div class="row">
        <button id="btn-register" class="btn">1) 注册新凭证</button>
        <span id="reg-tip" class="muted"></span>
      </div>
      <div class="muted">该步骤会创建“可发现凭证（discoverable）”。后续步骤会<strong>强制绑定同一把凭证</strong>，防止 A 步骤选 A、B 步骤却触摸 B。</div>
    </div>

    <!-- B. 生成 & 展示（生成即加密；默认整块遮挡） -->
    <div class="card">
      <h3>步骤 B：生成助记词（生成即用步骤 A 的凭证加密；默认整块遮挡）</h3>
      <div class="row">
        <button id="btn-gen" class="btn" disabled>2) 生成助记词并加密</button>
        <span id="gen-tip" class="muted"></span>
      </div>

      <!-- 助记词卡片：网格 + 整块遮挡 -->
      <div id="mnemo-card" style="display:none;margin-top:10px">
        <div class="mnemo-box">
          <div class="grid" id="mnemo-grid"></div>

          <!-- 蒙层：默认可见；点击解密显示 60 秒 -->
          <div class="mnemo-mask" id="mnemo-mask">
            <div class="mask-inner">
              <button class="mask-btn" id="btn-reveal">显示助记词（需 FIDO2 解密）</button>
              <div class="hint" id="mask-hint">默认遮挡。点击上方按钮并完成 FIDO2 验证后，明文显示 60 秒并自动遮挡。</div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- C. 写库 -->
    <div class="card">
      <h3>步骤 C：写入数据库（再次验证同一把凭证）</h3>
      <div class="row">
        <button id="btn-save" class="btn" disabled>3) 写入数据库</button>
        <span id="save-tip" class="muted"></span>
      </div>
      <div class="muted">仅写入密文，不包含助记词明文。</div>
    </div>
  </div>

<script type="module">
/* ===== 导入：与等价优化版 fido2.js 对齐 ===== */
import {
  loadCredHex,
  saveCredHex,
  clearCredHex,
  ensureCredentialWithChoice,
  deriveKEK,           // 生成用：自动生成随机 salt + 派生 KEK
  deriveKEKWithSalt,   // 解密用：用保存的 salt + 固定 cred 再派生 KEK
  aesGcmEncryptStr,
  aesGcmDecryptStr,
  discoverCredentialHex, // 静默探测（可有可无）
  RP_ID
} from './js/fido2.js';

import {
  genMnemonic, mnemonicToSeed, exportBranches
} from './js/hdwallet-core.js';

/* ===== 你的 API 基址（按实际修改） ===== */
const API_BASE = 'https://wallet.lucas-l-shang.workers.dev';

/* ===== DOM 小工具 ===== */
const $  = id => document.getElementById(id);
const setHTML = (id, html) => { const n=$(id); if(n) n.innerHTML = html; };
const setText = (id, txt)  => { const n=$(id); if(n) n.textContent = txt; };
const enable  = (id, on)   => { const n=$(id); if(n) n.disabled = !on; };
const show    = (id, on=true) => { const n=$(id); if(n) n.style.display = on ? '' : 'none'; };

/* ===== 全局状态 ===== */
let selectedCredHex = null;   // 步骤 A 绑定的那把凭证
let sealed = null;            // { saltHex, enc:{nonce,ciphertext} } —— 助记词密文
let branchesEnc = null;       // {ETH:{PubEnc,PrivEnc}, ...} —— 各链密文
let wordCount = 12;
let autoMaskTimer = null;
const REVEAL_MS = 60_000;     // 解密展示 60 秒

function clearAutoMask() { if (autoMaskTimer) { clearTimeout(autoMaskTimer); autoMaskTimer = null; } }

/* ===== 页面初始化：尝试静默探测可发现凭证，若成功直接允许进行下一步 ===== */
document.addEventListener('DOMContentLoaded', async ()=>{
  console.log('[init] DOM ready, RP_ID =', RP_ID);
  try {
    const found = await discoverCredentialHex();
    if (found) {
      selectedCredHex = found;
      setHTML('reg-tip', `<span class="ok">已选择沿用凭证（id: ${found.slice(0,16)}…）。可进行下一步。</span>`);
      enable('btn-gen', true);
    } else {
      setHTML('reg-tip', `<span class="muted">未探测到本域凭证，请先注册。</span>`);
      enable('btn-gen', false);
    }
  } catch (e) {
    console.error('[init] discover error:', e);
    setHTML('reg-tip', `<span class="err">探测凭证失败：${e?.message||e}</span>`);
  }
});

/* ===== 步骤 A：注册或选择本域 FIDO2 凭证 ===== */
$('btn-register')?.addEventListener('click', async ()=>{
  const tip = $('reg-tip');
  try {
    const res = await ensureCredentialWithChoice(); // 有则用、无则注册
    selectedCredHex = res?.id_hex || loadCredHex();
    if (!selectedCredHex) throw new Error('未能获得凭证 ID');

    tip.innerHTML = res?.created
      ? `<span class="ok">已注册新凭证。id: ${selectedCredHex.slice(0,16)}…</span>`
      : `<span class="ok">已选择沿用凭证（id: ${selectedCredHex.slice(0,16)}…）。</span>`;

    // A 完成后解禁 B
    enable('btn-gen', true);
  } catch (e) {
    console.error('[init] register/choose error:', e);
    tip.innerHTML = `<span class="err">注册/选择失败：${e?.message||e}</span>`;
    enable('btn-gen', false);
  }
});

/* ===== UI：助记词网格 + 遮挡 ===== */
function renderMaskedGrid(n) {
  const grid = $('mnemo-grid');
  if (!grid) return;
  grid.innerHTML = '';
  for (let i=0;i<n;i++) {
    const d = document.createElement('div');
    d.className = 'cell';
    d.innerHTML = `<span class="badge">${i+1}</span><span class="word">•••••</span>`;
    grid.appendChild(d);
  }
  show('mnemo-card', true);
  show('mnemo-mask', true);   // 显示整块遮挡
  show('btn-reveal', true);   // “显示助记词（需FIDO2）”按钮
}

/* ===== 步骤 B：生成助记词 & 立即加密（不保留明文） ===== */
$('btn-gen')?.addEventListener('click', async ()=>{
  const tip = $('gen-tip');
  try {
    if (!selectedCredHex) {
      tip.innerHTML = `<span class="err">请先完成步骤 A（绑定凭证）。</span>`;
      return;
    }

    // 1) 生成助记词 + 各链（立刻派生 seed + 导出分支）
    const mnemonic = genMnemonic(128);
    const words    = mnemonic.trim().split(/\s+/);
    wordCount      = words.length || 12;
    const seed     = mnemonicToSeed(mnemonic, '');
    const branches = exportBranches(seed);

    // 2) 用“同一把凭证”派生随机 salt 的 KEK（deriveKEK 内部会调用 WebAuthn）
    const { kek, salt, toHex, credential_id } = await deriveKEK({ autoRegister:false });
    if (credential_id !== selectedCredHex) {
      throw new Error('步骤 A 与步骤 B 的凭证不一致');
    }

    // 3) 加密助记词 & 各链 xpub/xprv（不同 nonce；同一 salt 没问题，因为 AES-GCM 的随机 IV 保证安全）
    sealed = {
      saltHex: toHex(salt),
      enc: await aesGcmEncryptStr(kek, mnemonic)  // {nonce,ciphertext}
    };

    const enc = async s => s ? await aesGcmEncryptStr(kek, s) : null;
    branchesEnc = {
      ETH:  { path: branches.ETH.path,  PubEnc: await enc(branches.ETH.xpub),   PrivEnc: await enc(branches.ETH.xprv) },
      BTC:  { path: branches.BTC.path,  PubEnc: await enc(branches.BTC.xpub_z), PrivEnc: await enc(branches.BTC.xprv_z) },
      EOS:  { path: branches.EOS.path,  PubEnc: await enc(branches.EOS.xpub),   PrivEnc: await enc(branches.EOS.xprv) },
      TRON: { path: branches.TRON.path, PubEnc: await enc(branches.TRON.xpub),  PrivEnc: await enc(branches.TRON.xprv) },
    };

    // 4) 清理明文
    try { for (let i=0;i<words.length;i++) words[i]=''; } catch {}
    // seed/branches 的明文私钥也不再保留
    branches.ETH.xprv = branches.EOS.xprv = branches.TRON.xprv = null;
    branches.BTC.xprv_z = null;

    // 5) UI：展示遮挡 + “显示助记词（需 FIDO2）”
    renderMaskedGrid(wordCount);
    tip.textContent = '';

    // 允许步骤 C（写库）
    enable('btn-encrypt', true);
  } catch (e) {
    console.error('[init] generate error:', e);
    setHTML('gen-tip', `<span class="err">生成/加密失败：${e?.message||e}</span>`);
  }
});

/* ===== 点击显示助记词（需 FIDO2 解密；展示 60s 后自动遮挡并清明文） ===== */
$('btn-reveal')?.addEventListener('click', async ()=>{
  try {
    if (!sealed || !selectedCredHex) return;

    clearAutoMask();

    // 1) 用相同的 cred + 已保存的 salt 重新派生 KEK
    const { kek, credential_id } = await deriveKEKWithSalt(selectedCredHex, sealed.saltHex);
    if (credential_id !== selectedCredHex) {
      throw new Error('当前解锁的凭证与步骤 A 不一致');
    }

    // 2) 解密助记词
    const mnemonic = await aesGcmDecryptStr(kek, sealed.enc);
    const words = mnemonic.trim().split(/\s+/);

    // 3) 渲染并去掉遮挡
    const grid = $('mnemo-grid');
    grid.innerHTML = '';
    words.forEach((w,i)=>{
      const d = document.createElement('div');
      d.className = 'cell';
      d.innerHTML = `<span class="badge">${i+1}</span><span class="word">${w}</span>`;
      grid.appendChild(d);
    });
    show('mnemo-mask', false);

    // 4) 60s 自动遮挡并清理局部明文
    autoMaskTimer = setTimeout(()=>{
      renderMaskedGrid(wordCount);
      try { for (let i=0;i<words.length;i++) words[i]=''; } catch {}
    }, REVEAL_MS);
  } catch (e) {
    console.error('[init] reveal error:', e);
    alert('解锁失败：' + (e?.message || e));
  }
});

/* ===== 步骤 C：把“密文分支 + KEKInfo”写库（不包含助记词明文） ===== */
$('btn-encrypt')?.addEventListener('click', async ()=>{
  const tip = $('encrypt-tip');
  try {
    if (!selectedCredHex) throw new Error('尚未绑定 FIDO2 凭证');
    if (!branchesEnc || !sealed) throw new Error('请先生成助记词（并已加密）');

    tip.textContent = '正在写入…';

    const bundle = {
      KEKInfo: {
        rp_id: RP_ID,
        info:  'wallet-priv-bundle-v1',
        salt:  sealed.saltHex,
        credential_id: selectedCredHex
      },
      chains: {
        ETH:  { path: branchesEnc.ETH.path,  PubEnc: branchesEnc.ETH.PubEnc,  PrivEnc: branchesEnc.ETH.PrivEnc },
        BTC:  { path: branchesEnc.BTC.path,  PubEnc: branchesEnc.BTC.PubEnc,  PrivEnc: branchesEnc.BTC.PrivEnc },
        EOS:  { path: branchesEnc.EOS.path,  PubEnc: branchesEnc.EOS.PubEnc,  PrivEnc: branchesEnc.EOS.PrivEnc },
        TRON: { path: branchesEnc.TRON.path, PubEnc: branchesEnc.TRON.PubEnc, PrivEnc: branchesEnc.TRON.PrivEnc },
      }
    };

    const resp = await fetch(`${API_BASE}/bundles`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user_id:'web-ui', note:'init via UI', bundle })
    });
    const data = await resp.json().catch(()=> ({}));
    if (!resp.ok || !data?.ok) throw new Error(data?.error || `HTTP ${resp.status}`);

    tip.textContent = '';
    alert(`写入成功：bundle_id=${data.bundle_id}`);
  } catch (e) {
    console.error('[init] write error:', e);
    tip.textContent = '';
    alert('写库失败：' + (e?.message || e));
  }
});
</script>

</body>
</html>
