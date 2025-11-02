<script type="module">
  /********** 依赖模块（与 fido2.js 对齐） **********/
  import {
    genMnemonic, mnemonicToSeed, exportBranches,
    createPasswordBackupBlob, validatePasswordStrict
  } from './js/hdwallet-core.js';

  import {
    ensureCredentialWithChoice,
    deriveKEK,                 // ✅ 统一用 deriveKEK({ saltHex })
    aesGcmEncryptStr,
    aesGcmDecryptStr           // ✅ 新增导入，用于“显示 30 秒”临时解密
  } from './js/fido2.js';

  /********** 配置：你的 Worker API **********/
  const API_BASE = 'https://wallet.lucas-l-shang.workers.dev';

  /********** 小工具 **********/
  const $ = id => document.getElementById(id);
  const u8toHex = u8 => [...u8].map(b=>b.toString(16).padStart(2,'0')).join('');

  async function saveBundleToDB(bundle, { user_id='web-ui', note='' } = {}) {
    const res = await fetch(`${API_BASE}/bundles`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ user_id, note, bundle })
    });
    const data = await res.json().catch(()=> ({}));
    if (!res.ok || !data?.ok) throw new Error(data?.error || `HTTP ${res.status}`);
    return data; // { ok:true, bundle_id:'...' }
  }

  /********** 状态 **********/
  let branches = null;               // 各链分支（xprv/xpub…）
  let mnemoEnc = null;               // 助记词密文 { nonce, ciphertext, saltHex, credential_id }
  let revealTimer = null;            // 30s 计时器
  const DISPLAY_MS = 30_000;

  /********** UI 辅助 **********/
  function fillGridPlaceholders(n=12){
    const grid = $('mnemo-grid'); grid.innerHTML = '';
    for (let i=1;i<=n;i++){
      const cell = document.createElement('div'); cell.className='cell';
      cell.innerHTML = `<span class="badge">${i}</span><span class="word">•••••</span>`;
      grid.appendChild(cell);
    }
  }
  function renderMnemonicWords(m){
    const words = m.trim().split(/\s+/);
    const grid = $('mnemo-grid'); grid.innerHTML = '';
    words.forEach((w,i)=>{
      const cell = document.createElement('div'); cell.className='cell';
      cell.innerHTML = `<span class="badge">${i+1}</span><span class="word">${w}</span>`;
      grid.appendChild(cell);
    });
  }
  function showMask(){ $('mnemo-mask').style.display = 'flex'; }
  function hideMask(){ $('mnemo-mask').style.display = 'none'; }
  function reMaskAfter(ms){
    clearTimeout(revealTimer);
    revealTimer = setTimeout(()=>{
      // 回到遮挡态 & 占位
      showMask();
      fillGridPlaceholders();
      // 清理任何残留明文
      try {
        // grid 里只剩占位，不存明文；另外确保本地变量不保存明文
      } catch {}
    }, ms);
  }

  /********** Step 1：生成助记词（先确保有 FIDO2 凭证） **********/
  $('btn-gen').onclick = async ()=>{
    try{
      // 1) 确保存在/复用凭证（这里不会阻塞后续“显示 30 秒”再次验证）
      await ensureCredentialWithChoice();

      // 2) 生成助记词与分支（明文只在本函数栈里存在）
      const mnemonic = genMnemonic(128);                  // 12 词
      const seed = mnemonicToSeed(mnemonic, '');
      branches = exportBranches(seed);

      // 3) 立刻用 FIDO2 派生出的 KEK 加密助记词，然后清理明文
      const { kek, salt, rp_id, info, credential_id, toHex } = await deriveKEK(); // 随机盐
      const enc = await aesGcmEncryptStr(kek, mnemonic);
      mnemoEnc = { ...enc, saltHex: toHex(salt), credential_id };

      // 清理明文变量（尽可能缩短明文驻留）
      // 覆盖字符串（JS 字符串不可原地覆写，只能丢弃引用）
      // 但我们尽量不再保留对 mnemonic 的任何引用
      // seed/branches 会保留以便写库（不含助记词明文）
      // 4) 初始展示卡片为遮挡占位
      $('mnemo-container').style.display = 'block';
      fillGridPlaceholders();
      showMask();

      // 按钮状态
      $('btn-encrypt').disabled = false;
      $('final-tip').textContent = '';
    }catch(e){
      alert('生成失败：' + (e?.message||e));
      console.error(e);
    }
  };

  /********** “显示 30 秒”：每次点击都重新派生 KEK 并解密 **********/
  $('mnemo-toggle').onclick = async ()=>{
    try{
      if (!mnemoEnc) { alert('请先生成助记词'); return; }
      hideMask(); // 先给出触发反馈

      // 1) 用保存的 saltHex 重新派生 KEK（必要时会引导触摸/验证）
      const { kek } = await deriveKEK({ saltHex: mnemoEnc.saltHex });

      // 2) 解密得到助记词明文，只用于渲染
      const plaintext = await aesGcmDecryptStr(kek, mnemoEnc);
      renderMnemonicWords(plaintext);

      // 3) 启动 30 秒自动遮挡，随后清理
      reMaskAfter(DISPLAY_MS);

      // 4) 立即销毁本地变量中对明文的引用（尽可能缩短生命周期）
      // （注意 JS 字符串不可原地擦除，只能丢失引用）
      // eslint-disable-next-line no-self-assign
      // @ts-ignore
      // 直接丢弃引用：
      // plaintext = null; // 在 strict 下会报错，因为 const；这里不再持有引用即可
    }catch(e){
      showMask();
      console.error(e);
      alert('解密显示失败：' + (e?.message||e));
    }
  };

  /********** Step 2：离线备份（可选） **********/
  $('want-backup').onchange = e=>{
    $('backup-area').style.display = e.target.checked ? 'block' : 'none';
    $('btn-backup').disabled = !e.target.checked;
  };
  $('pw1').oninput = $('pw2').oninput = ()=>{
    const p1=$('pw1').value, p2=$('pw2').value;
    if (!p1 && !p2){ $('pw-tip').textContent=''; $('btn-backup').disabled=true; return; }
    if (p1!==p2){ $('pw-tip').innerHTML='<span class="err">两次密码不一致</span>'; $('btn-backup').disabled=true; return; }
    const v = validatePasswordStrict(p1);
    if (!v.ok){ $('pw-tip').innerHTML='<span class="err">'+v.reason+'</span>'; $('btn-backup').disabled=true; return; }
    $('pw-tip').innerHTML='<span class="ok">密码强度通过</span>'; $('btn-backup').disabled=false;
  };
  $('btn-backup').onclick = async ()=>{
    try{
      if (!mnemoEnc){ alert('请先生成助记词'); return; }
      // 离线备份是“助记词明文 + 你的强密码”的二次加密策略
      // 需要明文：临时解密一次（派生 KEK）
      const { kek } = await deriveKEK({ saltHex: mnemoEnc.saltHex });
      const plaintext = await aesGcmDecryptStr(kek, mnemoEnc);

      const { blob } = await createPasswordBackupBlob(plaintext, $('pw1').value);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href=url; a.download='mnemonic_backup.enc.json'; a.click();
      setTimeout(()=>URL.revokeObjectURL(url), 3000);
      $('pw-tip').innerHTML = '<span class="ok">已生成并下载离线备份。</span>';
      // 丢弃明文引用
      // plaintext = null;
    }catch(e){
      $('pw-tip').innerHTML='<span class="err">备份失败：'+(e?.message||e)+'</span>';
      console.error(e);
    }
  };

  /********** Step 3：注册/复用 FIDO2 凭证（便捷入口，不阻塞第 4 步） **********/
  $('btn-register').onclick = async ()=>{
    try{
      const res = await ensureCredentialWithChoice(); // { ok, id_hex, created }
      if (res?.created){
        $('reg-tip').innerHTML = '<span class="ok">已注册新凭证。</span>';
      }else{
        $('reg-tip').innerHTML = `<span class="ok">已可使用凭证（id: ${String(res?.id_hex||'').slice(0,16)}…）。</span>`;
      }
    }catch(e){
      $('reg-tip').innerHTML = '<span class="err">注册/复用失败：'+(e?.message||e)+'</span>';
      console.error(e);
    }
  };

  /********** Step 4：PRF→HKDF → AES-GCM 加密分支并写库（不含助记词） **********/
  $('btn-encrypt').onclick = async ()=>{
    try{
      if (!branches){ alert('请先生成助记词'); return; }
      $('encrypt-tip').textContent = '请触摸密钥以继续…';

      // 用新的随机盐派生 KEK 加密分支（与助记词的 saltHex 无关）
      const { kek, salt, rp_id, info, credential_id, toHex } = await deriveKEK();

      const encBranch = async s => s ? await aesGcmEncryptStr(kek, s) : null;
      const bundle = {
        KEKInfo:{ rp_id, info, salt: toHex(salt), credential_id },
        chains:{
          ETH:  { path: branches.ETH.path,  PubEnc: await encBranch(branches.ETH.xpub),   PrivEnc: await encBranch(branches.ETH.xprv) },
          BTC:  { path: branches.BTC.path,  PubEnc: await encBranch(branches.BTC.xpub_z), PrivEnc: await encBranch(branches.BTC.xprv_z) },
          EOS:  { path: branches.EOS.path,  PubEnc: await encBranch(branches.EOS.xpub),   PrivEnc: await encBranch(branches.EOS.xprv) },
          TRON: { path: branches.TRON.path, PubEnc: await encBranch(branches.TRON.xpub),  PrivEnc: await encBranch(branches.TRON.xprv) },
        }
      };

      $('encrypt-tip').textContent='正在写入数据库…';
      const ret = await saveBundleToDB(bundle, { user_id:'web-ui', note:'初始化保存（UI）' });

      // 清理私钥引用
      branches.ETH.xprv=null; branches.BTC.xprv_z=null; branches.EOS.xprv=null; branches.TRON.xprv=null;

      $('encrypt-tip').textContent='';
      $('final-tip').innerHTML = `<span class="ok">注册成功！bundle_id=${ret.bundle_id}</span>`;
    }catch(e){
      $('encrypt-tip').textContent='';
      $('final-tip').innerHTML = `<span class="err">写入失败：${e?.message||e}</span>`;
      console.error(e);
    }
  };
</script>
