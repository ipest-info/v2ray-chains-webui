'use strict';
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let S = { nodes: [], chains: [], exits: [], users: [], tasks: [], settings: {}, tls: { dns_env_keys: [], cert: {} }, admin: '' };

async function api(method, path, body) {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: method === 'GET' ? undefined : JSON.stringify(body ?? {}),
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && path !== '/api/login') {
    showLogin();
    throw new Error('登录已过期，请重新登录');
  }
  if (!res.ok) throw new Error(data.error || `请求失败 (${res.status})`);
  return data;
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 3500);
}
const fmtTime = (s) => (s && !s.startsWith('0001') ? new Date(s).toLocaleString() : '');
const nodeName = (id) => (S.nodes.find((n) => n.id === id) || {}).name || '?';
const exitName = (id) => (S.exits.find((x) => x.id === id) || {}).name || '?';

// ---------- 登录 ----------
function showLogin() {
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
}
$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  $('#loginErr').textContent = '';
  try {
    await api('POST', '/api/login', { username: f.username.value, password: f.password.value });
    f.password.value = '';
    await refresh();
  } catch (err) {
    $('#loginErr').textContent = err.message;
  }
});
$('#logout').addEventListener('click', async () => {
  await api('POST', '/api/logout');
  showLogin();
});

// ---------- 渲染 ----------
async function refresh() {
  S = await api('GET', '/api/state');
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  render();
}

function render() {
  $('#adminName').textContent = S.admin;
  const dirty = S.nodes.filter((n) => n.dirty).length;
  $('#dirtyCount').textContent = dirty;
  $('#dirtyCount').classList.toggle('hidden', !dirty);

  $('#nodeRows').innerHTML = S.nodes.map((n) => {
    const st = n.status === 'online' ? '<span class="badge ok">SSH 正常</span>'
      : n.status === 'offline' ? '<span class="badge bad">SSH 不通</span>' : '<span class="badge">未检测</span>';
    const v2 = !n.v2ray_version ? '<span class="badge">未安装</span>'
      : `<span class="badge ${n.service_active ? 'ok' : 'bad'}">${esc(n.v2ray_version)} ${n.service_active ? '运行中' : '未运行'}</span>`;
    return `<tr>
      <td><strong>${esc(n.name)}</strong></td>
      <td class="mono">${esc(n.ssh_user)}@${esc(n.ssh_host)}:${n.ssh_port}
        ${n.jump_node_id ? `<div class="muted">经「${esc(nodeName(n.jump_node_id))}」跳转</div>` : ''}</td>
      <td class="mono">${esc(n.public_addr) || '<span class="muted">-</span>'}<div class="muted">${esc(n.internal_addr)}</div></td>
      <td>${st}${n.status === 'offline' ? `<div class="muted">${esc(n.status_msg)}</div>` : ''}</td>
      <td>${v2} ${n.dirty ? '<span class="badge warn">配置待同步</span>' : ''}</td>
      <td class="ops">
        <button class="small" data-act="node-check" data-id="${n.id}">检测</button>
        <button class="small" data-act="node-install" data-id="${n.id}">${n.v2ray_version ? '重装 / 升级' : '安装'}</button>
        <button class="small" data-act="node-apply" data-id="${n.id}">同步配置</button>
        <button class="small" data-act="node-conf" data-id="${n.id}">配置项</button>
        <button class="small" data-act="node-config" data-id="${n.id}">预览配置</button>
        <button class="small" data-act="node-backups" data-id="${n.id}">备份 / 恢复</button>
        <button class="small" data-act="node-edit" data-id="${n.id}">编辑</button>
        ${n.has_host_key ? `<button class="small" data-act="node-hostkey" data-id="${n.id}">重置主机公钥</button>` : ''}
        <button class="small danger" data-act="node-del" data-id="${n.id}">删除</button>
      </td></tr>`;
  }).join('') || '<tr><td colspan="6" class="empty">还没有节点，点右上角「添加节点」</td></tr>';

  $('#chainRows').innerHTML = S.chains.map((c) => `<tr>
      <td><strong>${esc(c.name)}</strong></td>
      <td>用户 ${c.hops.map((h, i) => `→ ${i > 0 ? `<span class="badge">${h.addr === 'internal' ? '内网' : '公网'}</span> ` : ''}${esc(nodeName(h.node_id))}`).join(' ')} → ${c.exit_id ? `<span class="badge warn">${esc(exitName(c.exit_id))}</span> → ` : ''}互联网</td>
      <td class="mono">${c.port}</td>
      <td class="ops">
        <button class="small" data-act="chain-test" data-id="${c.id}">检测连通性</button>
        <button class="small" data-act="chain-edit" data-id="${c.id}">编辑</button>
        <button class="small danger" data-act="chain-del" data-id="${c.id}">删除</button>
      </td></tr>`).join('') || '<tr><td colspan="4" class="empty">还没有线路</td></tr>';

  $('#exitRows').innerHTML = S.exits.map((x) => {
    const chains = S.chains.filter((c) => c.exit_id === x.id).map((c) => c.name);
    const users = S.users.filter((u) => u.exit_id === x.id).map((u) => u.name);
    return `<tr>
      <td><strong>${esc(x.name)}</strong></td>
      <td>${x.protocol === 'socks' ? 'SOCKS5' : 'HTTP'}</td>
      <td class="mono">${esc(x.address)}:${x.port}</td>
      <td>${x.username ? esc(x.username) : '<span class="muted">无</span>'}</td>
      <td>${chains.length ? `线路：${esc(chains.join('、'))}` : ''}${chains.length && users.length ? '<br>' : ''}${users.length ? `用户：${esc(users.join('、'))}` : ''}${!chains.length && !users.length ? '<span class="muted">未使用</span>' : ''}</td>
      <td class="ops">
        <button class="small" data-act="exit-edit" data-id="${x.id}">编辑</button>
        <button class="small danger" data-act="exit-del" data-id="${x.id}">删除</button>
      </td></tr>`;
  }).join('') || '<tr><td colspan="6" class="empty">还没有出口代理（不配置时，流量从线路末端节点直接出网）</td></tr>';

  $('#userRows').innerHTML = S.users.map((u) => `<tr>
      <td><strong>${esc(u.name)}</strong></td>
      <td><span class="badge ${u.enabled ? 'ok' : 'bad'}">${u.enabled ? '启用' : '停用'}</span></td>
      <td>${u.chain_ids.length ? u.chain_ids.map((id) => esc((S.chains.find((c) => c.id === id) || {}).name || '?')).join('、') : '全部线路'}</td>
      <td>${!u.exit_id ? '<span class="muted">跟随线路</span>' : u.exit_id === 'direct' ? '末端节点直连' : `<span class="badge warn">${esc(exitName(u.exit_id))}</span>`}</td>
      <td>${esc(u.remark)}</td>
      <td class="ops">
        <button class="small" data-act="user-links" data-id="${u.id}">连接信息</button>
        <button class="small" data-act="user-toggle" data-id="${u.id}">${u.enabled ? '停用' : '启用'}</button>
        <button class="small" data-act="user-edit" data-id="${u.id}">编辑</button>
        <button class="small" data-act="user-reset" data-id="${u.id}">重置凭据</button>
        <button class="small danger" data-act="user-del" data-id="${u.id}">删除</button>
      </td></tr>`).join('') || '<tr><td colspan="6" class="empty">还没有用户</td></tr>';

  $('#taskRows').innerHTML = S.tasks.map((t) => `<tr>
      <td>${esc(t.title)}</td>
      <td>${taskBadge(t.status)}</td>
      <td>${esc(fmtTime(t.started_at))}</td>
      <td class="ops"><button class="small" data-act="task-view" data-id="${t.id}">查看日志</button></td>
    </tr>`).join('') || '<tr><td colspan="4" class="empty">暂无任务</td></tr>';

  const tf = $('#tlsForm');
  const T = S.tls;
  if (!tf.contains(document.activeElement)) {
    tf.domain.value = T.domain || '';
    tf.email.value = T.email || '';
    tf.ca.value = T.ca || 'letsencrypt';
    tf.mode.value = T.mode || 'http';
    tf.dns_provider.value = T.dns_provider || '';
    tf.redirect.checked = !!T.redirect;
    tf.acme_base_url.value = T.acme_base_url || '';
    $('#tlsDns').classList.toggle('hidden', tf.mode.value !== 'dns');
  }
  $('#tlsEnvKeys').textContent = T.dns_env_keys.length ? `（已保存：${T.dns_env_keys.join('、')}；留空则不修改）` : '';
  const url = T.domain && T.https_port ? `https://${T.domain}:${T.https_port}/` : '';
  $('#tlsStatus').innerHTML = !T.https_port ? '<span class="badge">HTTPS 入口未启用</span>'
    : !T.cert.loaded ? `<span class="badge">尚未申请证书</span> <span class="muted">HTTPS 端口 ${esc(T.https_port)}</span>`
      : `<span class="badge ${T.cert.valid ? 'ok' : 'bad'}">${T.cert.valid ? '证书有效' : '证书已过期'}</span>
         ${esc(T.cert.domains.join(', '))}，${esc(T.cert.issuer)} 签发，${esc(new Date(T.cert.not_after).toLocaleDateString())} 到期
         ${url ? `<br><a href="${esc(url)}">${esc(url)}</a>` : ''}`;

  const sf = $('#settingsForm');
  if (document.activeElement !== sf.download_url) sf.download_url.value = S.settings.download_url || '';
  const pf = $('#passwordForm');
  if (!pf.username.value) pf.username.value = S.admin;
}

const taskBadge = (s) => s === 'running' ? '<span class="badge warn">执行中</span>'
  : s === 'success' ? '<span class="badge ok">成功</span>' : '<span class="badge bad">失败</span>';

$('#tabs').addEventListener('click', (e) => {
  const tab = e.target.dataset.tab;
  if (!tab) return;
  document.querySelectorAll('#tabs a').forEach((a) => a.classList.toggle('active', a === e.target));
  document.querySelectorAll('main > section').forEach((s) => s.classList.toggle('hidden', s.id !== 'tab-' + tab));
  refresh().catch(() => {});
});

// ---------- 对话框 ----------
let dlgSubmit = null;
let dlgTimer = null;
function openDialog(title, html, onSubmit, okText = '保存') {
  $('#dlgTitle').textContent = title;
  $('#dlgBody').onclick = null;
  $('#dlgBody').innerHTML = html;
  $('#dlgErr').textContent = '';
  $('#dlgOk').textContent = okText;
  $('#dlgOk').classList.toggle('hidden', !onSubmit);
  $('#dlgCancel').textContent = onSubmit ? '取消' : '关闭';
  dlgSubmit = onSubmit;
  $('#dlg').showModal();
}
$('#dlgCancel').addEventListener('click', () => $('#dlg').close());
$('#dlg').addEventListener('close', () => { clearInterval(dlgTimer); dlgTimer = null; });
$('#dlgForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (!dlgSubmit) return $('#dlg').close();
  $('#dlgOk').disabled = true;
  try {
    await dlgSubmit($('#dlgForm'));
    $('#dlg').close();
    await refresh();
  } catch (err) {
    $('#dlgErr').textContent = err.message;
  } finally {
    $('#dlgOk').disabled = false;
  }
});

// 打开任务日志并轮询直到结束。
function watchTask(id) {
  openDialog('任务日志', '<p id="taskHead"></p><pre class="log" id="taskLog"></pre>', null);
  const tick = async () => {
    try {
      const t = await api('GET', '/api/tasks/' + id);
      if (!$('#taskLog')) return;
      $('#taskHead').innerHTML = `${esc(t.title)} ${taskBadge(t.status)}`;
      const log = $('#taskLog');
      const atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 20;
      log.textContent = t.log || '';
      if (atEnd) log.scrollTop = log.scrollHeight;
      if (t.status !== 'running') {
        clearInterval(dlgTimer);
        dlgTimer = null;
        refresh().catch(() => {});
      }
    } catch (err) {
      clearInterval(dlgTimer);
    }
  };
  tick();
  dlgTimer = setInterval(tick, 1200);
}
async function startTask(path) {
  const r = await api('POST', path);
  watchTask(r.task_id);
}

// ---------- 节点 ----------
function nodeDialog(n) {
  const edit = !!n;
  n = n || { ssh_port: 22, ssh_user: 'root' };
  const jumps = S.nodes.filter((x) => x.id !== n.id)
    .map((x) => `<option value="${x.id}" ${x.id === n.jump_node_id ? 'selected' : ''}>经「${esc(x.name)}」跳转</option>`).join('');
  openDialog(edit ? '编辑节点' : '添加节点', `
    <label>节点名称<input name="name" value="${esc(n.name)}" placeholder="例如：广州" required></label>
    <fieldset><legend>SSH 登录</legend>
      <div class="row">
        <label>SSH 地址<input name="ssh_host" value="${esc(n.ssh_host)}" placeholder="IP 或域名" required></label>
        <label>端口<input name="ssh_port" type="number" min="1" max="65535" value="${n.ssh_port}" required></label>
        <label>用户名<input name="ssh_user" value="${esc(n.ssh_user)}" required></label>
      </div>
      <label>密码${edit && n.has_password ? '（已保存，留空则不修改）' : ''}
        <input name="ssh_password" type="password" autocomplete="new-password"></label>
      <label>或 SSH 私钥${edit && n.has_key ? '（已保存，留空则不修改）' : '（可选，PEM / OpenSSH 格式，不支持带口令的私钥）'}
        <textarea name="ssh_key" class="mono" spellcheck="false" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea></label>
      ${edit && n.has_key ? '<label class="check"><input type="checkbox" name="clear_key">删除已保存的私钥</label>' : ''}
      <label>SSH 跳板（后台无法直连该节点时使用，此时「SSH 地址」填跳板能访问到的地址）
        <select name="jump_node_id"><option value="">直连</option>${jumps}</select></label>
      <p class="hint">非 root 用户需要有 sudo 权限（免密，或 sudo 密码与 SSH 密码相同）。</p>
    </fieldset>
    <fieldset><legend>线路地址</legend>
      <div class="row">
        <label>公网地址<input name="public_addr" value="${esc(n.public_addr)}" placeholder="用户 / 上一跳经公网连接"></label>
        <label>内网地址<input name="internal_addr" value="${esc(n.internal_addr)}" placeholder="可选，专线内网 IP"></label>
      </div>
    </fieldset>`, async (f) => {
    const body = {
      name: f.name.value, ssh_host: f.ssh_host.value, ssh_port: +f.ssh_port.value, ssh_user: f.ssh_user.value,
      ssh_password: f.ssh_password.value, ssh_key: f.ssh_key.value, clear_key: !!(f.clear_key && f.clear_key.checked),
      jump_node_id: f.jump_node_id.value, public_addr: f.public_addr.value, internal_addr: f.internal_addr.value,
    };
    const r = await api(edit ? 'PUT' : 'POST', '/api/nodes' + (edit ? '/' + n.id : ''), body);
    // 保存后立即检测一次连通性，失败只提示不阻止保存。
    api('POST', `/api/nodes/${r.id}/check`).then((c) => {
      toast(c.ok === false ? 'SSH 连接失败：' + c.error : 'SSH 连接正常');
      refresh();
    }).catch(() => {});
  });
}

// 节点的 v2ray 配置项。
function confDialog(n) {
  const c = n.conf || {};
  const level = c.log_level || 'warning';
  openDialog(`「${n.name}」的 v2ray 配置项`, `
    <div class="row">
      <label>日志级别<select name="log_level">${['debug', 'info', 'warning', 'error', 'none']
    .map((l) => `<option ${l === level ? 'selected' : ''}>${l}</option>`).join('')}</select></label>
      <label>DNS 服务器（逗号分隔，留空使用系统 DNS）<input name="dns" value="${esc((c.dns || []).join(', '))}" placeholder="8.8.8.8, 1.1.1.1"></label>
    </div>
    <label class="check"><input type="checkbox" name="sniffing" ${c.sniffing ? 'checked' : ''}>开启流量嗅探（从 HTTP / TLS 中识别域名）</label>
    <label class="check"><input type="checkbox" name="allow_private" ${c.allow_private ? 'checked' : ''}>作为出口时允许访问私有地址段（默认禁止，防止用户访问节点内网）</label>
    <label style="margin-top:12px">自定义 JSON（高级，可选）
      <textarea name="extra" class="code" spellcheck="false" placeholder='{"policy": {...}, "inbounds": [...], "outbounds": [...], "routing": {"rules": [...]}}'>${esc(c.extra)}</textarea></label>
    <p class="hint">合并规则：<code>inbounds</code> / <code>outbounds</code> 追加在线路生成的配置之后；<code>routing.rules</code> 插在最前面优先匹配；其它顶层字段（如 <code>policy</code>、<code>dns</code>、<code>log</code>）整体覆盖。保存后用「预览配置」查看结果，再「同步配置」下发。</p>`,
  async (f) => {
    await api('PUT', `/api/nodes/${n.id}/conf`, {
      log_level: f.log_level.value,
      dns: f.dns.value.split(/[,，\s]+/).filter(Boolean),
      sniffing: f.sniffing.checked, allow_private: f.allow_private.checked, extra: f.extra.value,
    });
  });
}

// 节点上的配置备份：查看、恢复、立即备份。
async function backupsDialog(n) {
  openDialog(`「${n.name}」的配置备份`, '<p class="muted">正在读取…</p>', null);
  let list;
  try {
    list = (await api('GET', `/api/nodes/${n.id}/backups`)).backups;
  } catch (err) {
    $('#dlgBody').innerHTML = `<p class="err">${esc(err.message)}</p>`;
    return;
  }
  $('#dlgBody').innerHTML = `
    <p class="hint">每次同步或恢复配置前，节点上的当前配置会自动备份到 <code>/usr/local/etc/v2ray/backups/</code>（保留最近 30 份，时间为节点本地时间）。</p>
    <p><button type="button" class="small" data-bk="create">立即备份当前配置</button></p>
    ${list.map((b) => `<div class="backup"><span class="mono">${esc(b.time)}</span><span class="muted">${b.size} 字节</span>
      <button type="button" class="small" data-bk="view" data-name="${esc(b.name)}">查看</button>
      <button type="button" class="small" data-bk="restore" data-name="${esc(b.name)}">恢复</button></div>`).join('') || '<p class="muted">还没有备份</p>'}
    <pre class="log hidden" id="bkView" style="margin-top:12px"></pre>`;
  $('#dlgBody').onclick = async (e) => {
    const { bk, name } = e.target.dataset;
    if (!bk) return;
    try {
      if (bk === 'create') return await startTask(`/api/nodes/${n.id}/backups`);
      if (bk === 'view') {
        const r = await api('GET', `/api/nodes/${n.id}/backups/${name}`);
        $('#bkView').textContent = r.config;
        $('#bkView').classList.remove('hidden');
        return;
      }
      if (bk === 'restore' && confirm(`把「${n.name}」的配置恢复为 ${name} 并重启 v2ray？\n当前配置会先自动备份。恢复后节点配置与后台数据可能不一致，再次同步会被后台数据覆盖。`)) {
        await startTask(`/api/nodes/${n.id}/backups/${name}/restore`);
      }
    } catch (err) { toast(err.message); }
  };
}

// ---------- 出口代理 ----------
function exitDialog(x) {
  const edit = !!x;
  x = x || { protocol: 'socks', port: 1080 };
  openDialog(edit ? '编辑出口代理' : '添加出口代理', `
    <div class="row">
      <label>名称<input name="name" value="${esc(x.name)}" placeholder="例如：美国住宅代理" required></label>
      <label>协议<select name="protocol">
        <option value="socks" ${x.protocol === 'socks' ? 'selected' : ''}>SOCKS5</option>
        <option value="http" ${x.protocol === 'http' ? 'selected' : ''}>HTTP</option></select></label>
    </div>
    <div class="row">
      <label>代理地址<input name="address" value="${esc(x.address)}" placeholder="IP 或域名" required></label>
      <label>端口<input name="port" type="number" min="1" max="65535" value="${x.port}" required></label>
    </div>
    <div class="row">
      <label>用户名（可选）<input name="username" value="${esc(x.username)}" autocomplete="off"></label>
      <label>密码${edit && x.has_password ? '（已保存，留空则不修改）' : '（可选）'}<input name="password" type="password" autocomplete="new-password"></label>
    </div>
    <p class="hint">该代理由线路的<strong>最后一个节点</strong>去连接，请确认那台服务器能访问到这个地址。</p>`,
  async (f) => {
    await api(edit ? 'PUT' : 'POST', '/api/exits' + (edit ? '/' + x.id : ''), {
      name: f.name.value, protocol: f.protocol.value, address: f.address.value, port: +f.port.value,
      username: f.username.value, password: f.password.value,
    });
  });
}

// ---------- 线路 ----------
function chainDialog(c) {
  const edit = !!c;
  if (!S.nodes.length) return toast('请先添加节点');
  let hops = c ? c.hops.map((h) => ({ ...h })) : [{ node_id: S.nodes[0].id, addr: 'public' }];
  openDialog(edit ? '编辑线路' : '添加线路', `
    <div class="row">
      <label>线路名称<input name="name" value="${esc(c && c.name)}" placeholder="例如：广州-香港-新加坡" required></label>
      <label>端口（线路在各节点上监听的 TCP 端口）<input name="port" type="number" min="1" max="65535" value="${c ? c.port : 20000 + S.chains.length + 1}" required></label>
    </div>
    <fieldset><legend>路径（按顺序：入口 → 中转 → 出口）</legend>
      <div id="hops"></div>
      <button type="button" class="small" id="addHop">+ 添加下一跳</button>
    </fieldset>
    <label>最终出口
      <select name="exit_id"><option value="">从最后一个节点直接出网</option>
        ${S.exits.map((x) => `<option value="${x.id}" ${c && c.exit_id === x.id ? 'selected' : ''}>经出口代理「${esc(x.name)}」</option>`).join('')}</select></label>
    <p class="hint">「内网 / 公网」表示上一跳通过哪个地址连接该节点，例如广州 → 香港走专线内网，香港 → 新加坡走公网。请在云厂商安全组中放行对应端口。</p>`,
  async (f) => {
    await api(edit ? 'PUT' : 'POST', '/api/chains' + (edit ? '/' + c.id : ''), { name: f.name.value, port: +f.port.value, hops, exit_id: f.exit_id.value });
  });
  const draw = () => {
    $('#hops').innerHTML = hops.map((h, i) => `<div class="hop">
        <span class="muted">${i + 1}.</span>
        <select data-i="${i}" data-k="node_id">${S.nodes.map((n) => `<option value="${n.id}" ${n.id === h.node_id ? 'selected' : ''}>${esc(n.name)}</option>`).join('')}</select>
        ${i === 0 ? '<span class="muted">入口（用户经公网地址连接）</span>' : `<select data-i="${i}" data-k="addr">
          <option value="public" ${h.addr !== 'internal' ? 'selected' : ''}>上一跳经公网地址连接</option>
          <option value="internal" ${h.addr === 'internal' ? 'selected' : ''}>上一跳经内网地址连接</option></select>`}
        <button type="button" class="small danger" data-rm="${i}" ${hops.length === 1 ? 'disabled' : ''}>移除</button>
      </div>`).join('');
  };
  draw();
  $('#hops').addEventListener('change', (e) => {
    const { i, k } = e.target.dataset;
    if (k) hops[+i][k] = e.target.value;
  });
  $('#hops').addEventListener('click', (e) => {
    if (e.target.dataset.rm === undefined) return;
    hops.splice(+e.target.dataset.rm, 1);
    draw();
  });
  $('#addHop').addEventListener('click', () => {
    const used = new Set(hops.map((h) => h.node_id));
    const next = S.nodes.find((n) => !used.has(n.id));
    if (!next) return toast('没有更多可用节点');
    hops.push({ node_id: next.id, addr: next.internal_addr ? 'internal' : 'public' });
    draw();
  });
}

// ---------- 用户 ----------
function userDialog(u) {
  const edit = !!u;
  u = u || { enabled: true, chain_ids: [] };
  openDialog(edit ? '编辑用户' : '添加用户', `
    <label>用户名<input name="name" value="${esc(u.name)}" maxlength="64" required></label>
    <label>备注<input name="remark" value="${esc(u.remark)}"></label>
    <label>最终出口
      <select name="exit_id">
        <option value="">跟随线路的默认出口</option>
        <option value="direct" ${u.exit_id === 'direct' ? 'selected' : ''}>从线路最后一个节点直接出网</option>
        ${S.exits.map((x) => `<option value="${x.id}" ${u.exit_id === x.id ? 'selected' : ''}>经出口代理「${esc(x.name)}」</option>`).join('')}</select></label>
    <label class="check"><input type="checkbox" name="enabled" ${u.enabled ? 'checked' : ''}>启用</label>
    <fieldset><legend>可用线路（一个都不勾选 = 全部线路，包括以后新增的）</legend>
      ${S.chains.map((c) => `<label class="check"><input type="checkbox" name="chain" value="${c.id}" ${u.chain_ids.includes(c.id) ? 'checked' : ''}>${esc(c.name)}</label>`).join('') || '<span class="muted">还没有线路</span>'}
    </fieldset>`, async (f) => {
    const chain_ids = [...f.querySelectorAll('input[name=chain]:checked')].map((x) => x.value);
    await api(edit ? 'PUT' : 'POST', '/api/users' + (edit ? '/' + u.id : ''),
      { name: f.name.value, remark: f.remark.value, enabled: f.enabled.checked, chain_ids, exit_id: f.exit_id.value });
  });
}

function linksDialog(u) {
  const sub = `${location.origin}/sub/${u.sub_token}`;
  const item = (label, val) => `<label>${esc(label)}<div class="link">
      <input class="mono" readonly value="${esc(val)}"><button type="button" class="small" data-copy="${esc(val)}">复制</button></div></label>`;
  openDialog(`连接信息：${u.name}`, `
    ${u.enabled ? '' : '<p class="err">该用户已停用</p>'}
    ${item('UUID', u.uuid)}
    ${item('订阅地址（导入 v2rayN / v2rayNG 等客户端，包含全部可用线路）', sub)}
    ${u.links.map((l) => item(`${l.name}　出口：${l.exit}`, l.link)).join('') || '<p class="muted">暂无可用线路</p>'}
    <p class="hint">协议 VMess / TCP / alterId 0。新建或修改后需「同步全部配置」才会生效。</p>`, null);
}

document.addEventListener('click', async (e) => {
  const copy = e.target.dataset && e.target.dataset.copy;
  if (copy) {
    try { await navigator.clipboard.writeText(copy); toast('已复制'); } catch { toast('复制失败，请手动选择复制'); }
    return;
  }
  const act = e.target.dataset && e.target.dataset.act;
  if (!act) return;
  const id = e.target.dataset.id;
  const node = S.nodes.find((x) => x.id === id);
  const chain = S.chains.find((x) => x.id === id);
  const user = S.users.find((x) => x.id === id);
  try {
    switch (act) {
      case 'node-new': return nodeDialog();
      case 'node-edit': return nodeDialog(node);
      case 'node-check': {
        e.target.disabled = true;
        e.target.textContent = '检测中…';
        const r = await api('POST', `/api/nodes/${id}/check`);
        toast(r.ok === false ? 'SSH 连接失败：' + r.error : `「${node.name}」SSH 连接正常`);
        return refresh();
      }
      case 'node-install':
        if (confirm(`在「${node.name}」上安装 v2ray？将创建 systemd 服务 v2ray，并覆盖 /usr/local/bin/v2ray。`)) await startTask(`/api/nodes/${id}/install`);
        return;
      case 'node-apply': return startTask(`/api/nodes/${id}/apply`);
      case 'node-config': {
        const r = await api('GET', `/api/nodes/${id}/config`);
        return openDialog(`「${node.name}」将下发的 v2ray 配置`, `<pre class="log">${esc(r.config)}</pre>`, null);
      }
      case 'node-hostkey':
        if (confirm(`重置「${node.name}」已记录的 SSH 主机公钥？仅在服务器重装系统后使用，下次连接时会重新记录。`)) {
          await api('POST', `/api/nodes/${id}/reset-hostkey`);
          toast('已重置');
          await refresh();
        }
        return;
      case 'node-conf': return confDialog(node);
      case 'node-backups': return backupsDialog(node);
      case 'exit-new': return exitDialog();
      case 'exit-edit': return exitDialog(S.exits.find((x) => x.id === id));
      case 'exit-del':
        if (confirm('删除该出口代理？')) { await api('DELETE', `/api/exits/${id}`); await refresh(); }
        return;
      case 'node-del':
        if (confirm(`删除节点「${node.name}」？（不会卸载服务器上的 v2ray）`)) { await api('DELETE', `/api/nodes/${id}`); await refresh(); }
        return;
      case 'chain-new': return chainDialog();
      case 'chain-edit': return chainDialog(chain);
      case 'chain-test': return startTask(`/api/chains/${id}/test`);
      case 'chain-del':
        if (confirm(`删除线路「${chain.name}」？`)) { await api('DELETE', `/api/chains/${id}`); await refresh(); }
        return;
      case 'user-new': return userDialog();
      case 'user-edit': return userDialog(user);
      case 'user-links': return linksDialog(user);
      case 'user-toggle':
        await api('PUT', `/api/users/${id}`, { name: user.name, remark: user.remark, chain_ids: user.chain_ids, exit_id: user.exit_id, enabled: !user.enabled });
        return refresh();
      case 'user-reset':
        if (confirm(`重置「${user.name}」的 UUID 和订阅地址？同步配置后旧凭据失效。`)) { await api('POST', `/api/users/${id}/reset`); await refresh(); }
        return;
      case 'user-del':
        if (confirm(`删除用户「${user.name}」？`)) { await api('DELETE', `/api/users/${id}`); await refresh(); }
        return;
      case 'task-view': return watchTask(id);
    }
  } catch (err) {
    toast(err.message);
    refresh().catch(() => {});
  }
});

$('#applyAll').addEventListener('click', () => startTask('/api/apply-all').catch((e) => toast(e.message)));

$('#settingsForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await api('PUT', '/api/settings', { download_url: e.target.download_url.value });
    toast('已保存');
    await refresh();
  } catch (err) { toast(err.message); }
});

$('#tlsForm').mode.addEventListener('change', (e) => $('#tlsDns').classList.toggle('hidden', e.target.value !== 'dns'));
async function saveTLS() {
  const f = $('#tlsForm');
  await api('PUT', '/api/tls', {
    domain: f.domain.value, email: f.email.value, ca: f.ca.value, mode: f.mode.value,
    dns_provider: f.dns_provider.value, dns_env_text: f.dns_env_text.value,
    redirect: f.redirect.checked, acme_base_url: f.acme_base_url.value,
  });
  f.dns_env_text.value = '';
  document.activeElement.blur();
  await refresh();
}
$('#tlsForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  try { await saveTLS(); toast('已保存'); } catch (err) { toast(err.message); }
});
$('#tlsIssue').addEventListener('click', async () => {
  try { await saveTLS(); await startTask('/api/tls/issue'); } catch (err) { toast(err.message); }
});

$('#passwordForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  if (f.new.value !== f.new2.value) return toast('两次输入的新密码不一致');
  try {
    await api('POST', '/api/password', { username: f.username.value, old: f.old.value, new: f.new.value });
    f.reset();
    toast('已修改，请重新登录');
    showLogin();
  } catch (err) { toast(err.message); }
});

refresh().catch(() => showLogin());
