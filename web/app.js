'use strict';
const $ = (s, el = document) => el.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
let S = { nodes: [], chains: [], users: [], tasks: [], settings: {}, admin: '' };

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
        <button class="small" data-act="node-config" data-id="${n.id}">查看配置</button>
        <button class="small" data-act="node-edit" data-id="${n.id}">编辑</button>
        ${n.has_host_key ? `<button class="small" data-act="node-hostkey" data-id="${n.id}">重置主机公钥</button>` : ''}
        <button class="small danger" data-act="node-del" data-id="${n.id}">删除</button>
      </td></tr>`;
  }).join('') || '<tr><td colspan="6" class="empty">还没有节点，点右上角「添加节点」</td></tr>';

  $('#chainRows').innerHTML = S.chains.map((c) => `<tr>
      <td><strong>${esc(c.name)}</strong></td>
      <td>用户 ${c.hops.map((h, i) => `→ ${i > 0 ? `<span class="badge">${h.addr === 'internal' ? '内网' : '公网'}</span> ` : ''}${esc(nodeName(h.node_id))}`).join(' ')} → 互联网</td>
      <td class="mono">${c.port}</td>
      <td class="ops">
        <button class="small" data-act="chain-test" data-id="${c.id}">检测连通性</button>
        <button class="small" data-act="chain-edit" data-id="${c.id}">编辑</button>
        <button class="small danger" data-act="chain-del" data-id="${c.id}">删除</button>
      </td></tr>`).join('') || '<tr><td colspan="4" class="empty">还没有线路</td></tr>';

  $('#userRows').innerHTML = S.users.map((u) => `<tr>
      <td><strong>${esc(u.name)}</strong></td>
      <td><span class="badge ${u.enabled ? 'ok' : 'bad'}">${u.enabled ? '启用' : '停用'}</span></td>
      <td>${u.chain_ids.length ? u.chain_ids.map((id) => esc((S.chains.find((c) => c.id === id) || {}).name || '?')).join('、') : '全部线路'}</td>
      <td>${esc(u.remark)}</td>
      <td class="ops">
        <button class="small" data-act="user-links" data-id="${u.id}">连接信息</button>
        <button class="small" data-act="user-toggle" data-id="${u.id}">${u.enabled ? '停用' : '启用'}</button>
        <button class="small" data-act="user-edit" data-id="${u.id}">编辑</button>
        <button class="small" data-act="user-reset" data-id="${u.id}">重置凭据</button>
        <button class="small danger" data-act="user-del" data-id="${u.id}">删除</button>
      </td></tr>`).join('') || '<tr><td colspan="5" class="empty">还没有用户</td></tr>';

  $('#taskRows').innerHTML = S.tasks.map((t) => `<tr>
      <td>${esc(t.title)}</td>
      <td>${taskBadge(t.status)}</td>
      <td>${esc(fmtTime(t.started_at))}</td>
      <td class="ops"><button class="small" data-act="task-view" data-id="${t.id}">查看日志</button></td>
    </tr>`).join('') || '<tr><td colspan="4" class="empty">暂无任务</td></tr>';

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
    <p class="hint">「内网 / 公网」表示上一跳通过哪个地址连接该节点，例如广州 → 香港走专线内网，香港 → 新加坡走公网。请在云厂商安全组中放行对应端口。</p>`,
  async (f) => {
    await api(edit ? 'PUT' : 'POST', '/api/chains' + (edit ? '/' + c.id : ''), { name: f.name.value, port: +f.port.value, hops });
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
    <label class="check"><input type="checkbox" name="enabled" ${u.enabled ? 'checked' : ''}>启用</label>
    <fieldset><legend>可用线路（一个都不勾选 = 全部线路，包括以后新增的）</legend>
      ${S.chains.map((c) => `<label class="check"><input type="checkbox" name="chain" value="${c.id}" ${u.chain_ids.includes(c.id) ? 'checked' : ''}>${esc(c.name)}</label>`).join('') || '<span class="muted">还没有线路</span>'}
    </fieldset>`, async (f) => {
    const chain_ids = [...f.querySelectorAll('input[name=chain]:checked')].map((x) => x.value);
    await api(edit ? 'PUT' : 'POST', '/api/users' + (edit ? '/' + u.id : ''),
      { name: f.name.value, remark: f.remark.value, enabled: f.enabled.checked, chain_ids });
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
    ${u.links.map((l) => item(l.name, l.link)).join('') || '<p class="muted">暂无可用线路</p>'}
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
        await api('PUT', `/api/users/${id}`, { name: user.name, remark: user.remark, chain_ids: user.chain_ids, enabled: !user.enabled });
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
