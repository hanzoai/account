/**
 * Account Portal — Cloudflare Worker
 *
 * Serves branded account management pages for:
 *   - account.hanzo.id  (Hanzo brand)
 *   - account.lux.id    (Lux brand)
 *
 * Authentication: Uses IAM access tokens via OAuth code exchange.
 * Users are redirected to their brand's login page if unauthenticated.
 */

const IAM_ORIGIN = 'https://iam.hanzo.ai';

// Brand configuration keyed by hostname
const BRANDS = {
  'account.hanzo.id': {
    name: 'Hanzo',
    domain: 'hanzo.id',
    loginUrl: 'https://hanzo.id/login',
    bg: '#0a0a0a',
    surface: '#111111',
    border: '#222222',
    accent: '#fd4444',
    clientId: 'hanzo-app-client-id',
    logo: `<svg viewBox="0 0 100 100" width="40" height="40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M50 5L90 27.5V72.5L50 95L10 72.5V27.5L50 5Z" stroke="#fd4444" stroke-width="4"/>
      <path d="M30 35V65M70 35V65M30 50H70" stroke="#fd4444" stroke-width="4" stroke-linecap="round"/>
    </svg>`,
  },
  'account.lux.id': {
    name: 'Lux',
    domain: 'lux.id',
    loginUrl: 'https://lux.id/login',
    bg: '#050508',
    surface: '#0c0c10',
    border: '#222222',
    accent: '#ffffff',
    clientId: 'lux-app-client-id',
    logo: `<svg viewBox="0 0 100 100" width="40" height="40" fill="none" xmlns="http://www.w3.org/2000/svg">
      <polygon points="50,10 90,75 10,75" stroke="white" stroke-width="3" fill="none"/>
      <polygon points="50,30 72,68 28,68" stroke="white" stroke-width="2" fill="none"/>
    </svg>`,
  },
};

function getBrand(hostname) {
  return BRANDS[hostname] || BRANDS['account.hanzo.id'];
}

function htmlResponse(html) {
  return new Response(html, {
    headers: {
      'content-type': 'text/html;charset=UTF-8',
      'cache-control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
    },
  });
}

// Parse access token from cookie
function getToken(request) {
  const cookie = request.headers.get('Cookie') || '';
  const match = cookie.match(/account_token=([^;]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

// Fetch user info from IAM using token
async function getUserInfo(token) {
  const res = await fetch(`${IAM_ORIGIN}/v1/iam/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data;
}

// Fetch full user object for editing
async function getUser(token, owner, name) {
  const res = await fetch(`${IAM_ORIGIN}/v1/iam/get-user?id=${encodeURIComponent(owner)}/${encodeURIComponent(name)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.data || null;
}

// Build the OAuth login URL for the brand. Points at the brand's branded
// /login page (front-door worker) with the OAuth params; that page renders
// the two-pane login and emits the canonical /v1/iam/* calls itself — no
// bare /oauth/authorize, no host leak to iam.hanzo.ai.
function buildLoginUrl(brand, callbackUrl) {
  const params = new URLSearchParams({
    client_id: brand.clientId,
    redirect_uri: callbackUrl,
    response_type: 'code',
    scope: 'openid profile email',
    state: 'account',
  });
  return `${brand.loginUrl}?${params.toString()}`;
}

// Exchange authorization code for access token
async function exchangeCode(code, callbackUrl, brand) {
  const res = await fetch(`${IAM_ORIGIN}/v1/iam/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: callbackUrl,
      client_id: brand.clientId,
    }).toString(),
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.access_token || null;
}

function renderAccountPage(brand, user, fullUser) {
  const providers = [];
  // Extract linked providers from user object
  const providerFields = ['github', 'google', 'facebook', 'twitter', 'linkedin', 'discord', 'wechat', 'dingtalk'];
  if (fullUser) {
    for (const p of providerFields) {
      if (fullUser[p] && fullUser[p] !== '') {
        providers.push({ name: p, id: fullUser[p] });
      }
    }
    // Check for MetaMask/Web3 wallet
    if (fullUser.metamask && fullUser.metamask !== '') {
      providers.push({ name: 'web3', id: fullUser.metamask });
    } else if (fullUser.web3onboard && fullUser.web3onboard !== '') {
      providers.push({ name: 'web3', id: fullUser.web3onboard });
    }
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account - ${brand.name}</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${brand.bg};
      color: #fff;
      min-height: 100vh;
    }
    .topbar {
      border-bottom: 1px solid ${brand.border};
      padding: 0.75rem 1.5rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      background: ${brand.surface};
    }
    .topbar-brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      font-weight: 600;
      font-size: 1.1rem;
    }
    .topbar-actions { display: flex; gap: 0.75rem; align-items: center; }
    .topbar-actions a {
      color: #999;
      text-decoration: none;
      font-size: 0.85rem;
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      border: 1px solid ${brand.border};
    }
    .topbar-actions a:hover { color: #fff; border-color: #555; }
    .topbar-actions .logout { color: #ff6b6b; border-color: #ff6b6b33; }
    .topbar-actions .logout:hover { background: #ff6b6b11; }
    .container {
      max-width: 800px;
      margin: 2rem auto;
      padding: 0 1.5rem;
    }
    .section {
      background: ${brand.surface};
      border: 1px solid ${brand.border};
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }
    .section h2 {
      font-size: 1.1rem;
      margin-bottom: 1rem;
      padding-bottom: 0.75rem;
      border-bottom: 1px solid ${brand.border};
    }
    .field {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 0.6rem 0;
    }
    .field + .field { border-top: 1px solid ${brand.border}22; }
    .field-label { color: #888; font-size: 0.85rem; min-width: 120px; }
    .field-value { font-size: 0.92rem; }
    .field-action {
      color: ${brand.accent};
      text-decoration: none;
      font-size: 0.82rem;
      cursor: pointer;
      background: none;
      border: 1px solid ${brand.accent}44;
      padding: 0.3rem 0.6rem;
      border-radius: 6px;
    }
    .field-action:hover { background: ${brand.accent}11; }
    .provider-list { display: flex; flex-direction: column; gap: 0.5rem; }
    .provider-item {
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0.6rem 0.8rem;
      border: 1px solid ${brand.border};
      border-radius: 8px;
      background: ${brand.bg};
    }
    .provider-item .name {
      text-transform: capitalize;
      font-weight: 500;
    }
    .provider-item .id {
      color: #888;
      font-size: 0.8rem;
      margin-left: 0.5rem;
    }
    .provider-item .unlink {
      color: #ff6b6b;
      font-size: 0.78rem;
      cursor: pointer;
      background: none;
      border: 1px solid #ff6b6b33;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
    }
    .add-provider {
      display: flex;
      gap: 0.5rem;
      margin-top: 0.75rem;
      flex-wrap: wrap;
    }
    .add-btn {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      padding: 0.4rem 0.8rem;
      border: 1px dashed ${brand.border};
      border-radius: 8px;
      color: #999;
      font-size: 0.82rem;
      cursor: pointer;
      background: none;
      text-decoration: none;
    }
    .add-btn:hover { border-color: #555; color: #fff; }
    .badge {
      display: inline-block;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 500;
      background: #1a472a;
      color: #6ee7b7;
      margin-left: 0.4rem;
    }
    .badge.unverified { background: #472a1a; color: #e7b76e; }
    .danger-zone {
      border-color: #ff6b6b33;
    }
    .danger-zone h2 { color: #ff6b6b; }
    .msg {
      display: none;
      padding: 0.75rem;
      border-radius: 8px;
      margin-bottom: 1rem;
      font-size: 0.85rem;
    }
    .msg.success { background: #1a472a; color: #6ee7b7; display: block; }
    .msg.error { background: #472a1a; color: #e7b76e; display: block; }
    .avatar-row {
      display: flex;
      align-items: center;
      gap: 1rem;
      padding: 0.6rem 0;
    }
    .avatar {
      width: 64px;
      height: 64px;
      border-radius: 50%;
      background: ${brand.border};
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.5rem;
      font-weight: 700;
      color: #fff;
      overflow: hidden;
    }
    .avatar img { width: 100%; height: 100%; object-fit: cover; }
    .modal-overlay {
      display: none;
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.7);
      z-index: 100;
      align-items: center;
      justify-content: center;
    }
    .modal-overlay.active { display: flex; }
    .modal {
      background: ${brand.surface};
      border: 1px solid ${brand.border};
      border-radius: 12px;
      padding: 1.5rem;
      width: 100%;
      max-width: 420px;
    }
    .modal h3 { margin-bottom: 1rem; }
    .modal input {
      width: 100%;
      border-radius: 8px;
      border: 1px solid ${brand.border};
      background: ${brand.bg};
      color: #fff;
      padding: 0.6rem 0.8rem;
      font-size: 0.9rem;
      margin-bottom: 0.75rem;
    }
    .modal-actions {
      display: flex;
      gap: 0.5rem;
      justify-content: flex-end;
      margin-top: 0.75rem;
    }
    .modal-actions button {
      padding: 0.5rem 1rem;
      border-radius: 6px;
      border: 1px solid ${brand.border};
      background: none;
      color: #fff;
      cursor: pointer;
      font-size: 0.85rem;
    }
    .modal-actions .primary {
      background: ${brand.accent};
      color: ${brand.accent === '#ffffff' ? '#111' : '#fff'};
      border-color: ${brand.accent};
    }
    @media (max-width: 640px) {
      .container { padding: 0 1rem; margin: 1rem auto; }
      .section { padding: 1rem; }
      .field { flex-direction: column; align-items: flex-start; gap: 0.3rem; }
    }
  </style>
</head>
<body>
  <nav class="topbar">
    <div class="topbar-brand">
      ${brand.logo}
      <span>${brand.name} Account</span>
    </div>
    <div class="topbar-actions">
      <a href="https://${brand.domain}">Back to ${brand.name}</a>
      <a href="https://${brand.domain}/logout" class="logout">Sign Out</a>
    </div>
  </nav>

  <div class="container">
    <div id="msg" class="msg"></div>

    <div class="section">
      <h2>Profile</h2>
      <div class="avatar-row">
        <div class="avatar">
          ${user.picture ? `<img src="${user.picture}" alt="Avatar">` : (user.name || 'U').charAt(0).toUpperCase()}
        </div>
        <div>
          <div style="font-weight:600;font-size:1.1rem;">${user.preferred_username || user.name || 'User'}</div>
          <div style="color:#888;font-size:0.85rem;">${user.email || ''}</div>
        </div>
      </div>
      <div class="field">
        <span class="field-label">Display Name</span>
        <span class="field-value">${user.name || '—'}</span>
        <button class="field-action" onclick="editField('name','${(user.name || '').replace(/'/g, "\\'")}')">Edit</button>
      </div>
      <div class="field">
        <span class="field-label">Email</span>
        <span class="field-value">
          ${user.email || '—'}
          ${user.email_verified ? '<span class="badge">Verified</span>' : '<span class="badge unverified">Unverified</span>'}
        </span>
      </div>
      <div class="field">
        <span class="field-label">Phone</span>
        <span class="field-value">${user.phone || '—'}</span>
      </div>
    </div>

    <div class="section">
      <h2>Login Methods</h2>
      <div class="provider-list">
        <div class="provider-item">
          <div>
            <span class="name">Email & Password</span>
            <span class="id">${user.email || 'Not set'}</span>
          </div>
          <button class="field-action" onclick="openPasswordModal()">Change Password</button>
        </div>
        ${providers.map(p => `
        <div class="provider-item">
          <div>
            <span class="name">${p.name === 'web3' ? 'Web3 Wallet' : p.name}</span>
            <span class="id">${p.name === 'web3' ? p.id.slice(0, 6) + '...' + p.id.slice(-4) : p.id}</span>
          </div>
          <button class="unlink" onclick="unlinkProvider('${p.name}')">Unlink</button>
        </div>`).join('')}
      </div>
      <div class="add-provider">
        <a class="add-btn" href="https://${brand.domain}/v1/iam/oauth/authorize?client_id=${brand.clientId}&redirect_uri=${encodeURIComponent(`https://${brand.domain}/callback`)}&response_type=code&scope=openid+profile+email&provider=provider-google">
          + Google
        </a>
        <a class="add-btn" href="https://${brand.domain}/v1/iam/oauth/authorize?client_id=${brand.clientId}&redirect_uri=${encodeURIComponent(`https://${brand.domain}/callback`)}&response_type=code&scope=openid+profile+email&provider=provider-github">
          + GitHub
        </a>
        <button class="add-btn" onclick="linkWallet()">+ Web3 Wallet</button>
      </div>
    </div>

    <div class="section">
      <h2>Security</h2>
      <div class="field">
        <span class="field-label">Two-Factor Auth</span>
        <span class="field-value">${fullUser && fullUser.totpSecret ? '<span class="badge">Enabled</span>' : 'Not enabled'}</span>
        <button class="field-action" onclick="window.location.href='https://iam.hanzo.ai/account#mfa'">${fullUser && fullUser.totpSecret ? 'Manage' : 'Enable'}</button>
      </div>
      <div class="field">
        <span class="field-label">Last Sign-in</span>
        <span class="field-value">${fullUser && fullUser.lastSigninTime ? new Date(fullUser.lastSigninTime).toLocaleString() : '—'}</span>
      </div>
      <div class="field">
        <span class="field-label">Last Sign-in IP</span>
        <span class="field-value">${fullUser && fullUser.lastSigninIp ? fullUser.lastSigninIp : '—'}</span>
      </div>
    </div>

    <div class="section danger-zone">
      <h2>Danger Zone</h2>
      <div class="field">
        <span class="field-label">Delete Account</span>
        <span class="field-value" style="color:#888;font-size:0.82rem;">Permanently delete your account and all data</span>
        <button class="field-action" style="color:#ff6b6b;border-color:#ff6b6b44;" onclick="confirmDelete()">Delete Account</button>
      </div>
    </div>
  </div>

  <!-- Password Change Modal -->
  <div class="modal-overlay" id="password-modal">
    <div class="modal">
      <h3>Change Password</h3>
      <input type="password" id="old-password" placeholder="Current password" autocomplete="current-password">
      <input type="password" id="new-password" placeholder="New password (min 8 characters)" autocomplete="new-password">
      <input type="password" id="confirm-password" placeholder="Confirm new password" autocomplete="new-password">
      <div id="pw-error" style="color:#ff8f8f;font-size:0.82rem;display:none;margin-bottom:0.5rem;"></div>
      <div class="modal-actions">
        <button onclick="closePasswordModal()">Cancel</button>
        <button class="primary" onclick="changePassword()">Update Password</button>
      </div>
    </div>
  </div>

  <!-- Edit Field Modal -->
  <div class="modal-overlay" id="edit-modal">
    <div class="modal">
      <h3 id="edit-title">Edit Field</h3>
      <input type="text" id="edit-value">
      <div class="modal-actions">
        <button onclick="closeEditModal()">Cancel</button>
        <button class="primary" onclick="saveField()">Save</button>
      </div>
    </div>
  </div>

  <script>
    const TOKEN = document.cookie.match(/account_token=([^;]+)/)?.[1] ? decodeURIComponent(document.cookie.match(/account_token=([^;]+)/)[1]) : null;
    const IAM = '${IAM_ORIGIN}';
    const BRAND_DOMAIN = '${brand.domain}';
    let editingField = null;

    function showMsg(text, type) {
      const el = document.getElementById('msg');
      el.textContent = text;
      el.className = 'msg ' + type;
      setTimeout(() => { el.className = 'msg'; }, 5000);
    }

    function openPasswordModal() {
      document.getElementById('password-modal').classList.add('active');
    }
    function closePasswordModal() {
      document.getElementById('password-modal').classList.remove('active');
      document.getElementById('old-password').value = '';
      document.getElementById('new-password').value = '';
      document.getElementById('confirm-password').value = '';
      document.getElementById('pw-error').style.display = 'none';
    }

    async function changePassword() {
      const oldPw = document.getElementById('old-password').value;
      const newPw = document.getElementById('new-password').value;
      const confirm = document.getElementById('confirm-password').value;
      const errEl = document.getElementById('pw-error');

      if (!oldPw || !newPw) { errEl.textContent = 'All fields required'; errEl.style.display = 'block'; return; }
      if (newPw.length < 8) { errEl.textContent = 'Password must be at least 8 characters'; errEl.style.display = 'block'; return; }
      if (newPw !== confirm) { errEl.textContent = 'Passwords do not match'; errEl.style.display = 'block'; return; }

      try {
        const res = await fetch('/v1/iam/set-password', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            Authorization: 'Bearer ' + TOKEN,
          },
          body: new URLSearchParams({
            userOwner: '${fullUser ? fullUser.owner : 'hanzo'}',
            userName: '${fullUser ? fullUser.name : ''}',
            oldPassword: oldPw,
            newPassword: newPw,
          }).toString(),
        });
        const data = await res.json();
        if (data.status === 'ok') {
          closePasswordModal();
          showMsg('Password updated successfully', 'success');
        } else {
          errEl.textContent = data.msg || 'Failed to update password';
          errEl.style.display = 'block';
        }
      } catch (e) {
        errEl.textContent = 'Network error';
        errEl.style.display = 'block';
      }
    }

    function editField(field, currentValue) {
      editingField = field;
      document.getElementById('edit-title').textContent = 'Edit ' + field.charAt(0).toUpperCase() + field.slice(1);
      document.getElementById('edit-value').value = currentValue;
      document.getElementById('edit-modal').classList.add('active');
    }
    function closeEditModal() {
      document.getElementById('edit-modal').classList.remove('active');
      editingField = null;
    }
    async function saveField() {
      if (!editingField) return;
      const value = document.getElementById('edit-value').value;
      try {
        const userObj = { owner: '${fullUser ? fullUser.owner : 'hanzo'}', name: '${fullUser ? fullUser.name : ''}' };
        if (editingField === 'name') userObj.displayName = value;
        const res = await fetch('/v1/iam/update-user?id=${fullUser ? fullUser.owner + '/' + fullUser.name : ''}', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: 'Bearer ' + TOKEN,
          },
          body: JSON.stringify(userObj),
        });
        const data = await res.json();
        if (data.status === 'ok') {
          closeEditModal();
          showMsg('Updated successfully. Refreshing...', 'success');
          setTimeout(() => location.reload(), 1000);
        } else {
          showMsg(data.msg || 'Update failed', 'error');
        }
      } catch (e) {
        showMsg('Network error', 'error');
      }
    }

    async function unlinkProvider(provider) {
      if (!confirm('Unlink ' + provider + ' from your account?')) return;
      try {
        var field = provider === 'web3' ? 'metamask' : provider;
        var userObj = { owner: '${fullUser ? fullUser.owner : 'hanzo'}', name: '${fullUser ? fullUser.name : ''}' };
        userObj[field] = '';
        var res = await fetch('/v1/iam/update-user?id=${fullUser ? fullUser.owner + '/' + fullUser.name : ''}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(userObj),
        });
        var data = await res.json();
        if (data.status === 'ok') {
          showMsg(provider + ' unlinked successfully', 'success');
          setTimeout(function() { location.reload(); }, 1000);
        } else {
          showMsg(data.msg || 'Failed to unlink ' + provider, 'error');
        }
      } catch (e) {
        showMsg('Network error: ' + e.message, 'error');
      }
    }

    async function linkWallet() {
      if (typeof window.ethereum === 'undefined') {
        showMsg('Please install MetaMask or another Web3 wallet', 'error');
        return;
      }
      try {
        var accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
        var address = accounts[0];
        if (!address) { showMsg('No wallet account found', 'error'); return; }

        // Sign a message to prove wallet ownership
        var message = 'Link wallet ' + address + ' to ' + BRAND_DOMAIN + ' account for ${fullUser ? fullUser.name : 'user'}';
        await window.ethereum.request({ method: 'personal_sign', params: [message, address] });

        // Update user with wallet address
        var userObj = { owner: '${fullUser ? fullUser.owner : 'hanzo'}', name: '${fullUser ? fullUser.name : ''}', metamask: address };
        var res = await fetch('/v1/iam/update-user?id=${fullUser ? fullUser.owner + '/' + fullUser.name : ''}', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(userObj),
        });
        var data = await res.json();
        if (data.status === 'ok') {
          showMsg('Wallet linked: ' + address.slice(0, 6) + '...' + address.slice(-4), 'success');
          setTimeout(function() { location.reload(); }, 1500);
        } else {
          showMsg(data.msg || 'Failed to link wallet', 'error');
        }
      } catch (err) {
        if (err.code === 4001) return; // User rejected
        showMsg(err.message || 'Failed to connect wallet', 'error');
      }
    }

    function confirmDelete() {
      if (!confirm('Are you sure? This action is permanent and cannot be undone.')) return;
      if (!confirm('This will permanently delete your account and all associated data. Type OK to confirm.')) return;
      showMsg('Account deletion requires verification. Redirecting to IAM...', 'error');
      window.location.href = 'https://iam.hanzo.ai/account';
    }
  </script>
</body>
</html>`;
}

function renderLoginRedirectPage(brand, loginUrl) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Sign In Required - ${brand.name}</title>
  <meta http-equiv="refresh" content="2;url=${loginUrl}">
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: ${brand.bg};
      color: #fff;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
      margin: 0;
    }
    .card {
      text-align: center;
      padding: 2rem;
      border: 1px solid ${brand.border};
      border-radius: 12px;
      background: ${brand.surface};
      max-width: 400px;
    }
    a { color: ${brand.accent}; }
  </style>
</head>
<body>
  <div class="card">
    ${brand.logo}
    <h2 style="margin-top:1rem;">Sign in to continue</h2>
    <p style="color:#888;margin-top:0.5rem;">Redirecting to ${brand.name} login...</p>
    <p style="margin-top:1rem;"><a href="${loginUrl}">Click here if not redirected</a></p>
  </div>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const hostname = url.hostname;
    const pathname = url.pathname;
    const brand = getBrand(hostname);
    const callbackUrl = `https://${hostname}/callback`;

    // Handle OAuth callback — exchange code for token
    if (pathname === '/callback') {
      const code = url.searchParams.get('code');
      if (!code) {
        return new Response(null, {
          status: 302,
          headers: { Location: buildLoginUrl(brand, callbackUrl) },
        });
      }

      const token = await exchangeCode(code, callbackUrl, brand);
      if (!token) {
        return new Response(null, {
          status: 302,
          headers: { Location: buildLoginUrl(brand, callbackUrl) },
        });
      }

      // Set token cookie and redirect to account page
      return new Response(null, {
        status: 302,
        headers: {
          Location: '/',
          'Set-Cookie': `account_token=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`,
        },
      });
    }

    // Handle logout
    if (pathname === '/logout') {
      return new Response(null, {
        status: 302,
        headers: {
          Location: `https://${brand.domain}`,
          'Set-Cookie': 'account_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        },
      });
    }

    // Proxy IAM API calls (for client-side JS). Same-origin /v1/iam/* from
    // the account page is forwarded to IAM; the access token is attached
    // server-side from the HttpOnly cookie so it never rides in page JS.
    if (pathname.startsWith('/v1/iam/')) {
      const token = getToken(request);
      const iamUrl = new URL(pathname + url.search, IAM_ORIGIN);
      const headers = new Headers(request.headers);
      headers.set('Host', new URL(IAM_ORIGIN).hostname);
      if (token) headers.set('Authorization', `Bearer ${token}`);

      const iamRes = await fetch(iamUrl.toString(), {
        method: request.method,
        headers,
        body: request.method !== 'GET' ? request.body : undefined,
      });

      return new Response(iamRes.body, {
        status: iamRes.status,
        headers: {
          'content-type': iamRes.headers.get('content-type') || 'application/json',
          'cache-control': 'no-store',
        },
      });
    }

    // Check authentication for all other routes
    const token = getToken(request);
    if (!token) {
      const loginUrl = buildLoginUrl(brand, callbackUrl);
      return new Response(null, {
        status: 302,
        headers: { Location: loginUrl },
      });
    }

    // Get user info
    const user = await getUserInfo(token);
    if (!user || !user.name) {
      // Token expired or invalid — re-authenticate
      const loginUrl = buildLoginUrl(brand, callbackUrl);
      return new Response(null, {
        status: 302,
        headers: {
          Location: loginUrl,
          'Set-Cookie': 'account_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
        },
      });
    }

    // Get full user object for detailed info
    const fullUser = await getUser(token, user.owner || 'hanzo', user.preferred_username || user.name);

    // Serve account page
    return htmlResponse(renderAccountPage(brand, user, fullUser));
  },
};
