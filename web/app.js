const registerForm = document.querySelector('#register-form');
const loginForm = document.querySelector('#login-form');
const registerTab = document.querySelector('#register-tab');
const loginTab = document.querySelector('#login-tab');
const message = (id, text, success = false) => {
  const node = document.querySelector(id);
  node.textContent = text;
  node.classList.toggle('success', success);
};
async function request(path, payload) {
  const response = await fetch(path, {method: 'POST', headers: {'Content-Type': 'application/json'}, credentials: 'same-origin', body: JSON.stringify(payload)});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || data.message || '请求失败，请稍后重试');
  return data;
}
function showAccount(user) {
  document.querySelector('#auth-view').hidden = true;
  document.querySelector('#account-view').hidden = false;
  document.querySelector('#account-email').textContent = user.email;
}
function setMode(mode) {
  const registering = mode === 'register';
  registerForm.hidden = !registering;
  loginForm.hidden = registering;
  registerTab.classList.toggle('active', registering);
  loginTab.classList.toggle('active', !registering);
  registerTab.setAttribute('aria-selected', String(registering));
  loginTab.setAttribute('aria-selected', String(!registering));
  document.querySelector('#form-title').textContent = registering ? '创建账户' : '登录账户';
}
registerTab.addEventListener('click', () => setMode('register'));
loginTab.addEventListener('click', () => setMode('login'));
document.querySelector('#send-code').addEventListener('click', async (event) => {
  const button = event.currentTarget;
  const email = document.querySelector('#register-email').value.trim();
  if (!document.querySelector('#register-email').reportValidity()) return;
  button.disabled = true;
  message('#register-message', '正在发送验证码…');
  try {
    const result = await request('/api/send-code', {email});
    message('#register-message', result.message, true);
    let cooldown = 60;
    const timer = setInterval(() => {
      cooldown -= 1;
      button.textContent = cooldown ? '重新发送 (' + cooldown + 's)' : '发送验证码';
      if (!cooldown) { clearInterval(timer); button.disabled = false; }
    }, 1000);
    button.textContent = '重新发送 (60s)';
  } catch (error) {
    message('#register-message', error.message);
    button.disabled = false;
  }
});
registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!registerForm.reportValidity()) return;
  const button = registerForm.querySelector('[type=submit]');
  button.disabled = true;
  message('#register-message', '正在创建账户…');
  try {
    const result = await request('/api/register', {email: document.querySelector('#register-email').value, code: document.querySelector('#verification-code').value.trim(), password: document.querySelector('#register-password').value});
    showAccount(result.user);
  } catch (error) {
    message('#register-message', error.message);
    button.disabled = false;
  }
});
loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!loginForm.reportValidity()) return;
  const button = loginForm.querySelector('[type=submit]');
  button.disabled = true;
  message('#login-message', '正在登录…');
  try {
    const result = await request('/api/login', {email: document.querySelector('#login-email').value, password: document.querySelector('#login-password').value});
    showAccount(result.user);
  } catch (error) {
    message('#login-message', error.message);
    button.disabled = false;
  }
});
document.querySelector('#logout-button').addEventListener('click', async () => {
  await fetch('/api/session', {method: 'DELETE', credentials: 'same-origin'});
  document.querySelector('#account-view').hidden = true;
  document.querySelector('#auth-view').hidden = false;
  setMode('login');
});
fetch('/api/me', {credentials: 'same-origin'}).then((response) => response.ok ? response.json() : null).then((data) => { if (data && data.user) showAccount(data.user); }).catch(() => {});
