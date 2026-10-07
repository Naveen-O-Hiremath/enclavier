// First-run page: choose the Enclavier server. Served from app://vault/__setup
// with the same strict content security policy as the vault (no inline code).

export const SETUP_HTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Enclavier</title>
<link rel="stylesheet" href="/__setup.css">
</head>
<body>
<main>
  <div class="brand"><img class="mark" src="/logo.png" alt=""><span>Enclavier</span></div>
  <form id="form" class="card">
    <h1>Connect to your server</h1>
    <p class="muted">Enter the address of your organization's Enclavier server. Your administrator can tell you what it is.</p>
    <label for="url">Server address</label>
    <input id="url" type="text" placeholder="https://vault.example.com" autocomplete="off" spellcheck="false" autofocus required>
    <p id="error" class="error" role="alert" hidden></p>
    <button id="go" type="submit">Connect</button>
  </form>
  <p class="foot">End-to-end encrypted. Your master password never leaves this computer.</p>
</main>
<script src="/__setup.js"></script>
</body>
</html>`;

export const SETUP_CSS = `
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(#eef2ff,#f8fafc);color:#0f172a;font:15px/1.5 -apple-system,'Segoe UI',Roboto,sans-serif}
main{width:100%;max-width:400px;padding:24px}
.brand{display:flex;align-items:center;justify-content:center;gap:10px;margin-bottom:28px;font-size:24px;font-weight:600;letter-spacing:-.3px}
.mark{width:48px;height:48px;border-radius:22%;box-shadow:0 1px 3px rgba(15,23,42,.15)}
.card{background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:24px;box-shadow:0 10px 30px rgba(15,23,42,.08)}
h1{font-size:18px;margin:0 0 4px}
.muted{color:#64748b;font-size:14px;margin:0 0 18px}
label{display:block;font-size:12px;font-weight:600;letter-spacing:.04em;text-transform:uppercase;color:#64748b;margin-bottom:6px}
input{width:100%;padding:10px 12px;border:1px solid #cbd5e1;border-radius:9px;font:inherit;outline:none}
input:focus{border-color:#6366f1;box-shadow:0 0 0 3px rgba(99,102,241,.2)}
button{width:100%;margin-top:16px;padding:11px;border:0;border-radius:9px;background:#4f46e5;color:#fff;font:600 15px inherit;cursor:pointer}
button:hover{background:#4338ca}
button:disabled{opacity:.6;cursor:default}
.error{margin:12px 0 0;padding:9px 12px;border-radius:9px;background:#fef2f2;color:#b91c1c;font-size:13px}
.foot{text-align:center;color:#94a3b8;font-size:12px;margin-top:22px}
`;

export const SETUP_JS = `
const form = document.getElementById('form');
const input = document.getElementById('url');
const button = document.getElementById('go');
const error = document.getElementById('error');
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  error.hidden = true;
  button.disabled = true;
  button.textContent = 'Checking…';
  try {
    await window.enclavierDesktop.connect(input.value);
  } catch (err) {
    // Electron prefixes errors thrown in the main process.
    error.textContent = String(err && err.message || err).replace(/^Error invoking remote method '[^']+': (Error: )?/, '');
    error.hidden = false;
    button.disabled = false;
    button.textContent = 'Connect';
  }
});
`;
