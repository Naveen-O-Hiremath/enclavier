# Enclavier browser extension

Manifest V3 extension for Chrome, Edge, Brave, Opera and Firefox (115+).

## Features

- **Autofill**
  - The **Fill** button in the popup.
  - The **Enclavier icon inside login fields**, which opens a login picker for that site.
  - The keyboard shortcut **Ctrl+Shift+L** (⌘⇧L on Mac), which fills the best match.
  - Sign-in pages that use frameworks (React/Vue/Angular) fill correctly.
- **Launch & fill:** opens a login's website and fills it once the page loads.
- **Save on submit:** after you sign in somewhere new, or with a changed password, a bar offers to save or update the login.
  - You can choose **Never for this site**.
  - A web page cannot click **Save** on your behalf.
- **Copy:** username, password or 2FA code.
  - The clipboard is cleared after 30 seconds, or sooner if your organization's policy says so.
- **Password generator.**
- **Auto-lock:** after inactivity, when your computer locks, and when the browser closes. Organization vault-timeout policies apply.
- **"Use-only" shared items** (collection permission *use*) can be autofilled but not revealed or copied.

## Security model

- **Where the vault lives:**
  - The vault is decrypted only in the background worker.
  - Unlocked keys are held in `chrome.storage.session`, which lives in memory, is never written to disk, and can't be read by content scripts.
- **What the page side can do:** content scripts can only report a submitted form and receive values to fill.
  - Values are sent only to a tab whose address matches the login.
- **URL matching:**
  - Matching compares registrable domains using the public-suffix list, so `a.github.io` and `b.github.io` are different sites.
  - Logins saved for https are never filled into http pages.
  - IP addresses and localhost must match exactly, including the port.
  - Only frames on the page's own origin are filled.
- **The in-page picker** is an extension page in an iframe. The website around it can't read the list, and it only ever receives names and usernames.

## Build and install

```bash
npm install
npm run build -w @enclavier/extension
```

- **Chrome / Edge / Brave:**
  1. Open `chrome://extensions`.
  2. Turn on **Developer mode**.
  3. Click **Load unpacked** and choose `apps/extension/dist/chrome`.
- **Firefox:**
  1. Open `about:debugging#/runtime/this-firefox`.
  2. Click **Load Temporary Add-on** and choose `apps/extension/dist/firefox/manifest.json`.
  3. Allow site access when asked.

In the popup, enter your server address (for example `https://vault.codearrive.in`, or `http://localhost:8088` for the local Docker stack), then your e-mail and master password.

## Not yet supported

- Signing in with **SSO**. Members of organizations that require SSO use the web vault for now.
- **Security-key 2FA** inside the extension. Use an authenticator app or a recovery code.
- **Safari** (needs an Xcode wrapper) and **store publishing**. These come with the desktop and mobile phases.
