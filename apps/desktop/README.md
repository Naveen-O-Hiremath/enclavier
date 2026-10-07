# Enclavier for Windows

A desktop app for Windows 10 and 11 (x64). It is the same vault as the web version, in its own locked-down window.

## What it adds over the browser

- **Its own window and Start-menu entry**, separate from your browser tabs and extensions.
- **Locks with Windows:** the vault locks when you lock the computer (Win+L) or it goes to sleep. `Ctrl+L` locks it by hand.
- **Block screen capture** (View menu): hides the window from screenshots, screen sharing and recordings.
- **Launch** buttons open websites in your default browser.
- **Works with any Enclavier server:** on first start you enter your server's address. *File → Change server* switches later.

## Security model

- The vault's code ships **inside the app**. Nothing executable is downloaded from the server; only API calls go over the network, to the server you chose.
- The vault page runs sandboxed with no access to Node.js or the file system. It can't open other windows, can't be navigated to another address and can't call any host except the app's own API proxy.
- Single sign-on opens your identity provider in a separate, throwaway window that has no access to the vault.
- The server address must be `https://` (plain `http://` is accepted only for `localhost`), and the app checks that it really is an Enclavier server before saving it.
- Spell-checking is off, so vault text is never sent to a spelling service.

## Install

Run `Enclavier-Setup-<version>.exe` from the release page. It installs for the current user and doesn't need administrator rights.

The installer is not code-signed yet, so Windows SmartScreen shows a warning ("Windows protected your PC"). Choose **More info → Run anyway**, or see below to sign your own build.

## Build it yourself

```bash
npm install
npm run build:desktop        # → apps/desktop/release/Enclavier-Setup-<version>.exe
```

To run without packaging: `npm run start -w @enclavier/desktop`.

### Code signing

Set these before building and the installer is signed automatically:

```powershell
$env:CSC_LINK = 'C:\path\to\certificate.pfx'
$env:CSC_KEY_PASSWORD = '...'
```

The release workflow reads the same values from the `WINDOWS_CERTIFICATE` and `WINDOWS_CERTIFICATE_PASSWORD` repository secrets.

## Not yet supported

- **Security keys and passkeys** as a second factor inside the app. Use an authenticator app or a recovery code, or sign in through the web vault.
- **Windows Hello** unlock and **automatic updates**. Install a newer version over the old one to update.
- macOS and Linux builds.
