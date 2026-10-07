import { contextBridge, ipcRenderer } from 'electron';

// The only bridge between pages and the app: the setup page asks to connect
// to a server. The main process checks who is asking and verifies the server.
contextBridge.exposeInMainWorld('enclavierDesktop', {
  connect: (serverUrl: string): Promise<string> => ipcRenderer.invoke('enclavier:connect', serverUrl) as Promise<string>,
});
