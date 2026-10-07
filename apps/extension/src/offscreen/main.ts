// Chrome offscreen document: the service worker has no DOM, so clipboard
// clearing happens here. It only ever writes a blank value.
chrome.runtime.onMessage.addListener((msg: { type?: string }) => {
  if (msg.type !== 'offscreen-clear-clipboard') return;
  const t = document.getElementById('clip') as HTMLTextAreaElement;
  t.value = ' ';
  t.select();
  document.execCommand('copy');
  t.value = '';
});
