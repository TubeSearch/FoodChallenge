// Wrapper around fetch that always includes credentials + the header needed to
// bypass ngrok's free-tier browser-warning interstitial (which otherwise returns
// an HTML page instead of JSON and breaks auth checks like the admin gate).
function fcFetch(url, opts) {
  opts = opts || {};
  opts.credentials = 'include';
  opts.headers = Object.assign({ 'ngrok-skip-browser-warning': '1' }, opts.headers || {});
  return fetch(url, opts);
}
// Builds a full image URL for a stored path. DB-uploaded photos are relative
// (e.g. "/uploads/photos/abc.jpg") and need the API origin prepended. JSON-sourced
// challenge images are already full URLs (e.g. foodchallenges.com) and must be
// left untouched, or prepending API mangles them into a broken nested URL.
function imgUrl(path, apiBase) {
  if (!path) return '';
  if (/^https?:\/\//i.test(path)) return path;
  return apiBase + path;
}
function timeAgo(ts) {
  const s = Math.floor((Date.now() - ts) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}
function escHtml(s) {
  return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function fmtDate(ts) {
  return new Date(ts).toLocaleDateString(undefined,{year:'numeric',month:'short',day:'numeric'});
}
