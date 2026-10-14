// finding the password fields in the page 
const credentialFields = document.querySelectorAll(
  'input[type="password"], input[type="email"], ' +
  'input[id*="email" i], input[name*="email" i], input[autocomplete*="email"], ' +
  'input[id*="user" i], input[name*="user" i], input[autocomplete="username"]'
)
// writing the freeze function that will make the inputs, any text area, buttons unclickable
function freeze() {
    // selecting all those elements
    document.querySelectorAll('input, textarea, button, select').forEach(el => {
      el.disabled = true
      if(['password', 'email', 'text'].includes(el.type)) el.classList.add('ve-flagged');
    });

    // not letting the button submit 
    document.querySelectorAll('form button, button[type="submit"]').forEach(b => b.disabled = true);

    // now preventing the forms to be submitted
    document.querySelectorAll('form').forEach(f => f.addEventListener('submit', e => e.preventDefault()));
}

function showBanner() {
  if (document.getElementById('verifyeye-banner')) return;   // don't double-add
  const banner = document.createElement('div');
  banner.id = 'verifyeye-banner';
  banner.innerHTML = `
    <span class="ve-mark">⚠</span>
    <span class="ve-text">
      <span class="ve-title">VerifyEye blocked a phishing page</span>
      <span class="ve-sub">This page is asking for your password but isn't the real site. The login fields are frozen.</span>
    </span>
    <button class="ve-btn" id="ve-leave">Leave</button>`;
  document.body.appendChild(banner);
  document.getElementById('ve-leave').addEventListener('click', () => { window.location.href = 'about:blank'; });
}

function guard() {
  const observer = new MutationObserver(() => {
    // if the page re enables any field or deletes our banner we will put it back 
    const tampered = [...document.querySelectorAll('input')].some(el => !el.disabled)
      || !document.getElementById('verifyeye-banner');
    if (tampered) { freeze(); showBanner(); }
  })
  observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
}

// we will send the post alert to the backend
let reported = false;
function report() {
  if (reported) return;
  reported = true;
  const action = document.querySelector('form')?.getAttribute('action') || null;
  chrome.runtime.sendMessage({
    type: "phishing_detected",
    alert: {
      source: "verifyeye",
      event_type: "phishing_page_detected",
      severity: "critical",
      // host is hardcoded for now — a browser extension can't read the machine's
      // OS hostname (no API, blocked for privacy). real deploy: push it per-machine
      // via managed policy (chrome.storage.managed). demo: make it an options-page
      // setting later. this field is what the graph groups alerts by, so it matters.
      host: "LAPTOP-10",
      domain: location.hostname,
      target_url: location.href,
      action_endpoint: action,
      mitre_technique: "T1566",
      confidence: 0.9,
      description: `Credential form on ${location.hostname} submitting to ${action || "unknown"}.`,
    },
  });
}


if (credentialFields.length > 0) {
    freeze()
    showBanner()
    guard()
    report()
}