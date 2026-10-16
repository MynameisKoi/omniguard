// finding the password fields in the page 
// making this as a function 
function hasCredentialFields() {
  return document.querySelectorAll(
    'input[type="password"], input[type="email"], ' +
    'input[id*="email" i], input[name*="email" i], input[autocomplete*="email"], ' +
    'input[id*="user" i], input[name*="user" i], input[autocomplete="username"]'
  ).length > 0;
}

// writing the freeze function that will lock the credential fields
function freeze() {
    // lock the credential fields but leave normal buttons alone. a phishing page
    // can have a legit-looking "continue with google" that opens another fake
    // popup — we want the user to still trigger it so we catch that popup too.
    // only the credential fields + the submit buttons get disabled.
    document.querySelectorAll('input, textarea, select').forEach(el => {
      el.disabled = true
      if(['password', 'email', 'text'].includes(el.type)) el.classList.add('ve-flagged');
    });

    // not letting the form submit — only the submit buttons, NOT other buttons
    // inside the form (an oauth "continue with google" is type=button and must
    // stay clickable so we catch the popup it opens).
    document.querySelectorAll('button[type="submit"], input[type="submit"]').forEach(b => b.disabled = true);

    // stopping every form submit in one shot. we listen on the document in the
    // capture phase (the true at the end) so we catch it on the way down, before
    // the page's own handler can grab the password and send it off. stopPropagation
    // means the page never even hears about the submit.
    document.addEventListener('submit', e => {
      e.preventDefault();
      e.stopPropagation();
    }, true);
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


// now we have brands fetched from the database we will use the cached value and then use that to verify against 
// so that not every page is blocked.
// we will also have backend validation but for now we will have this for frontend
function detectBrand(brands) {
  // this will give me the entire page texts in lowercase
  const text = (document.title + " " + document.body.innerText).toLowerCase();

  // looping over the brands 
  for (const brand of brands) {
    // if we see any name that matches our brands we will return that one 
    if (brand.keywords.some(kw => text.includes(kw))) {
      return brand;
    }
  }

  return null;
}

// another function to check if the found text is actually corresponding to the domain 
function isLegitDomain(brand) {
  const host = location.hostname.toLowerCase();

  return brand.domains.some(domain => 
    host === domain || host.endsWith("." + domain)
  ); 
}

// we will write a function to run the detection 
function runDetection(brands) {
  const brand = detectBrand(brands);

  if (hasCredentialFields() && brand && !isLegitDomain(brand)) {
    freeze()
    showBanner()
    guard()
    report()
    return true;
  }

  return false;
}

chrome.storage.local.get("brands", (d) => {
  const brands = d.brands || [];

  // if we have any brands and not legit we do this
  if (!runDetection(brands)) {
    const obs = new MutationObserver(() => {
      if (runDetection(brands)) obs.disconnect();   // caught the late form → done
    });
    obs.observe(document.body, { childList: true, subtree: true });
  }

  let lastUrl = location.href;
  setInterval(() => {
    if (location.href !== lastUrl) {
      lastUrl = location.href;
      reported = false;
      runDetection(brands);
    }
  }, 1000)
})