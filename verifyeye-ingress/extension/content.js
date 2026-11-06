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

let guardObserver = null;
function guard() {
  guardObserver = new MutationObserver(() => {
    // if the page re enables any field or deletes our banner we will put it back
    const tampered = [...document.querySelectorAll('input')].some(el => !el.disabled)
      || !document.getElementById('verifyeye-banner');
    if (tampered) { freeze(); showBanner(); }
  })
  guardObserver.observe(document.documentElement, { childList: true, subtree: true, attributes: true });
}

function unfreeze() {
  if (guardObserver) guardObserver.disconnect();
  document.querySelectorAll('input, textarea, select, button').forEach(el => {
    el.disabled = false;
    el.classList.remove('ve-flagged');
  });
  document.getElementById('verifyeye-banner')?.remove();
}

let verified = false;
function verifyWithAgent() {
  if (verified) return;
  verified = true;
  chrome.runtime.sendMessage({ type: "verify", url: location.href }, (res) => {
    if (!res || !res.ok || !res.verdict) return;
    const v = res.verdict;
    const frozen = !!document.getElementById('verifyeye-banner');
    if (v.phishing && !frozen) {
      freeze();
      showBanner();
      guard();
      report();
    } else if (!v.phishing && v.credential_form && !v.off_domain && frozen) {
      unfreeze();
    }
  });
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

function registrableDomain(host) {
  return host.toLowerCase().split(".").slice(-2).join(".");
}

function submitsOffDomain() {
  const field = document.querySelector('input[type="password"], input[type="email"]');
  const action = field?.closest("form")?.getAttribute("action");
  if (!action) return false;
  let actionHost;
  try {
    actionHost = new URL(action, location.href).hostname;
  } catch {
    return false;
  }
  return registrableDomain(actionHost) !== registrableDomain(location.hostname);
}

function editDistance(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 0; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }
  return dp[a.length][b.length];
}

function looksLikeTyposquat(brands) {
  const host = registrableDomain(location.hostname);
  return brands.some(brand =>
    brand.domains.some(domain => {
      const d = registrableDomain(domain);
      const dist = editDistance(host, d);
      return dist > 0 && dist <= 2;
    })
  );
}

// punycode (RFC 3492) decoder: browsers give us international domains as
// "xn--..." labels, and we need the real characters to judge them
function punyDecode(label) {
  if (!label.startsWith("xn--")) return label;
  const input = label.slice(4);
  const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
  const adapt = (delta, numPoints, first) => {
    delta = first ? Math.floor(delta / damp) : delta >> 1;
    delta += Math.floor(delta / numPoints);
    let k = 0;
    while (delta > ((base - tMin) * tMax) >> 1) { delta = Math.floor(delta / (base - tMin)); k += base; }
    return k + Math.floor(((base - tMin + 1) * delta) / (delta + skew));
  };
  const digit = (c) => c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
  const sep = input.lastIndexOf("-");
  const out = sep > 0 ? [...input.slice(0, sep)].map(c => c.codePointAt(0)) : [];
  let n = 128, i = 0, bias = 72;
  for (let idx = sep > 0 ? sep + 1 : 0; idx < input.length;) {
    const oldi = i;
    for (let w = 1, k = base; ; k += base) {
      const d = digit(input.charCodeAt(idx++));
      if (d >= base) return label;   // not valid punycode: leave it as is
      i += d * w;
      const t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
      if (d < t) break;
      w *= base - t;
    }
    bias = adapt(i - oldi, out.length + 1, oldi === 0);
    n += Math.floor(i / (out.length + 1));
    i %= out.length + 1;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

// Cyrillic / Greek letters that look like Latin ones
const CONFUSABLE = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
  "ј": "j", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ѕ": "s", "ԛ": "q", "ԝ": "w",
  "α": "a", "ο": "o", "ρ": "p", "ν": "v", "τ": "t", "ι": "i", "κ": "k", "χ": "x",
};
const scriptOf = (ch) => /[a-z0-9-]/.test(ch) ? "latin"
  : /[\u0400-\u04ff\u0500-\u052f]/.test(ch) ? "cyrillic"
  : /[\u0370-\u03ff]/.test(ch) ? "greek"
  : /\p{Script=Latin}/u.test(ch) ? "latin" : "other";

// lookalike domains (#7). Used to flag ANY international domain, which hit every
// legit non-English site. Now only what's built to deceive: a label mixing
// Latin with Cyrillic/Greek ("аpple" with a Cyrillic а), or one that reads as
// a known brand's domain once lookalike letters are swapped back
function hasHomoglyphOrPunycode(brands = []) {
  const labels = location.hostname.toLowerCase().split(".").map(punyDecode);
  const brandNames = new Set(brands.flatMap(b => b.domains.map(d => d.split(".")[0])));
  return labels.some(label => {
    if (/^[\x00-\x7f]*$/.test(label)) return false;   // plain ASCII: nothing to fake
    const scripts = new Set([...label].map(scriptOf).filter(s => s !== "other"));
    if (scripts.has("latin") && (scripts.has("cyrillic") || scripts.has("greek"))) return true;
    const skeleton = [...label].map(ch => CONFUSABLE[ch] || ch).join("");
    return brandNames.has(skeleton);
  });
}

function brandAsSubdomain(brands) {
  const labels = location.hostname.toLowerCase().split(".");
  const reg = registrableDomain(location.hostname);
  return brands.some(brand =>
    brand.domains.some(domain => {
      const name = registrableDomain(domain).split(".")[0];
      return labels.includes(name) && !reg.startsWith(name + ".") && reg.split(".")[0] !== name;
    })
  );
}

function scorePage(brands) {
  if (!hasCredentialFields()) return 0;

  let score = 0;
  const brand = detectBrand(brands);

  if (brand && !isLegitDomain(brand)) score += 10;
  if (submitsOffDomain()) score += 40;
  if (looksLikeTyposquat(brands)) score += 30;
  if (hasHomoglyphOrPunycode(brands)) score += 30;
  if (brandAsSubdomain(brands)) score += 25;

  return score;
}

const FREEZE_THRESHOLD = 50;

function runDetection(brands) {
  const froze = scorePage(brands) >= FREEZE_THRESHOLD;

  if (froze) {
    freeze()
    showBanner()
    guard()
    report()
  }

  if (hasCredentialFields()) verifyWithAgent();

  return froze;
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
      verified = false;
      runDetection(brands);
    }
  }, 1000)
})