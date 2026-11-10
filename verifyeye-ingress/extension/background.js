// when we catch a phishing page we take the address its form was posting to and
// tell chrome to block every request going to that host. this is the network-level
// lock: even if the page skips the form and fires a raw fetch() to the attacker,
// the request dies here. the content script's submit block is the first lock, this
// is the backstop.
// Where the SOC backend lives. On your own machine this is localhost. To run the
// extension against another laptop (the analyst's machine on the LAN), change
// these two to that laptop's IP, e.g. "http://192.168.1.50:8000".
const CORE = "http://localhost:8000";       // alerts + brands
const VERIFY = "http://localhost:8100";      // visual verify agent

function blockHost(url) {
    if (!url) return;
    try {
        const host = new URL(url).hostname;
        const filter = `||${host}`;
        chrome.declarativeNetRequest.getDynamicRules().then(rules => {
            if (rules.some(r => r.condition.urlFilter === filter)) return;
            const id = rules.reduce((m, r) => Math.max(m, r.id), 0) + 1;
            chrome.declarativeNetRequest.updateDynamicRules({
                addRules: [{
                    id,
                    priority: 1,
                    action: {type: "block"},
                    condition: {
                        urlFilter: filter,
                        resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "ping", "other"],
                    },
                }],
                removeRuleIds: [],
            });
        });
    } catch (e) {}
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type == "phishing_detected") {
        // lock down the harvester host before anything else
        blockHost(msg.alert.action_endpoint);

        fetch(`${CORE}/alerts`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(msg.alert),
        })
        .then(r => r.json())
        .then(data => sendResponse({ok: true, data}))
        .catch(err => sendResponse({ok: false, error: String(err)}));
        return true
    }

    if (msg.type == "verify") {
        fetch(`${VERIFY}/verify`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({url: msg.url}),
        })
        .then(r => r.json())
        .then(verdict => sendResponse({ok: true, verdict}))
        .catch(err => sendResponse({ok: false, error: String(err)}));
        return true
    }
});

// we are going to fetch the list of brands that we have right now 
function cacheBrands() {
    fetch(`${CORE}/brands`)
    .then(r => r.json())
    .then(brands => chrome.storage.local.set({brands}))
    .catch(() => {}) // keep whatever is in the cached
}

// going to run these on installed and on startup
chrome.runtime.onInstalled.addListener(cacheBrands);
chrome.runtime.onStartup.addListener(cacheBrands);