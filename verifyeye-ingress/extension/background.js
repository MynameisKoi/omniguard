// when we catch a phishing page we take the address its form was posting to and
// tell chrome to block every request going to that host. this is the network-level
// lock: even if the page skips the form and fires a raw fetch() to the attacker,
// the request dies here. the content script's submit block is the first lock, this
// is the backstop.
function blockHost(url) {
    if (!url) return;
    try {
        const host = new URL(url).hostname;
        chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [{
                id: Math.floor(Math.random() * 1e6),  // random so we don't clash with an existing rule id
                priority: 1,
                action: {type: "block"},
                condition: {
                    urlFilter: `||${host}`,
                    resourceTypes: ["main_frame", "sub_frame", "xmlhttprequest", "ping", "other"],
                },
            }],
            removeRuleIds: [],
        });
    } catch (e) {}  // a weird/relative action url just means nothing to block
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type == "phishing_detected") {
        // lock down the harvester host before anything else
        blockHost(msg.alert.action_endpoint);

        fetch("http://localhost:8000/alerts", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(msg.alert),
        })
        .then(r => r.json())
        .then(data => sendResponse({ok: true, data}))
        .catch(err => sendResponse({ok: false, error: String(err)}));
        return true
    }
});

// we are going to fetch the list of brands that we have right now 
function cacheBrands() {
    fetch("http://localhost:8000/brands")
    .then(r => r.json())
    .then(brands => chrome.storage.local.set({brands}))
    .catch(() => {}) // keep whatever is in the cached
}

// going to run these on installed and on startup
chrome.runtime.onInstalled.addListener(cacheBrands);
chrome.runtime.onStartup.addListener(cacheBrands);