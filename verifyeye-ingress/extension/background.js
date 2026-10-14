chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type == "phishing_detected") {
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