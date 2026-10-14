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