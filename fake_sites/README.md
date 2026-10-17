# fake_sites — phishing fixtures (LOCAL ONLY)

Static fake login pages used as **targets for our own VerifyEye detector**. They
impersonate real brands and submit credentials off-domain — the exact pattern the
extension is built to catch. **None of these are ever deployed.** No real domains
are registered; the off-domain form actions (e.g. `google-account-verify.com`)
resolve to nothing. They exist only to prove detection works.

## Run them

```bash
./serve.sh        # start every site on its port
./serve.sh stop   # stop them all
```

## Port map

| Site       | Port | Impersonates | Notes |
|------------|------|--------------|-------|
| claude     | 5500 | Claude / Anthropic | real fonts + video; has the Google OAuth popup |
| spa-test   | 5600 | Google | injects the login form late (SPA / Reddit-style) |
| google     | 5700 | Google | the fake OAuth popup window the other sites open |
| netflix    | 5800 | Netflix | |
| tiktok     | 5900 | TikTok | |
| amazon     | 6000 | Amazon | |

## The Google OAuth popup

A real phishing trick: the page shows "Continue with Google", and clicking it
opens a **popup window** with a fake Google login. The popup is its own page
(`google/`, port 5700) living on localhost — so VerifyEye freezes it the same way
it freezes any brand-impersonating page on a non-brand domain.

To add the popup to another fake site, give its Google button `onclick="openGoogleOAuth()"`
and paste this before `</body>`:

```html
<script>
  const GOOGLE_OAUTH_URL = "http://localhost:5700";
  function openGoogleOAuth() {
    const w = 500, h = 600;
    const left = screen.width / 2 - w / 2, top = screen.height / 2 - h / 2;
    window.open(GOOGLE_OAUTH_URL, "google_oauth",
      `width=${w},height=${h},left=${left},top=${top},menubar=no,toolbar=no,location=no`);
  }
</script>
```

## Add a new fake site

1. `mkdir fake_sites/<brand>` with an `index.html` (credential form + off-domain action).
2. Make sure the brand is in the backend `/brands` list (`backend/db.py`) so the
   detector knows the keyword + legit domain.
3. Add `<brand>:<port>` to the `SITES` line in `serve.sh`.
4. Keep the "LOCAL TEST FIXTURE ONLY" comment at the top of the file.

## TODO (after this week)
- Popups on all sites (not just claude).
- Per-site metrics / probability scoring for the confidence model.
- Screenshot capture of each page via the extension (`chrome.tabs.captureVisibleTab`).
