/* OmniGuard service worker — receives web push and shows the notification,
   so the analyst is told even when the dashboard is closed / the phone is locked.
   The push carries no sensitive data; tapping it opens the dashboard, which then
   loads the real details from the local server. */

self.addEventListener("install", (event) => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

self.addEventListener("push", (event) => {
  let data = {};
  try { data = event.data ? event.data.json() : {}; } catch (e) { data = {}; }
  const title = data.title || "OmniGuard SOC";
  const options = {
    body: data.body || "An alert needs your attention.",
    icon: "/icon-192.png",
    badge: "/icon-192.png",
    tag: data.tag || "omniguard",
    renotify: true,
    requireInteraction: false,
    data: { url: data.url || "/" },
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  const url = (event.notification.data && event.notification.data.url) || "/";
  event.waitUntil((async () => {
    const wins = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    for (const w of wins) {
      if ("focus" in w) {
        try { await w.navigate(url); } catch (e) { /* cross-origin / not allowed */ }
        return w.focus();
      }
    }
    if (self.clients.openWindow) return self.clients.openWindow(url);
  })());
});
