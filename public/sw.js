/* global self */

self.addEventListener("install", () => {
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(self.clients.claim());
});

// Deliberately no fetch or Cache Storage handler: plaintext messages, address
// cards, and authenticated responses must never enter a service-worker cache.

// Push wakeups are payload-free by design (the keeper sends empty pushes);
// message content stays end-to-end encrypted and decrypts only in the app.
self.addEventListener("push", (event) => {
  event.waitUntil(
    self.registration.showNotification("Fruitful", {
      body: "New activity in an encrypted conversation.",
      icon: "/icon.svg",
      tag: "jbm-messaging-wakeup",
    }),
  );
});

self.addEventListener("notificationclick", (event) => {
  event.notification.close();
  event.waitUntil(
    self.clients
      .matchAll({ type: "window", includeUncontrolled: true })
      .then((clients) => {
        for (const client of clients) {
          if ("focus" in client) return client.focus();
        }
        return self.clients.openWindow("/");
      }),
  );
});
