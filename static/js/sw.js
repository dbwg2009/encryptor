const CACHE_NAME = 'cipher-vault-v1';

// Files to cache for offline support
const CACHE_URLS = [
  '/',
  '/static/index.html',
  '/static/app.css',
  '/static/js/crypto.js',
  '/static/js/api.js',
  '/static/js/app.js',
  '/static/manifest.json',
];

// Install event - cache essential files
self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      // Try to cache URLs but don't fail if some are not available
      return Promise.allSettled(
        CACHE_URLS.map((url) => cache.add(url).catch(() => {}))
      );
    }).then(() => self.skipWaiting())
  );
});

// Activate event - clean up old caches
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      );
    }).then(() => self.clients.claim())
  );
});

// Fetch event - cache first, fall back to network
self.addEventListener('fetch', (event) => {
  const { request } = event;

  // Skip non-GET requests
  if (request.method !== 'GET') {
    return;
  }

  // For API calls, use network first
  if (request.url.includes('/api/')) {
    event.respondWith(
      fetch(request)
        .then((response) => response)
        .catch(() => caches.match(request))
    );
    return;
  }

  // For static assets, use cache first
  event.respondWith(
    caches.match(request).then((cached) => {
      return cached || fetch(request).then((response) => {
        // Cache successful responses
        if (response.ok) {
          const cache = caches.open(CACHE_NAME);
          cache.then((c) => c.put(request, response.clone()));
        }
        return response;
      });
    }).catch(() => {
      // Offline fallback
      return new Response('Offline - content not available', {
        status: 503,
        statusText: 'Service Unavailable',
      });
    })
  );
});

// Handle push notifications
self.addEventListener('push', (event) => {
  if (!event.data) {
    return;
  }

  let notificationData;
  try {
    notificationData = event.data.json();
  } catch (e) {
    notificationData = {
      title: 'Cipher Vault',
      body: event.data.text(),
    };
  }

  const options = {
    icon: '/static/icon-192.png',
    badge: '/static/icon-192.png',
    tag: notificationData.tag || 'message',
    requireInteraction: notificationData.requireInteraction || false,
    data: notificationData.data || {},
    vibrate: [200, 100, 200],
  };

  if (notificationData.body) {
    options.body = notificationData.body;
  }

  event.waitUntil(
    self.registration.showNotification(notificationData.title || 'Cipher Vault', options)
  );
});

// Handle notification clicks
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  const { data } = event.notification;
  const urlToOpen = data.url || '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Check if we already have a window open with the target URL
      for (let i = 0; i < clientList.length; i++) {
        const client = clientList[i];
        if (client.url === urlToOpen && 'focus' in client) {
          return client.focus();
        }
      }
      // If not, open a new window
      if (clients.openWindow) {
        return clients.openWindow(urlToOpen);
      }
    })
  );
});

// Handle notification close
self.addEventListener('notificationclose', (event) => {
  // Could track dismissals here if needed
  console.log('Notification closed');
});
