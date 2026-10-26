
/* GoRelay Pro Service Worker
 * 策略：网络优先、离线回退；图标与 manifest 在安装阶段预缓存，
 * 保证「添加到主屏幕」后即使断网也能立即渲染出正确的图标与启动图。
 *
 * 注意：CACHE_NAME 必须在图标资源变更时同步升级，否则旧图标会被永久命中。
 */
const CACHE_NAME = 'gorelay-pwa-v3';

const PRECACHE = [
    '/manifest.json',
    '/icons/icon-192.png?v=2',
    '/icons/icon-512.png?v=2',
    '/icons/icon-maskable-192.png?v=2',
    '/icons/icon-maskable-512.png?v=2',
    '/icons/apple-touch-icon.png?v=2',
    '/icons/favicon-32.png?v=2',
    '/icons/icon.svg?v=2'
];

self.addEventListener('install', event => {
    self.skipWaiting();
    event.waitUntil(
        caches.open(CACHE_NAME)
            // 单个资源失败不影响整体安装
            .then(cache => Promise.allSettled(PRECACHE.map(url => cache.add(url))))
            .catch(() => {})
    );
});

self.addEventListener('activate', event => {
    event.waitUntil(
        caches.keys()
            .then(keys => Promise.all(keys.filter(k => k !== CACHE_NAME).map(k => caches.delete(k))))
            .then(() => self.clients.claim())
    );
});

self.addEventListener('fetch', event => {
    if (event.request.method !== 'GET') return;

    const url = new URL(event.request.url);

    // 图标：网络优先、离线回退缓存。
    // 不用 cache-first —— 图标一旦改版，cache-first 会永久吐旧图（这正是 v2 的坑）。
    // 图标体积很小，且请求本身还会走浏览器 HTTP 缓存，网络优先的代价可以忽略。
    if (url.origin === self.location.origin && url.pathname.startsWith('/icons/')) {
        event.respondWith(
            fetch(event.request).then(res => {
                if (res && res.ok) {
                    const copy = res.clone();
                    caches.open(CACHE_NAME).then(c => c.put(event.request, copy));
                }
                return res;
            }).catch(() =>
                caches.match(event.request).then(hit => hit || new Response('', { status: 504, statusText: 'Offline' }))
            )
        );
        return;
    }

    // 其余请求：网络优先，失败回退缓存
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
