
/* GoRelay Pro Service Worker
 * 策略：网络优先、离线回退；图标与 manifest 在安装阶段预缓存，
 * 保证「添加到主屏幕」后即使断网也能立即渲染出正确的图标与启动图。
 */
const CACHE_NAME = 'gorelay-pwa-v2';

const PRECACHE = [
    '/manifest.json',
    '/icons/icon-192.png',
    '/icons/icon-512.png',
    '/icons/icon-maskable-192.png',
    '/icons/icon-maskable-512.png',
    '/icons/apple-touch-icon.png',
    '/icons/favicon-32.png',
    '/icons/icon.svg'
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

    // 图标：缓存优先（内容不变，命中后零网络开销）
    if (url.origin === self.location.origin && url.pathname.startsWith('/icons/')) {
        event.respondWith(
            caches.match(event.request).then(hit => {
                if (hit) return hit;
                return fetch(event.request).then(res => {
                    const copy = res.clone();
                    caches.open(CACHE_NAME).then(c => c.put(event.request, copy));
                    return res;
                }).catch(() => new Response('', { status: 504, statusText: 'Offline' }));
            })
        );
        return;
    }

    // 其余请求：网络优先，失败回退缓存
    event.respondWith(
        fetch(event.request).catch(() => caches.match(event.request))
    );
});
