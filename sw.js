// 網路優先：有網路就抓最新版並順手存一份；沒網路才用存起來的舊版。
// 每次改版把 CACHE 的數字 +1，舊快取會自動清掉。
const CACHE = "huikao-v4";
const ASSETS = [
  "./", "./index.html", "./manifest.json", "./data/math-kx-108.json",
  "./icon-192.png", "./icon-512.png", "./apple-touch-icon.png", "./vendor/supabase.js"
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  if (e.request.method !== "GET") return;
  if (e.request.url.indexOf("supabase.co") !== -1) return;  // 雲端資料讀寫不快取
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        // 網址有 ?…（例：學生連結 ?s=代碼）不存進快取，避免代碼留在快取裡；離線時用 ignoreSearch 找回同一頁
        if (!new URL(e.request.url).search) {
          const copy = res.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
        }
        return res;
      })
      .catch(() => caches.match(e.request, { ignoreSearch: true }).then((r) => r || caches.match("./index.html")))
  );
});
