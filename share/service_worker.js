// must update cache name on any web page change
const cacheName = "kirksud_sw_cache_20250731_1100"

self.addEventListener("fetch", event => {
    const request = event.request
    if (
        request.destination === ""
        || new URL(request.url).protocol !== "https:"
        || request.headers.has("Range")
    )
        return

    event.respondWith((async () => {
        let response = await caches.match(request)
        if (response)
            return response

        response = await fetch(request)
        if (response.status < 400 && response.status !== 206) {
            const cache = await caches.open(cacheName)
            cache.put(request, response.clone())
        }
        return response
    })())
})

self.addEventListener("activate", event => {
    event.waitUntil((async () => {
        const keys = await caches.keys()
        await Promise.all(keys.map(key => caches.delete(key)))
    })())
})
