// must update cache name on any web page change
const cacheName = "kirksud_sw_cache_20250208_0000"

self.addEventListener("fetch", event => {
    event.respondWith((async () => {
        const request = event.request
        let response = await caches.match(request)
        if (response)
            return response
        response = await fetch(request)
        if (request.destination !== "" && response.status < 400) {
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
