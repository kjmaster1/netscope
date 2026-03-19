#include "../include/dns_cache.h"
#include "../include/analyser.h"
#include <stdio.h>
#include <string.h>

/* =========================================================================
 * Internal helpers
 * ========================================================================= */

static int ip_equal(const uint8_t a[4], const uint8_t b[4]) {
    return a[0] == b[0] && a[1] == b[1] &&
           a[2] == b[2] && a[3] == b[3];
}

/*
 * Find a cache entry by IP. Returns NULL if not found.
 * Must be called with the lock held.
 */
static DnsCacheEntry* find_entry(DnsCache* cache,
                                  const uint8_t ip[4]) {
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (cache->entries[i].state != DNS_STATE_EMPTY &&
            ip_equal(cache->entries[i].ip, ip)) {
            return &cache->entries[i];
        }
    }
    return NULL;
}

/*
 * Find an empty slot or evict the oldest entry.
 * Must be called with the lock held.
 */
static DnsCacheEntry* alloc_entry(DnsCache* cache) {
    /* First try to find an empty slot */
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (cache->entries[i].state == DNS_STATE_EMPTY) {
            return &cache->entries[i];
        }
    }

    /* Evict the oldest resolved entry */
    DnsCacheEntry* oldest = NULL;
    DWORD oldest_time = 0xFFFFFFFF;
    for (int i = 0; i < DNS_CACHE_SIZE; i++) {
        if (cache->entries[i].state == DNS_STATE_RESOLVED &&
            cache->entries[i].resolved_at < oldest_time) {
            oldest_time = cache->entries[i].resolved_at;
            oldest = &cache->entries[i];
        }
    }
    return oldest;
}

/*
 * Queue an IP for background resolution.
 * Must be called with the lock held.
 */
static void queue_pending(DnsCache* cache, const uint8_t ip[4]) {
    if (cache->pending_count >= DNS_CACHE_SIZE) return;
    memcpy(cache->pending[cache->pending_tail], ip, 4);
    cache->pending_tail = (cache->pending_tail + 1) % DNS_CACHE_SIZE;
    cache->pending_count++;
}

/*
 * Pop an IP from the pending queue.
 * Returns 1 if successful, 0 if empty.
 * Must be called with the lock held.
 */
static int dequeue_pending(DnsCache* cache, uint8_t ip[4]) {
    if (cache->pending_count == 0) return 0;
    memcpy(ip, cache->pending[cache->pending_head], 4);
    cache->pending_head = (cache->pending_head + 1) % DNS_CACHE_SIZE;
    cache->pending_count--;
    return 1;
}

/* =========================================================================
 * Background DNS resolution thread
 * ========================================================================= */

static DWORD WINAPI dns_thread(LPVOID param) {
    DnsCache* cache = (DnsCache*)param;

    while (cache->running) {
        uint8_t ip[4];
        int has_work = 0;

        /* Pop one pending IP */
        EnterCriticalSection(&cache->lock);
        has_work = dequeue_pending(cache, ip);
        LeaveCriticalSection(&cache->lock);

        if (!has_work) {
            /* Nothing to resolve — sleep briefly */
            Sleep(10);
            continue;
        }

        /*
         * Perform the reverse DNS lookup.
         * getnameinfo() is the modern, thread-safe way to do this.
         * We pass a sockaddr_in with the IP and ask for the hostname.
         */
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        memcpy(&addr.sin_addr, ip, 4);

        char hostname[DNS_MAX_HOST];
        int result = getnameinfo(
            (struct sockaddr*)&addr,
            sizeof(addr),
            hostname,
            sizeof(hostname),
            NULL, 0,          /* we don't need the service name */
            NI_NAMEREQD       /* fail if no hostname found */
        );

        /* Update the cache entry */
        EnterCriticalSection(&cache->lock);
        DnsCacheEntry* entry = find_entry(cache, ip);
        if (entry) {
            if (result == 0) {
                /* Successfully resolved */
                strncpy_s(entry->hostname,
                          sizeof(entry->hostname),
                          hostname,
                          sizeof(entry->hostname) - 1);
                entry->state = DNS_STATE_RESOLVED;
            } else {
                /* Failed — store IP as hostname so we don't retry */
                format_ip(ip, entry->hostname);
                entry->state = DNS_STATE_FAILED;
            }
            entry->resolved_at = GetTickCount();
        }
        LeaveCriticalSection(&cache->lock);
    }

    return 0;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

void dns_cache_init(DnsCache* cache) {
    memset(cache, 0, sizeof(DnsCache));
    InitializeCriticalSection(&cache->lock);
    cache->running = 1;
    cache->thread = CreateThread(NULL, 0, dns_thread,
                                  cache, 0, NULL);
}

void dns_cache_destroy(DnsCache* cache) {
    cache->running = 0;
    if (cache->thread) {
        WaitForSingleObject(cache->thread, 2000);
        CloseHandle(cache->thread);
    }
    DeleteCriticalSection(&cache->lock);
}

const char* dns_lookup(DnsCache* cache, const uint8_t ip[4]) {
    EnterCriticalSection(&cache->lock);

    DnsCacheEntry* entry = find_entry(cache, ip);

    if (entry) {
        /*
         * Found in cache. Check if TTL has expired for resolved entries.
         * Failed entries we also retry after TTL.
         */
        DWORD age = GetTickCount() - entry->resolved_at;
        if ((entry->state == DNS_STATE_RESOLVED ||
             entry->state == DNS_STATE_FAILED) &&
            age > DNS_TTL_SECONDS * 1000) {
            /* Expired — re-queue for resolution */
            entry->state = DNS_STATE_PENDING;
            queue_pending(cache, ip);
        }

        const char* result = entry->hostname;
        LeaveCriticalSection(&cache->lock);
        return result;
    }

    /* Not in cache — create a pending entry */
    entry = alloc_entry(cache);
    if (entry) {
        memcpy(entry->ip, ip, 4);
        format_ip(ip, entry->hostname);  /* use IP until resolved */
        entry->state = DNS_STATE_PENDING;
        entry->resolved_at = 0;
        queue_pending(cache, ip);
    }

    /* Return the IP string for now */
    /* We need a stable pointer — find the entry we just created */
    entry = find_entry(cache, ip);
    const char* result = entry ? entry->hostname : "unknown";
    LeaveCriticalSection(&cache->lock);
    return result;
}