#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#endif

#include <stdint.h>

/* Maximum number of IPs to cache */
#define DNS_CACHE_SIZE    512

/* Maximum hostname length */
#define DNS_MAX_HOST      256

/* How long a cache entry is valid (seconds) */
#define DNS_TTL_SECONDS   300

/* Resolution states */
#define DNS_STATE_EMPTY      0
#define DNS_STATE_PENDING    1
#define DNS_STATE_RESOLVED   2
#define DNS_STATE_FAILED     3

typedef struct {
    uint8_t  ip[4];
    char     hostname[DNS_MAX_HOST];
    int      state;
    DWORD    resolved_at;   /* GetTickCount() timestamp */
} DnsCacheEntry;

typedef struct {
    DnsCacheEntry    entries[DNS_CACHE_SIZE];
    CRITICAL_SECTION lock;

    /* Pending resolution queue */
    uint8_t          pending[DNS_CACHE_SIZE][4];
    int              pending_head;
    int              pending_tail;
    int              pending_count;

    volatile int     running;
    HANDLE           thread;
} DnsCache;

/*
 * Initialise the cache and start the background resolution thread.
 */
void dns_cache_init(DnsCache* cache);

/*
 * Shutdown the background thread and free resources.
 */
void dns_cache_destroy(DnsCache* cache);

/*
 * Look up an IP address.
 * Returns the hostname if resolved, the dotted-decimal IP if not yet
 * resolved, or if resolution failed.
 * If the IP is not in the cache, queues it for background resolution.
 */
const char* dns_lookup(DnsCache* cache, const uint8_t ip[4]);