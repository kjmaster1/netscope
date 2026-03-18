#include "../include/server.h"
#include "../include/analyser.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <wincrypt.h>
#endif

/* =========================================================================
 * Thread-safe queue implementation
 * ========================================================================= */

void queue_init(PacketQueue* q) {
    memset(q, 0, sizeof(PacketQueue));
    InitializeCriticalSection(&q->lock);
}

void queue_destroy(PacketQueue* q) {
    DeleteCriticalSection(&q->lock);
}

int queue_push(PacketQueue* q, const ParsedPacket* pkt) {
    EnterCriticalSection(&q->lock);
    if (q->count >= QUEUE_CAPACITY) {
        LeaveCriticalSection(&q->lock);
        return 0;  /* queue full — drop packet */
    }
    q->packets[q->tail] = *pkt;
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count++;
    LeaveCriticalSection(&q->lock);
    return 1;
}

int queue_pop(PacketQueue* q, ParsedPacket* out) {
    EnterCriticalSection(&q->lock);
    if (q->count == 0) {
        LeaveCriticalSection(&q->lock);
        return 0;
    }
    *out = q->packets[q->head];
    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count--;
    LeaveCriticalSection(&q->lock);
    return 1;
}

/* =========================================================================
 * Base64 encoding — needed for WebSocket handshake
 * ========================================================================= */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void base64_encode(const uint8_t* in, int in_len,
                           char* out, int out_size) {
    int i = 0, j = 0;
    uint8_t buf[3];
    char enc[5];
    enc[4] = '\0';

    while (in_len > 0) {
        int chunk = in_len >= 3 ? 3 : in_len;
        memset(buf, 0, 3);
        memcpy_s(buf, 3, in + i, chunk);

        enc[0] = b64_table[(buf[0] >> 2) & 0x3F];
        enc[1] = b64_table[((buf[0] & 0x03) << 4) |
                            ((buf[1] >> 4) & 0x0F)];
        enc[2] = chunk > 1 ? b64_table[((buf[1] & 0x0F) << 2) |
                            ((buf[2] >> 6) & 0x03)] : '=';
        enc[3] = chunk > 2 ? b64_table[buf[2] & 0x3F] : '=';

        if (j + 4 < out_size) {
            memcpy_s(out + j, out_size - j, enc, 4);
            j += 4;
        }
        i += chunk;
        in_len -= chunk;
    }
    if (j < out_size) out[j] = '\0';
}

/* =========================================================================
 * SHA-1 — needed for WebSocket handshake accept key
 * We use Windows CryptoAPI to avoid implementing SHA-1 ourselves
 * ========================================================================= */

static int sha1_base64(const char* input, char* out, int out_size) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    uint8_t digest[20];
    DWORD digest_len = 20;
    int ok = 0;

    if (!CryptAcquireContext(&prov, NULL, NULL,
                              PROV_RSA_FULL,
                              CRYPT_VERIFYCONTEXT)) {
        return 0;
    }

    if (!CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0);
        return 0;
    }

    if (CryptHashData(hash, (const BYTE*)input,
                      (DWORD)strlen(input), 0) &&
        CryptGetHashParam(hash, HP_HASHVAL,
                          digest, &digest_len, 0)) {
        base64_encode(digest, 20, out, out_size);
        ok = 1;
    }

    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    return ok;
}

/* =========================================================================
 * HTTP handler — serves the dashboard HTML
 * ========================================================================= */

#include "../include/dashboard_html.h"

static int is_websocket_request(const char* buf) {
    return strstr(buf, "Upgrade: websocket") != NULL ||
           strstr(buf, "Upgrade: WebSocket") != NULL;
}

static void serve_http(SOCKET fd) {
    /* Send HTTP/1.1 200 with the embedded dashboard HTML */
    const char* header =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/html; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n";

    send(fd, header, (int)strlen(header), 0);
    send(fd, DASHBOARD_HTML, (int)strlen(DASHBOARD_HTML), 0);
    closesocket(fd);
}

/* =========================================================================
 * WebSocket handshake
 * ========================================================================= */

static int ws_do_handshake(WsClient* client) {
    /* Find the Sec-WebSocket-Key header */
    char* key_start = strstr(client->recv_buf, "Sec-WebSocket-Key:");
    if (!key_start) return 0;

    key_start += 18;  /* skip "Sec-WebSocket-Key:" */
    while (*key_start == ' ') key_start++;

    char key[64] = {0};
    int i = 0;
    while (key_start[i] && key_start[i] != '\r' &&
           key_start[i] != '\n' && i < 63) {
        key[i] = key_start[i];
        i++;
    }
    key[i] = '\0';

    /* Concatenate key with magic string and compute SHA-1 + base64 */
    char combined[256];
    snprintf(combined, sizeof(combined), "%s%s", key, WS_KEY_MAGIC);

    char accept_key[64];
    if (!sha1_base64(combined, accept_key, sizeof(accept_key))) {
        return 0;
    }

    /* Send 101 Switching Protocols response */
    char response[512];
    snprintf(response, sizeof(response),
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        accept_key);

    send(client->fd, response, (int)strlen(response), 0);
    client->handshake_done = 1;
    return 1;
}

/* =========================================================================
 * WebSocket frame sender
 * Sends a text frame containing 'payload'
 * ========================================================================= */

static void ws_send_text(SOCKET fd, const char* payload) {
    size_t payload_len = strlen(payload);
    uint8_t header[10];
    int header_len = 0;

    /* FIN bit set (0x80) + opcode 1 (text frame) */
    header[0] = 0x81;

    if (payload_len <= 125) {
        header[1] = (uint8_t)payload_len;
        header_len = 2;
    } else if (payload_len <= 65535) {
        header[1] = 126;
        header[2] = (uint8_t)(payload_len >> 8);
        header[3] = (uint8_t)(payload_len & 0xFF);
        header_len = 4;
    } else {
        /* We won't send frames this large */
        return;
    }

    send(fd, (const char*)header, header_len, 0);
    send(fd, payload, (int)payload_len, 0);
}

/* =========================================================================
 * JSON serialiser
 * ========================================================================= */

static void packet_to_json(const ParsedPacket* pkt,
                            char* buf, int buf_len) {
    char src_ip[16], dst_ip[16];
    format_ip(pkt->src_ip, src_ip);
    format_ip(pkt->dst_ip, dst_ip);

    /* Determine well-known port service name */
    const char* service = "";
    uint16_t port = pkt->dst_port < pkt->src_port
                  ? pkt->dst_port : pkt->src_port;
    if (port == 80)   service = "HTTP";
    else if (port == 443)  service = "HTTPS";
    else if (port == 53)   service = "DNS";
    else if (port == 5353) service = "mDNS";
    else if (port == 22)   service = "SSH";
    else if (port == 25)   service = "SMTP";
    else if (port == 1900) service = "SSDP";

    snprintf(buf, buf_len,
        "{"
        "\"proto\":\"%s\","
        "\"src_ip\":\"%s\","
        "\"src_port\":%d,"
        "\"dst_ip\":\"%s\","
        "\"dst_port\":%d,"
        "\"length\":%d,"
        "\"service\":\"%s\","
        "\"ttl\":%d"
        "}",
        protocol_name(pkt->protocol),
        src_ip, pkt->src_port,
        dst_ip, pkt->dst_port,
        pkt->packet_len,
        service,
        pkt->ttl
    );
}

/* =========================================================================
 * Server thread
 * ========================================================================= */

static DWORD WINAPI server_thread(LPVOID param) {
    WsServer* srv = (WsServer*)param;

    while (srv->running) {
        /* Build fd_set for select() */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(srv->server_fd, &read_fds);

        EnterCriticalSection(&srv->lock);
        for (int i = 0; i < srv->client_count; i++) {
            FD_SET(srv->clients[i].fd, &read_fds);
        }
        LeaveCriticalSection(&srv->lock);

        /* 10ms timeout so we can check the queue regularly */
        struct timeval tv = {0, 10000};
        int ready = select(0, &read_fds, NULL, NULL, &tv);

        if (ready > 0) {
            /* New connection? */
            if (FD_ISSET(srv->server_fd, &read_fds)) {
                SOCKET client_fd = accept(srv->server_fd,
                                          NULL, NULL);
                if (client_fd != INVALID_SOCKET) {
                    EnterCriticalSection(&srv->lock);
                    if (srv->client_count < MAX_CLIENTS) {
                        WsClient* c =
                            &srv->clients[srv->client_count++];
                        memset(c, 0, sizeof(WsClient));
                        c->fd = client_fd;
                        printf("[server] Client connected\n");
                    } else {
                        closesocket(client_fd);
                    }
                    LeaveCriticalSection(&srv->lock);
                }
            }

            /* Data from existing clients */
            EnterCriticalSection(&srv->lock);
            for (int i = 0; i < srv->client_count; i++) {
                WsClient* c = &srv->clients[i];
                if (!FD_ISSET(c->fd, &read_fds)) continue;

                int n = recv(c->fd,
                            c->recv_buf + c->recv_len,
                            sizeof(c->recv_buf) - c->recv_len - 1,
                            0);

                if (n <= 0) {
                    printf("[server] Client disconnected\n");
                    closesocket(c->fd);
                    memmove(&srv->clients[i],
                            &srv->clients[i + 1],
                            (srv->client_count - i - 1)
                                * sizeof(WsClient));
                    srv->client_count--;
                    i--;
                    continue;
                }

                c->recv_len += n;
                c->recv_buf[c->recv_len] = '\0';

                if (!c->handshake_done) {
                    if (strstr(c->recv_buf, "\r\n\r\n")) {
                        if (is_websocket_request(c->recv_buf)) {
                            ws_do_handshake(c);
                            c->recv_len = 0;
                            memset(c->recv_buf, 0,
                                sizeof(c->recv_buf));
                        } else {
                            /* HTTP request — serve dashboard and close */
                            serve_http(c->fd);
                            memmove(&srv->clients[i],
                                    &srv->clients[i + 1],
                                    (srv->client_count - i - 1)
                                        * sizeof(WsClient));
                            srv->client_count--;
                            i--;
                        }
                    }
                }
            }
            LeaveCriticalSection(&srv->lock);
        }

        /* Drain the packet queue and broadcast to all clients */
        ParsedPacket pkt;
        while (queue_pop(srv->queue, &pkt)) {
            char json[512];
            packet_to_json(&pkt, json, sizeof(json));

            EnterCriticalSection(&srv->lock);
            for (int i = 0; i < srv->client_count; i++) {
                if (srv->clients[i].handshake_done) {
                    ws_send_text(srv->clients[i].fd, json);
                }
            }
            LeaveCriticalSection(&srv->lock);
        }
    }

    return 0;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

int server_start(WsServer* srv, PacketQueue* queue) {
    memset(srv, 0, sizeof(WsServer));
    srv->queue   = queue;
    srv->running = 1;
    InitializeCriticalSection(&srv->lock);

    /* Create TCP socket */
    srv->server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv->server_fd == INVALID_SOCKET) {
        fprintf(stderr, "[server] Failed to create socket\n");
        return 0;
    }

    /* Allow port reuse */
    int opt = 1;
    setsockopt(srv->server_fd, SOL_SOCKET, SO_REUSEADDR,
               (const char*)&opt, sizeof(opt));

    struct sockaddr_in addr = {0};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons(WS_PORT);

    if (bind(srv->server_fd,
             (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        fprintf(stderr, "[server] Bind failed\n");
        closesocket(srv->server_fd);
        return 0;
    }

    if (listen(srv->server_fd, 5) != 0) {
        fprintf(stderr, "[server] Listen failed\n");
        closesocket(srv->server_fd);
        return 0;
    }

    printf("[server] WebSocket server listening on "
           "ws://localhost:%d\n", WS_PORT);

    /* Start server thread */
    HANDLE thread = CreateThread(NULL, 0, server_thread,
                                  srv, 0, NULL);
    if (!thread) {
        fprintf(stderr, "[server] Failed to create thread\n");
        return 0;
    }
    CloseHandle(thread);
    return 1;
}

void server_stop(WsServer* srv) {
    srv->running = 0;
    closesocket(srv->server_fd);
    DeleteCriticalSection(&srv->lock);
}

void server_enqueue(WsServer* srv, const ParsedPacket* pkt) {
    queue_push(srv->queue, pkt);
}