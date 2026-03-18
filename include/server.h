#pragma once

#include <stdint.h>
#include "../include/analyser.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#endif

/* =========================================================================
 * Thread-safe packet queue
 * ========================================================================= */

#define QUEUE_CAPACITY 1024

typedef struct {
    ParsedPacket packets[QUEUE_CAPACITY];
    int          head;
    int          tail;
    int          count;
    CRITICAL_SECTION lock;
} PacketQueue;

void queue_init(PacketQueue* q);
void queue_destroy(PacketQueue* q);
int  queue_push(PacketQueue* q, const ParsedPacket* pkt);
int  queue_pop(PacketQueue* q, ParsedPacket* out);

/* =========================================================================
 * WebSocket server
 * ========================================================================= */

#define WS_PORT         7681
#define MAX_CLIENTS     16
#define WS_KEY_MAGIC    "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

typedef struct {
    SOCKET   fd;
    int      handshake_done;
    char     recv_buf[4096];
    int      recv_len;
} WsClient;

typedef struct {
    SOCKET     server_fd;
    WsClient   clients[MAX_CLIENTS];
    int        client_count;
    PacketQueue* queue;
    CRITICAL_SECTION lock;
    volatile int running;
} WsServer;

/* Initialise and start the WebSocket server on a background thread */
int  server_start(WsServer* srv, PacketQueue* queue);

/* Stop the server */
void server_stop(WsServer* srv);

/* Push a packet into the queue from the capture thread */
void server_enqueue(WsServer* srv, const ParsedPacket* pkt);