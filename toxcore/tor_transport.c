/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025 The TokTok team.
 */

#include "tor_transport.h"

#include <string.h>

#include "ccompat.h"
#include "crypto_core.h"
#include "network.h"
#include "util.h"

/** SOCKS5 protocol constants. */
enum Socks5_Proxy_Hs {
    SOCKS5_VERSION               = 0x05,
    SOCKS5_COMMAND_CONNECT       = 0x01,
    SOCKS5_REPLY_SUCCEEDED       = 0x00,
    SOCKS5_AUTH_METHODS          = 0x01,
    SOCKS5_AUTH_NO_AUTH          = 0x00,
    SOCKS5_RESERVED              = 0x00,
    SOCKS5_ATYP_IPV4             = 0x01,
    SOCKS5_ATYP_DOMAINNAME       = 0x03,
    SOCKS5_ATYP_IPV6             = 0x04,
};

/** Number of seconds without activity before a connection is considered stale. */
#define TOR_CONNECTION_REUSE_TIMEOUT 30

struct Tor_Transport {
    const Logger         *log;
    const Memory         *mem;
    const Mono_Time      *mono_time;
    const Random         *rng;
    const Network        *ns;
    Tor_Transport_Config  config;
    Tor_Node_Connection   connections[MAX_TOR_CONNECTIONS];
    uint32_t              num_connections;

    /** Packet handler dispatch table, indexed by first byte of packet. */
    tor_packet_handler_cb *handlers[256];
    void                  *handler_objects[256];
};

/**
 * Find a connection in the pool by (onion_addr, port).
 * @return Index into connections[], or -1 if not found.
 */
static int find_connection(const Tor_Transport *tran,
                           const uint8_t *onion_addr, uint16_t port)
{
    for (uint32_t i = 0; i < tran->num_connections; ++i) {
        const Tor_Node_Connection *conn = &tran->connections[i];
        if (conn->port == port
                && conn->status != TOR_NODE_DISCONNECTED
                && memcmp(conn->onion_addr, onion_addr, ONION_V3_ADDRESS_SIZE) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Find a free slot in the connections array.
 * @return Index into connections[], or -1 if the pool is full.
 */
static int find_free_slot(Tor_Transport *tran)
{
    for (uint32_t i = 0; i < MAX_TOR_CONNECTIONS; ++i) {
        if (tran->connections[i].status == TOR_NODE_DISCONNECTED) {
            return (int)i;
        }
    }
    return -1;
}

/**
 * Close a connection and mark it as DISCONNECTED.
 */
static void close_connection(Tor_Transport *tran, uint32_t index)
{
    Tor_Node_Connection *conn = &tran->connections[index];
    if (conn->status != TOR_NODE_DISCONNECTED && sock_valid(conn->sock)) {
        kill_sock(tran->ns, conn->sock);
    }
    memset(conn, 0, sizeof(Tor_Node_Connection));
    conn->status = TOR_NODE_DISCONNECTED;
}

/**
 * Open a new TCP socket and connect to the SOCKS5 proxy.
 * The socket is set to non-blocking.
 *
 * @return true on success (connect initiated), false on failure.
 */
static bool open_proxy_connection(Tor_Transport *tran, Tor_Node_Connection *conn)
{
    const Network *ns = tran->ns;

    Socket sock = net_socket(ns, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    if (!sock_valid(sock)) {
        LOGGER_ERROR(tran->log, "tor_transport: failed to create TCP socket");
        return false;
    }

    if (!set_socket_nonblock(ns, sock)) {
        LOGGER_WARNING(tran->log, "tor_transport: failed to set socket nonblock");
    }

    if (!set_socket_nosigpipe(ns, sock)) {
        LOGGER_WARNING(tran->log, "tor_transport: failed to set socket nosigpipe");
    }

    /* Connect to the SOCKS5 proxy */
    IP_Port proxy_ip_port;
    ip_init(&proxy_ip_port.ip, false);
    addr_parse_ip(tran->config.proxy_host, &proxy_ip_port.ip);
    proxy_ip_port.port = net_htons(tran->config.proxy_port);

    Net_Err_Connect err;
    net_connect(ns, tran->mem, tran->log, sock, &proxy_ip_port, &err);

    if (err == NET_ERR_CONNECT_INVALID_FAMILY) {
        LOGGER_ERROR(tran->log, "tor_transport: invalid proxy address family");
        kill_sock(ns, sock);
        return false;
    }

    conn->sock = sock;
    conn->status = TOR_NODE_SOCKS5_GREETING;
    conn->send_len = 0;
    conn->send_sent = 0;
    conn->recv_len = 0;
    conn->recv_expected = 0;
    conn->last_active = mono_time_get(tran->mono_time);

    /* Generate SOCKS5 greeting: [ver=5][nmethods=1][method=0 (no auth)] */
    conn->send_buf[0] = SOCKS5_VERSION;
    conn->send_buf[1] = SOCKS5_AUTH_METHODS;
    conn->send_buf[2] = SOCKS5_AUTH_NO_AUTH;
    conn->send_len = 3;
    conn->send_sent = 0;

    return true;
}

/**
 * Send pending data from the send buffer.
 * @retval 0 if all data sent.
 * @retval -1 if data remains or error.
 */
static int send_pending_data_tor(Tor_Transport *tran, Tor_Node_Connection *conn)
{
    if (conn->send_len == 0) {
        return 0;
    }

    const uint16_t left = conn->send_len - conn->send_sent;
    const int len = net_send(tran->ns, tran->log, conn->sock,
                             conn->send_buf + conn->send_sent, left,
                             nullptr, nullptr);

    if (len <= 0) {
        return -1;
    }

    conn->send_sent += (uint16_t)len;

    if (conn->send_sent >= conn->send_len) {
        conn->send_len = 0;
        conn->send_sent = 0;
        return 0;
    }

    return -1;
}

/**
 * Read raw bytes into the recv buffer. Tries to fill up to `total` bytes.
 * @retval 0 if still waiting for more data.
 * @retval 1 if all `total` bytes received.
 * @retval -1 on error.
 */
static int read_fixed_bytes(Tor_Transport *tran, Tor_Node_Connection *conn,
                            uint16_t total)
{
    const uint16_t count = net_socket_data_recv_buffer(tran->ns, conn->sock);
    const uint16_t needed = total - conn->recv_len;

    if (count < needed) {
        return 0;
    }

    const int len = net_recv(tran->ns, tran->log, conn->sock,
                             conn->recv_buf + conn->recv_len, needed,
                             nullptr);

    if (len != (int)needed) {
        return -1;
    }

    conn->recv_len += (uint16_t)len;
    return 1;
}

/**
 * Advance the SOCKS5 handshake state machine for a connection.
 * @retval 0 if handshake is still in progress.
 * @retval 1 if handshake completed successfully.
 * @retval -1 on failure (connection must be closed).
 */
static int do_socks5_handshake(Tor_Transport *tran, Tor_Node_Connection *conn)
{
    switch (conn->status) {
        case TOR_NODE_SOCKS5_GREETING: {
            if (send_pending_data_tor(tran, conn) != 0) {
                return 0;
            }
            conn->status = TOR_NODE_SOCKS5_GREETING_REPLY;
            conn->recv_len = 0;
            conn->recv_expected = 2;
            /* fall through */
        }

        case TOR_NODE_SOCKS5_GREETING_REPLY: {
            const int ret = read_fixed_bytes(tran, conn, 2);
            if (ret != 1) {
                return ret;
            }
            /* Expected: [ver=5][auth_method] */
            if (conn->recv_buf[0] != SOCKS5_VERSION || conn->recv_buf[1] != SOCKS5_AUTH_NO_AUTH) {
                LOGGER_ERROR(tran->log, "tor_transport: SOCKS5 greeting rejected (ver=%d, auth=%d)",
                             conn->recv_buf[0], conn->recv_buf[1]);
                return -1;
            }
            conn->status = TOR_NODE_SOCKS5_CONNECT;
            conn->send_len = 0;
            conn->send_sent = 0;
            conn->recv_len = 0;
            /* fall through - build connect request */
        }

        case TOR_NODE_SOCKS5_CONNECT: {
            /* Build SOCKS5 connect request with domain name (.onion) */
            /* First, build the .onion FQDN from the 35-byte address */
            char onion_fqdn[64];
            if (onion_addr_to_string(conn->onion_addr, onion_fqdn, sizeof(onion_fqdn)) == nullptr) {
                return -1;
            }
            const size_t domain_len = strlen(onion_fqdn);

            uint8_t *buf = conn->send_buf;
            uint16_t pos = 0;
            buf[pos++] = SOCKS5_VERSION;
            buf[pos++] = SOCKS5_COMMAND_CONNECT;
            buf[pos++] = SOCKS5_RESERVED;
            buf[pos++] = SOCKS5_ATYP_DOMAINNAME;
            buf[pos++] = (uint8_t)domain_len;
            memcpy(buf + pos, onion_fqdn, domain_len);
            pos += (uint16_t)domain_len;
            /* Port in network byte order */
            buf[pos++] = (uint8_t)((conn->port >> 8) & 0xff);
            buf[pos++] = (uint8_t)(conn->port & 0xff);

            conn->send_len = pos;
            conn->send_sent = 0;

            if (send_pending_data_tor(tran, conn) != 0) {
                return 0;
            }
            conn->status = TOR_NODE_SOCKS5_CONNECT_REPLY;
            conn->recv_len = 0;
            /* IPv4 reply is 10 bytes, IPv6 is 22 bytes, domain varies. We read
             * just the fixed header (4 bytes) to determine the address type,
             * then read the rest. */
            conn->recv_expected = 4;
            /* fall through */
        }

        case TOR_NODE_SOCKS5_CONNECT_REPLY: {
            /* Read the first 4 bytes: [ver][reply][rsv][atyp] */
            int ret;
            if (conn->recv_len < 4) {
                ret = read_fixed_bytes(tran, conn, 4);
                if (ret != 1) {
                    return ret;
                }
            }

            const uint8_t *hdr = conn->recv_buf;
            if (hdr[0] != SOCKS5_VERSION) {
                LOGGER_ERROR(tran->log, "tor_transport: SOCKS5 connect bad version %d", hdr[0]);
                return -1;
            }
            if (hdr[1] != SOCKS5_REPLY_SUCCEEDED) {
                LOGGER_ERROR(tran->log, "tor_transport: SOCKS5 connect failed (reply=%d)", hdr[1]);
                return -1;
            }

            /* Determine total response size based on address type */
            uint16_t total_size;
            switch (hdr[3]) {
                case SOCKS5_ATYP_IPV4: {
                    total_size = 4 + 4 + 2;  /* hdr + IPv4 + port */
                    break;
                }
                case SOCKS5_ATYP_IPV6: {
                    total_size = 4 + 16 + 2; /* hdr + IPv6 + port */
                    break;
                }
                case SOCKS5_ATYP_DOMAINNAME: {
                    /* Need to read domain length first */
                    if (conn->recv_len < 5) {
                        ret = read_fixed_bytes(tran, conn, 5);
                        if (ret != 1) {
                            return ret;
                        }
                    }
                    const uint8_t domain_len = conn->recv_buf[4];
                    total_size = 5 + domain_len + 2;
                    break;
                }
                default: {
                    LOGGER_ERROR(tran->log, "tor_transport: SOCKS5 connect unknown atyp %d", hdr[3]);
                    return -1;
                }
            }

            ret = read_fixed_bytes(tran, conn, total_size);
            if (ret != 1) {
                return ret;
            }

            conn->status = TOR_NODE_CONNECTED;
            conn->last_active = mono_time_get(tran->mono_time);
            conn->recv_len = 0;
            conn->recv_expected = 0;
            LOGGER_DEBUG(tran->log, "tor_transport: SOCKS5 connection established");
            return 1;
        }

        default: {
            return -1;
        }
    }
}

/**
 * Frame and queue a DHT packet for sending on an established connection.
 * The frame is: [2-byte big-endian payload length][payload].
 *
 * @retval 1 on success.
 * @retval 0 if the send buffer is full (try again later).
 * @retval -1 if the connection is broken.
 */
static int send_packet_on_conn(Tor_Transport *tran, Tor_Node_Connection *conn,
                               const uint8_t *data, uint16_t length)
{
    if (conn->send_len != 0) {
        /* Send buffer is busy (previous packet not fully sent yet) */
        return 0;
    }

    if (length > TOR_TRANSPORT_MAX_PACKET_SIZE) {
        LOGGER_ERROR(tran->log, "tor_transport: packet too large (%d > %d)",
                     length, TOR_TRANSPORT_MAX_PACKET_SIZE);
        return -1;
    }

    uint8_t *buf = conn->send_buf;
    uint16_t pos = 0;
    buf[pos++] = (uint8_t)((length >> 8) & 0xff);
    buf[pos++] = (uint8_t)(length & 0xff);
    memcpy(buf + pos, data, length);
    pos += length;

    conn->send_len = pos;
    conn->send_sent = 0;
    conn->last_active = mono_time_get(tran->mono_time);

    return 1;
}

/**
 * Dispatch an incoming framed packet to the appropriate handler based on its
 * first byte.
 */
static void dispatch_packet(Tor_Transport *tran,
                            const Tor_Node_Connection *conn,
                            const uint8_t *data, uint16_t length,
                            void *userdata)
{
    const uint8_t type = data[0];
    if (tran->handlers[type] != nullptr) {
        IP_Port source;
        ip_set_onion(&source.ip, conn->onion_addr);
        source.port = conn->port;
        tran->handlers[type](tran->handler_objects[type], &source,
                             data, length, userdata);
    } else {
        LOGGER_TRACE(tran->log, "tor_transport: no handler for packet type 0x%02x", type);
    }
}

/**
 * Read framed data from an established connection.
 *
 * Framing: first 2 bytes are big-endian payload length (payload only, excludes
 * the 2-byte prefix), followed by that many bytes of payload.
 *
 * When a complete frame is received, it is dispatched to the registered
 * packet handler.
 */
static void do_read_connected(Tor_Transport *tran, Tor_Node_Connection *conn,
                              void *userdata)
{
    /* Read the 2-byte length prefix if we don't yet know the frame size */
    while (true) {
        if (conn->recv_expected == 0) {
            const uint16_t count = net_socket_data_recv_buffer(tran->ns, conn->sock);
            if (count < sizeof(uint16_t)) {
                return; /* Not enough data yet */
            }

            uint8_t len_buf[sizeof(uint16_t)];
            const int len = net_recv(tran->ns, tran->log, conn->sock,
                                     len_buf, sizeof(len_buf), nullptr);
            if (len != (int)sizeof(len_buf)) {
                LOGGER_ERROR(tran->log, "tor_transport: failed to read length prefix");
                /* Connection is broken */
                return;
            }

            conn->recv_expected = (uint16_t)((uint16_t)len_buf[0] << 8) | len_buf[1];
            if (conn->recv_expected > TOR_TRANSPORT_MAX_PACKET_SIZE) {
                LOGGER_ERROR(tran->log, "tor_transport: frame too large %d", conn->recv_expected);
                return;
            }

            conn->recv_len = 0;
        }

        /* Read the payload */
        const uint16_t count = net_socket_data_recv_buffer(tran->ns, conn->sock);
        const uint16_t needed = conn->recv_expected - conn->recv_len;

        if (count < needed) {
            return; /* Still waiting */
        }

        const int r = net_recv(tran->ns, tran->log, conn->sock,
                               conn->recv_buf + conn->recv_len, needed, nullptr);
        if (r != (int)needed) {
            LOGGER_ERROR(tran->log, "tor_transport: short recv in frame");
            return;
        }

        conn->recv_len += (uint16_t)r;

        if (conn->recv_len == conn->recv_expected) {
            conn->last_active = mono_time_get(tran->mono_time);
            dispatch_packet(tran, conn, conn->recv_buf, conn->recv_len, userdata);
            conn->recv_expected = 0;
            conn->recv_len = 0;
            /* Loop to read next frame */
        }
    }
}

Tor_Transport *tor_transport_new(
    const Logger *log, const Memory *mem,
    const Mono_Time *mono_time, const Random *rng,
    const Network *ns, const Tor_Transport_Config *cfg)
{
    Tor_Transport *tran = (Tor_Transport *)mem_alloc(mem, sizeof(Tor_Transport));
    if (tran == nullptr) {
        return nullptr;
    }

    memset(tran, 0, sizeof(Tor_Transport));
    tran->log = log;
    tran->mem = mem;
    tran->mono_time = mono_time;
    tran->rng = rng;
    tran->ns = ns;
    tran->config = *cfg;

    /* Mark all connection slots as DISCONNECTED */
    for (uint32_t i = 0; i < MAX_TOR_CONNECTIONS; ++i) {
        tran->connections[i].status = TOR_NODE_DISCONNECTED;
    }

    return tran;
}

void tor_transport_kill(Tor_Transport *tran)
{
    if (tran == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < MAX_TOR_CONNECTIONS; ++i) {
        if (tran->connections[i].status != TOR_NODE_DISCONNECTED) {
            close_connection(tran, i);
        }
    }

    mem_delete(tran->mem, tran);
}

int tor_transport_send(Tor_Transport *tran,
                       const uint8_t *onion_addr, uint16_t port,
                       const uint8_t *public_key,
                       const uint8_t *data, uint16_t length)
{
    int idx = find_connection(tran, onion_addr, port);

    if (idx == -1) {
        /* Create a new connection */
        idx = find_free_slot(tran);
        if (idx == -1) {
            LOGGER_WARNING(tran->log, "tor_transport: connection pool full");
            return -1;
        }

        Tor_Node_Connection *conn = &tran->connections[idx];
        memset(conn, 0, sizeof(Tor_Node_Connection));
        memcpy(conn->onion_addr, onion_addr, ONION_V3_ADDRESS_SIZE);
        conn->port = port;
        memcpy(conn->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
        conn->status = TOR_NODE_CONNECTING;

        if (!open_proxy_connection(tran, conn)) {
            close_connection(tran, (uint32_t)idx);
            return -1;
        }

        if (tran->num_connections < MAX_TOR_CONNECTIONS) {
            ++tran->num_connections;
        }
    }

    Tor_Node_Connection *conn = &tran->connections[idx];

    /* If connection not yet established, queue one pending packet in recv_buf
     * (unused during handshake). It will be sent once the SOCKS5 handshake
     * completes (see tor_transport_iterate). */
    if (conn->status != TOR_NODE_CONNECTED) {
        if (conn->recv_len > 0) {
            return 0; /* already have a pending packet queued */
        }
        if (length + 2 > TOR_TRANSPORT_MAX_PACKET_SIZE) {
            return -1;
        }
        conn->recv_buf[0] = (uint8_t)((length >> 8) & 0xff);
        conn->recv_buf[1] = (uint8_t)(length & 0xff);
        memcpy(conn->recv_buf + 2, data, length);
        conn->recv_len = length + 2;
        return 1;
    }

    return send_packet_on_conn(tran, conn, data, length);
}

void tor_transport_register_handler(Tor_Transport *tran, uint8_t type,
                                     tor_packet_handler_cb *cb,
                                     void *object)
{
    tran->handlers[type] = cb;
    tran->handler_objects[type] = object;
}

void tor_transport_iterate(Tor_Transport *tran, void *userdata)
{
    const uint64_t now = mono_time_get(tran->mono_time);

    for (uint32_t i = 0; i < MAX_TOR_CONNECTIONS; ++i) {
        Tor_Node_Connection *conn = &tran->connections[i];

        if (conn->status == TOR_NODE_DISCONNECTED) {
            continue;
        }

        /* Idle timeout */
        if (now - conn->last_active > TOR_CONNECTION_IDLE_TIMEOUT
                && conn->status == TOR_NODE_CONNECTED) {
            LOGGER_DEBUG(tran->log, "tor_transport: idle timeout for connection %u", i);
            close_connection(tran, i);
            continue;
        }

        /* Reuse timeout — close if not used for TOR_CONNECTION_REUSE_TIMEOUT */
        if (now - conn->last_active > TOR_CONNECTION_REUSE_TIMEOUT
                && conn->status >= TOR_NODE_CONNECTED) {
            /* Only close if there's no pending data */
            if (conn->send_len == 0 && conn->recv_expected == 0) {
                LOGGER_DEBUG(tran->log, "tor_transport: reuse timeout for connection %u", i);
                close_connection(tran, i);
                continue;
            }
        }

        /* SOCKS5 handshake state machine */
        if (conn->status < TOR_NODE_CONNECTED) {
            const int hs_ret = do_socks5_handshake(tran, conn);
            if (hs_ret == -1) {
                LOGGER_WARNING(tran->log, "tor_transport: SOCKS5 handshake failed for connection %u", i);
                close_connection(tran, i);
                continue;
            }

            if (hs_ret == 1) {
                /* Handshake completed. Send any pending packet that was queued
                 * during connection setup. We stored it in recv_buf with
                 * recv_len = packet_size + 2 (see tor_transport_send). */
                if (conn->recv_len > 0) {
                    const uint16_t pending_len = conn->recv_len;
                    conn->recv_len = 0;
                    /* pending data is stored as [len_hi][len_lo][data...] */
                    const uint16_t payload_len =
                        (uint16_t)((uint16_t)conn->recv_buf[0] << 8) | conn->recv_buf[1];
                    if (payload_len <= TOR_TRANSPORT_MAX_PACKET_SIZE
                            && 2 + payload_len == pending_len) {
                        send_packet_on_conn(tran, conn,
                                            conn->recv_buf + 2, payload_len);
                    }
                }
            }
            continue;
        }

        /* Send any pending data */
        if (conn->send_len > 0) {
            const int ret = send_pending_data_tor(tran, conn);
            if (ret == -1) {
                LOGGER_WARNING(tran->log, "tor_transport: send failed on connection %u", i);
                close_connection(tran, i);
                continue;
            }
        }

        /* Read incoming frames */
        do_read_connected(tran, conn, userdata);
    }
}

uint32_t tor_transport_num_connections(const Tor_Transport *tran)
{
    return tran->num_connections;
}
