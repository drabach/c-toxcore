/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2025 The TokTok team.
 */

/**
 * Tor transport layer for DHT over Tor SOCKS5 proxy.
 *
 * Replaces Networking_Core (UDP socket) as the DHT's I/O backend when
 * operating exclusively over Tor. All DHT communication happens over TCP
 * connections through a SOCKS5 proxy (typically 127.0.0.1:9050).
 */
#ifndef C_TOXCORE_TOXCORE_TOR_TRANSPORT_H
#define C_TOXCORE_TOXCORE_TOR_TRANSPORT_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Maximum number of concurrent Tor TCP connections in the pool. */
#define MAX_TOR_CONNECTIONS 128

/** Maximum size of a framed DHT packet over TCP. */
#define TOR_TRANSPORT_MAX_PACKET_SIZE 2048

/**
 * Timeout in seconds after which an idle connection is closed.
 * A connection is idle if no packet has been sent or received on it.
 */
#define TOR_CONNECTION_IDLE_TIMEOUT 300

/**
 * SOCKS5 proxy configuration for the Tor transport.
 */
typedef struct Tor_Transport_Config {
    char     proxy_host[256];       /**< SOCKS5 proxy host (e.g. "127.0.0.1") */
    uint16_t proxy_port;            /**< SOCKS5 proxy port (e.g. 9050) */
    uint8_t  self_public_key[32];   /**< Our DHT public key (for routing) */
} Tor_Transport_Config;

/**
 * Status of a Tor node TCP connection through the SOCKS5 proxy.
 */
typedef enum Tor_Node_Status {
    TOR_NODE_CONNECTING,              /**< TCP connecting to SOCKS5 proxy */
    TOR_NODE_SOCKS5_GREETING,         /**< Sending SOCKS5 greeting */
    TOR_NODE_SOCKS5_GREETING_REPLY,   /**< Waiting for SOCKS5 greeting reply */
    TOR_NODE_SOCKS5_CONNECT,          /**< Sending SOCKS5 connect request */
    TOR_NODE_SOCKS5_CONNECT_REPLY,    /**< Waiting for SOCKS5 connect reply */
    TOR_NODE_CONNECTED,               /**< Connection established, ready for data */
    TOR_NODE_DISCONNECTED,            /**< Connection closed or failed */
} Tor_Node_Status;

/**
 * A single TCP connection to a DHT node reachable at an onion address.
 */
typedef struct Tor_Node_Connection {
    uint8_t  onion_addr[ONION_V3_ADDRESS_SIZE]; /**< Remote node's onion address */
    uint16_t port;                              /**< Remote node's port */
    uint8_t  public_key[CRYPTO_PUBLIC_KEY_SIZE]; /**< Remote node's DHT public key */
    Socket   sock;                              /**< TCP socket through Tor */
    Tor_Node_Status status;                     /**< Connection state */
    uint64_t last_active;                       /**< Mono time of last send/recv */

    /* Send buffer */
    uint8_t  send_buf[TOR_TRANSPORT_MAX_PACKET_SIZE + 2]; /**< +2 for length prefix */
    uint16_t send_len;
    uint16_t send_sent;

    /* Receive buffer */
    uint8_t  recv_buf[TOR_TRANSPORT_MAX_PACKET_SIZE + 2];
    uint16_t recv_len;
    uint16_t recv_expected; /**< Expected total bytes for current frame (0 = reading length prefix) */
} Tor_Node_Connection;

/**
 * Callback for incoming DHT packets received over a Tor connection.
 *
 * @param object User object registered with the handler.
 * @param source The IP_Port of the sending node (ip contains the onion address).
 * @param packet The received packet data (same format as UDP DHT packet).
 * @param length Length of the packet data.
 * @param userdata User data passed through from the iteration call.
 */
typedef void tor_packet_handler_cb(void *_Nonnull object,
                                    const IP_Port *_Nonnull source,
                                    const uint8_t *_Nonnull packet, uint16_t length,
                                    void *_Nullable userdata);

/**
 * Tor transport state.
 */
typedef struct Tor_Transport Tor_Transport;

/**
 * Create a new Tor transport instance.
 *
 * Opens no sockets initially. Connections are created on demand by
 * tor_transport_send().
 *
 * @param log Logger instance.
 * @param mem Memory allocator.
 * @param mono_time Monotonic time source.
 * @param rng Random number generator.
 * @param ns Network abstraction.
 * @param cfg SOCKS5 proxy configuration.
 *
 * @return A new Tor_Transport, or NULL on allocation failure.
 */
Tor_Transport *_Nullable tor_transport_new(
    const Logger *_Nonnull log, const Memory *_Nonnull mem,
    const Mono_Time *_Nonnull mono_time, const Random *_Nonnull rng,
    const Network *_Nonnull ns, const Tor_Transport_Config *_Nonnull cfg);

/** Destroy a Tor transport instance and close all connections. */
void tor_transport_kill(Tor_Transport *_Nullable tran);

/**
 * Send a DHT packet to a node identified by its onion address and public key.
 *
 * Creates a new TCP connection through Tor if one doesn't already exist for
 * this (onion_addr, port) pair. Reuses an existing connection from the pool.
 *
 * The packet is framed with a 2-byte big-endian length prefix (payload length,
 * excluding the prefix itself) before being sent over TCP.
 *
 * @param tran The Tor transport instance.
 * @param onion_addr 35-byte onion address of the target node.
 * @param port Port of the target node.
 * @param public_key DHT public key of the target node (for routing incoming replies).
 * @param data Packet data to send.
 * @param length Length of the packet data.
 *
 * @retval 1 on success (packet queued for sending).
 * @retval 0 if the packet could not be queued (connection busy).
 * @retval -1 on failure (connection broken, must reconnect).
 */
int tor_transport_send(Tor_Transport *_Nonnull tran,
                       const uint8_t *_Nonnull onion_addr, uint16_t port,
                       const uint8_t *_Nonnull public_key,
                       const uint8_t *_Nonnull data, uint16_t length);

/**
 * Register a handler for incoming DHT packets with a given first byte (type).
 *
 * The handler is called from tor_transport_iterate() when a complete frame is
 * received on any connection.
 *
 * @param tran The Tor transport instance.
 * @param type The packet type byte (e.g. NET_PACKET_PING_REQUEST).
 * @param cb The callback function.
 * @param object User object passed to the callback.
 */
void tor_transport_register_handler(Tor_Transport *_Nonnull tran, uint8_t type,
                                     tor_packet_handler_cb *_Nullable cb,
                                     void *_Nullable object);

/**
 * Main loop — poll all TCP connections, read data, dispatch to handlers.
 *
 * Must be called periodically (at least once per tox_iterate cycle).
 *
 * @param tran The Tor transport instance.
 * @param userdata User data passed to packet handlers.
 */
void tor_transport_iterate(Tor_Transport *_Nonnull tran, void *_Nullable userdata);

/**
 * Return the number of currently open connections in the pool.
 */
uint32_t tor_transport_num_connections(const Tor_Transport *_Nonnull tran);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOR_TRANSPORT_H */
