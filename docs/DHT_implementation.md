# c-toxcore DHT Implementation

## Overview

The DHT (Distributed Hash Table) in c-toxcore is a Kademlia-like overlay network that enables peer discovery in the Tox messaging protocol. It provides a way for nodes to find each other's IP addresses using only their long-term public keys, without requiring a central server.

The implementation follows the principles of the BitTorrent DHT (BEP 0005) but with a simplified, encrypted packet format and NAT traversal capabilities.

---

## Architecture

### Key Data Structures

#### `DHT` (top-level state)
The central object holding all DHT state:

| Field | Type | Description |
|-------|------|-------------|
| `self_public_key` | `uint8_t[32]` | Our Curve25519 DHT public key |
| `self_secret_key` | `uint8_t[32]` | Our Curve25519 DHT secret key |
| `close_clientlist` | `Client_data[1024]` | 128 buckets x 8 nodes closest to our key |
| `friends_list` | `DHT_Friend[]` | Dynamic array of friends we want to find |
| `num_friends` | `uint16_t` | Number of DHT friends |
| `hole_punching_enabled` | `bool` | NAT hole punching toggle |
| `dht_ping_array` | `Ping_Array*` | Stores ping IDs for nodes requests |
| `shared_keys_recv/sent` | `Shared_Key_Cache*` | ECDH shared key caches |

#### `DHT_Friend`
Represents a friend in the DHT:

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | `uint8_t[32]` | Friend's DHT public key |
| `client_list` | `Client_data[8]` | 8 nodes closest to this friend |
| `last_nodes_request` | `uint64_t` | Last nodes request timestamp |
| `bootstrap_times` | `uint32_t` | Bootstrap attempt count |
| `nat` | `NAT` | Hole punching state |
| `to_bootstrap` | `Node_format[4]` | Pending nodes to bootstrap for this friend |

#### `Client_data`
A known DHT node:

| Field | Type | Description |
|-------|------|-------------|
| `public_key` | `uint8_t[32]` | Node's DHT public key |
| `assoc4` | `IPPTsPng` | IPv4 association (IP, port, timestamps) |
| `assoc6` | `IPPTsPng` | IPv6 association |
| `announce_node` | `bool` | Supports announce protocol (if `CHECK_ANNOUNCE_NODE`) |

#### `IPPTsPng`
Tracks a single association with a node:

| Field | Type | Description |
|-------|------|-------------|
| `ip_port` | `IP_Port` | The node's address |
| `timestamp` | `uint64_t` | Last successful ping |
| `last_pinged` | `uint64_t` | Last time we pinged them |
| `ret_ip_port` | `IP_Port` | IP the node says we have |
| `ret_timestamp` | `uint64_t` | When `ret_ip_port` was updated |
| `ret_ip_self` | `bool` | Whether `ret_ip_port` is our own IP |

#### `Node_format`
Compact format for transferring node info in packets:

```
uint8_t public_key[32]   -- DHT public key
IP_Port ip_port          -- IP address and port
```

#### `NAT`
Hole punching state per friend:

| Field | Type | Description |
|-------|------|-------------|
| `hole_punching` | `bool` | Actively hole punching? |
| `punching_index` | `uint32_t` | Port iteration index |
| `tries` | `uint32_t` | Attempt counter |
| `punching_index2` | `uint32_t` | Second port iteration index |
| `punching_timestamp` | `uint64_t` | Last punch time |
| `recv_nat_ping_timestamp` | `uint64_t` | Last NAT ping received |
| `nat_ping_id` | `uint64_t` | Current NAT ping ID |
| `nat_ping_timestamp` | `uint64_t` | Last NAT ping sent |

---

## Network Protocol

### Packet Types

| Type | Value | Purpose |
|------|-------|---------|
| `NET_PACKET_PING_REQUEST` | `0x00` | Ping request |
| `NET_PACKET_PING_RESPONSE` | `0x01` | Ping response |
| `NET_PACKET_NODES_REQUEST` | `0x02` | Request close nodes |
| `NET_PACKET_NODES_RESPONSE` | `0x04` | Send close nodes |
| `NET_PACKET_CRYPTO` | `0x20` | Generic encrypted packet |

### Crypto Packet IDs (inside `NET_PACKET_CRYPTO`)

| ID | Value | Purpose |
|----|-------|---------|
| `CRYPTO_PACKET_FRIEND_REQ` | `32` | Friend request |
| `CRYPTO_PACKET_DHTPK` | `156` | DHT public key exchange |
| `CRYPTO_PACKET_NAT_PING` | `254` | NAT hole punching ping |

### Node Format (wire)

```
[uint8_t family]
  - 2   = IPv4
  - 10  = IPv6
  - 130 = TCP over IPv4
  - 138 = TCP over IPv6
[ip bytes: 4 (IPv4) or 16 (IPv6)]
[uint16_t port (network byte order)]
[uint8_t[32] public_key]
```

### Ping Packet

```
Request:  0x00 | sender_pubkey[32] | nonce[24] | encrypt(nonce, key, type=0 | ping_id[8])
Response: 0x01 | sender_pubkey[32] | nonce[24] | encrypt(nonce, key, type=1 | ping_id[8])
```

Total size: `1 + 32 + 24 + (1 + 8 + 16) = 82 bytes`

Ping IDs are stored in a `Ping_Array` with a 5-second timeout (`PING_TIMEOUT`).

### Nodes Request Packet

```
0x02 | sender_pubkey[32] | nonce[24] | encrypt(nonce, key, target_node_id[32] | sendback_data[8])
```

### Nodes Response Packet

```
0x04 | sender_pubkey[32] | nonce[24] | encrypt(nonce, key, num_nodes | nodes[] | sendback_data[8])
```

The response contains up to 4 nodes (`MAX_SENT_NODES`) closest to the requested target.

---

## Core Algorithms

### Kademlia-like Routing

The DHT organizes nodes by XOR distance between their 256-bit public keys. The distance metric is:

```
distance(a, b) = a XOR b  (treated as a 256-bit integer)
```

#### Close List
The `close_clientlist` has 1024 slots organized as 128 buckets x 8 nodes.

Bucket `i` (0-127) contains nodes where the first differing bit from our key falls in bit range `[i*8, i*8+7]`.

A node is added to the close list if:
- Its XOR distance to our key lands it in a non-full bucket, or
- It is closer than the worst node in the appropriate bucket

Important: The *first* differing bit determines the bucket. The *total* XOR distance determines ordering within a bucket.

#### XOR Comparison
`bit_by_bit_cmp(pk1, pk2)` returns the index of the first differing bit (starting from the MSB, 0-indexed).

`id_closest(pk, pk1, pk2)` returns:
- `0` if both are equally close
- `1` if `pk1` is closer to `pk`
- `2` if `pk2` is closer to `pk`

### Bootstrap Process

1. **Initial bootstrap**: `dht_bootstrap()` sends a `NET_PACKET_NODES_REQUEST` to a known bootstrap node (IP, port, public key from a hardcoded list).

2. **Post-load bootstrap**: `dht_connect_after_load()` bootstraps from up to 8 previously saved nodes in round-robin fashion. It stops once `dht_non_lan_connected()` returns true.

3. **Aggressive bootstrap**: For each friend, up to `MAX_BOOTSTRAP_TIMES` (5) extra nodes requests are sent aggressively before settling into the routine interval.

### Peer Discovery (Iterative Lookup)

For each friend in `friends_list[]`, the DHT periodically sends nodes requests:

- **Every 20 seconds** (`NODES_REQUEST_INTERVAL`): Send a nodes request to a random good node from the friend's client list.
- **Every 60 seconds** (`PING_INTERVAL`): Send nodes requests (combined with pings) to every node in both the close list and friend client lists.

When a nodes response arrives:
1. The ping ID is verified.
2. The responder is added to the close list and relevant friend lists via `addto_lists()`.
3. Each returned node is queued for pinging via the `to_ping` buffer (anti-amplification mechanism).
4. Return IP information is updated for NAT traversal.

### `get_close_nodes()`

Searches both `close_clientlist` and every friend's `client_list` to find up to 4 nodes closest to a target public key. Used when responding to nodes requests.

Features:
- IPv4/IPv6 filtering
- LAN IP filtering when the requester is not on LAN
- Optional announce-node-only filtering (`CHECK_ANNOUNCE_NODE`)

---

## Ping System

### Anti-Amplification Design

The ping system in `ping.c` prevents amplification attacks through a **to_ping buffer**:

1. When a node sends us a valid packet and we don't know it yet, `ping_add()` adds it to a `to_ping` buffer (max 32 entries).
2. Every 2 seconds (`TIME_TO_PING`), `ping_iterate()` sends actual ping requests to all buffered nodes.
3. This ensures we never initiate contact with a node that didn't contact us first.

### Ping Flow

1. We generate a random 64-bit ping ID and store `{public_key, IP_Port}` in `ping_array` with a 5-second timeout.
2. Encrypt the ping ID with an ECDH-derived shared key and send it as `NET_PACKET_PING_REQUEST`.
3. Receiver decrypts, sends back `NET_PACKET_PING_RESPONSE` with the same ping ID.
4. We receive the response, verify the ping ID matches, confirm the source IP/port matches what we stored, then call `addto_lists()` to update our routing tables.

### Combined Pings + Nodes Requests

In `do_ping_and_sendnode_requests()`, nodes requests double as pings:
- Every 60 seconds, every node in the lists gets a nodes request.
- This serves as both a liveness check and a lookup for closer nodes.

---

## Timing Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `PING_TIMEOUT` | 5s | Ping ID validity |
| `PING_INTERVAL` | 60s | Routine ping interval |
| `PINGS_MISSED_NODE_GOES_BAD` | 1 | Missed pings before "bad" |
| `PING_ROUNDTRIP` | 2 | Estimated round-trips |
| `BAD_NODE_TIMEOUT` | 122s | = 60 + 1*(60+2) |
| `KILL_NODE_TIMEOUT` | 182s | = 122 + 60, full discard |
| `NODES_REQUEST_INTERVAL` | 20s | Random nodes request |
| `DHT_PING_ARRAY_SIZE` | 512 | Ping array capacity |
| `MAX_BOOTSTRAP_TIMES` | 5 | Aggressive bootstrap limit |
| `PUNCH_INTERVAL` | 3s | Hole punching interval |
| `PUNCH_RESET_TIME` | 40s | Punching reset timeout |
| `MAX_PUNCHING_PORTS` | 48 | Ports per punching cycle |
| `MAX_NORMAL_PUNCHING_TRIES` | 5 | Normal tries before brute-force |
| `TIME_TO_PING` | 2s | to_ping buffer flush interval |
| `KEYS_TIMEOUT` | 600s | Shared key cache timeout |

---

## NAT Hole Punching

### Prerequisites

- `hole_punching_enabled` must be `true` (set at DHT creation).
- At least `MAX_FRIEND_CLIENTS / 2` (4) nodes must report the same friend IP.
- The friend must be "online" (nodes are returning their IPs).

### Protocol

Uses `CRYPTO_PACKET_NAT_PING` (ID 254):

- **Request** (type 0): Broadcast via `route_to_friend()` to all nodes that claim to know the friend.
- **Response** (type 1): Sent via `routeone_to_friend()` to a single node.

### Punching Algorithm (`punch_holes()`)

**Phase 1** (first 5 tries):
- If all reported ports are the same, ping that port directly.
- If ports differ, iterate through `MAX_PUNCHING_PORTS` (48) attempts, alternating around known ports:
  `delta = sign * (it / (2 * numports))`, `port = port_list[index] + delta`

**Phase 2** (after 5+ tries):
- Brute-force scan ports starting from 1024.
- Sends 48 pings per cycle, incrementing `punching_index2`.

If no success after `PUNCH_RESET_TIME` (40s), all counters are reset.

### `do_nat()` Loop

Runs every `do_dht()` cycle:
- Every 3 seconds (`PUNCH_INTERVAL`), sends a NAT ping request for each friend with enough returned IPs.
- If hole punching is active and we received a ping within 6 seconds:
  - Find the most common IP among returned nodes via `nat_commonip()`.
  - Call `punch_holes()` to send direct ping requests.

---

## Close List and Friend List Relationship

### Close List (`close_clientlist[1024]`)
- Nodes closest to **our own** DHT public key.
- 128 buckets, 8 nodes per bucket.
- Bucket determined by first differing bit with our key.
- Used for routing, responding to nodes requests, connectivity detection.

### Friend List (`friends_list[]`)
- One entry per friend.
- Each friend has a `client_list[8]` of nodes closest to **the friend's** public key.
- These nodes report the friend's current IP via `ret_ip_port`.
- A friend is "found" when the friend's own public key appears in its own `client_list` with a valid, non-timed-out association.

### `addto_lists()`
Called whenever we receive a valid packet from a node. It adds/updates the node in:
1. The `close_clientlist` (via `add_to_close()`).
2. Every friend's `client_list` where the node is within range (via `replace_all()`).

Returns the count of lists the node was added to.

### Node Replacement (`replace_all()`)
Within each friend's `client_list[8]`, nodes are sorted by:
1. Non-timed-out nodes first (sorted by XOR distance).
2. Timed-out nodes last (sorted by XOR distance).

A new node replaces an existing one if:
- There is a "bad" (timed-out) slot, or
- The new node is XOR-closer to the friend than the furthest good node.

### Fake Friends
On DHT creation, `DHT_FAKE_FRIEND_NUMBER` (2) random keypairs are added as fake friends. These are used to:
- Populate onion path routing nodes.
- Prevent real friend information from leaking into onion path selection.

---

## Connectivity Detection

- `dht_isconnected()`: `true` if any close list entry has a non-timed-out IPv4 or IPv6 association.
- `dht_non_lan_connected()`: `true` if any close list entry has a non-timed-out, non-LAN association.

---

## Integration with Onion Routing

### Onion Path Construction
The onion system selects 3 DHT nodes for each 3-hop path:
- `randfriends_nodes()` provides nodes from fake friends' client lists (avoids leaking real friend info).
- `closelist_nodes()` provides nodes from the close client list.
- `create_onion_path()` in `onion.c` assembles the path with ephemeral keypairs per hop.

### Announce Protocol
Clients announce themselves to `MAX_ONION_CLIENTS_ANNOUNCE` (12) DHT nodes via 3-hop onion paths:
- The announce server stores: real public key, 3-layer encrypted return path, data encryption key.
- Entries expire after `ONION_ANNOUNCE_TIMEOUT` (300s).

### Data Delivery
To send data to a friend whose IP is unknown:
1. Send an onion data request to an announce server the friend announced to.
2. The server wraps the data in a response along the stored return path.
3. The friend receives it through 3 layers of decryption.

### DHT Public Key Exchange
Friends exchange temporary DHT public keys via onion data packets (`ONION_DATA_DHTPK = 156`). The DHT key changes on reconnection. Sent every 30s via onion and every 20s via direct DHT.

---

## Integration with TCP Relays

TCP relays have DHT public keys and are represented as `Node_format` entries with special address families (`TOX_TCP_INET = 130`, `TOX_TCP_INET6 = 138`).

- TCP relay info is exchanged between friends through onion data packets.
- When UDP is unavailable, onion paths can use TCP relays: `random_nodes_path_onion()` uses TCP connections when `!dht_isconnected()`.
- `NUM_ONION_TCP_CONNECTIONS` (3) TCP connections are reserved for onion use.
- `tcp_send_onion_request()` sends onion packets via TCP relays.

---

## Cryptography

All cryptographic primitives use NaCl/libsodium:

| Primitive | Usage |
|-----------|-------|
| Curve25519 | DHT key exchange |
| Salsa20 | Stream cipher |
| Poly1305 | MAC (authentication) |
| ECDH | Shared key derivation per (pubkey, secretkey) pair |

### Packet Encryption
- DHT packets use ECDH key exchange → shared key → symmetric encryption.
- `Shared_Key_Cache` caches ECDH results per (their_pubkey, our_secretkey) with a 600-second timeout.
- Onion packets use ephemeral keypairs per hop; the sender computes a shared key with each hop's public key.
- Ping IDs are encrypted with ECDH-derived shared keys using `encrypt_data_symmetric()`/`decrypt_data_symmetric()`.

---

## Saving and Loading

The DHT state can be serialized and deserialized:
- `dht_save()` writes the close client list and friend data to a binary buffer.
- `dht_load()` restores the DHT state and queues saved nodes for bootstrap.
- Size is determined by `dht_size()`.

---

## Constants Summary

### List Sizes
| Constant | Value | Purpose |
|----------|-------|---------|
| `MAX_FRIEND_CLIENTS` | 8 | Nodes per friend |
| `LCLIENT_NODES` | 8 | Nodes per close bucket |
| `LCLIENT_LENGTH` | 128 | Close list buckets |
| `LCLIENT_LIST` | 1024 | Total close entries |
| `MAX_SENT_NODES` | 4 | Nodes in a response |
| `MAX_CLOSE_TO_BOOTSTRAP_NODES` | 8 | Bootstrap nodes from save |
| `DHT_FAKE_FRIEND_NUMBER` | 2 | Fake friends for onion |
| `MAX_CRYPTO_REQUEST_SIZE` | 1024 | Max request packet size |
| `DHT_PING_ARRAY_SIZE` | 512 | DHT ping array capacity |
| `DHT_FRIEND_MAX_LOCKS` | 32 | Max callbacks per friend |
| `PING_NUM_MAX` | 512 | Ping array capacity |
| `MAX_TO_PING` | 32 | to_ping buffer size |

### Timeouts
| Constant | Value | Purpose |
|----------|-------|---------|
| `PING_TIMEOUT` | 5s | Ping ID validity |
| `BAD_NODE_TIMEOUT` | 122s | Node considered bad |
| `KILL_NODE_TIMEOUT` | 182s | Node fully discarded |
| `PUNCH_RESET_TIME` | 40s | Punching reset |
| `KEYS_TIMEOUT` | 600s | Shared key cache expiry |
| `ONION_ANNOUNCE_TIMEOUT` | 300s | Onion entry expiry |
| `ONION_PATH_MAX_LIFETIME` | 1200s | Max onion path lifetime |
| `ONION_OFFLINE_TIMEOUT` | 51s | Onion offline timeout |

### Intervals
| Constant | Value | Purpose |
|----------|-------|---------|
| `PING_INTERVAL` | 60s | Routine ping |
| `NODES_REQUEST_INTERVAL` | 20s | Nodes lookup |
| `PUNCH_INTERVAL` | 3s | Hole punching |
| `TIME_TO_PING` | 2s | to_ping flush |
| `MAX_BOOTSTRAP_TIMES` | 5 | Aggressive bootstrap tries |
| `ONION_NODE_PING_INTERVAL` | 15s | Onion node ping |
| `ONION_DHTPK_SEND_INTERVAL` | 30s | DHT PK via onion |
| `DHT_DHTPK_SEND_INTERVAL` | 20s | DHT PK via DHT |
| `LAN_DISCOVERY_INTERVAL` | 10s | LAN discovery broadcast |

### Packet Structure
| Constant | Value | Purpose |
|----------|-------|---------|
| `PACKED_NODE_SIZE_IP4` | 1+4+2+32 = 39 | IPv4 node size |
| `PACKED_NODE_SIZE_IP6` | 1+16+2+32 = 51 | IPv6 node size |
| `DHT_PING_SIZE` | 1+32+24+1+8+16 = 82 | Ping packet size |

---

---

## Concrete Walkthrough: Two Clients Behind Tor Finding Each Other

This section traces a real scenario end-to-end: two bootstrap relays R1 and R2 that are each reachable via both a clearnet IP and a Tor onion address; two clients A and B, each behind Tor, each contacting a different relay; both clients wanting to find each other.

### Setup

- **R1, R2** — bootstrap relays. Each runs a Tox node with a DHT public key and a TCP relay server. Each has a clearnet IP *and* a Tor onion address (`.onion`).
- **A, B** — clients. Each configured with `TOX_PROXY_TYPE_SOCKS5` pointing to `127.0.0.1:9050`.

### Layer 1: no UDP

Because a SOCKS5 proxy is configured, c-toxcore **disables UDP entirely** (`tox_options.h:130-131`). All communication goes over TCP relay connections through Tor.

```
A → SOCKS5 → Tor → R1.onion:33445   (TCP relay connection)
B → SOCKS5 → Tor → R2.onion:33445   (TCP relay connection)
```

### Step 1: Bootstrap

A calls `dht_bootstrap_from_address("R1.onion", 33445, R1_pubkey)`.

This resolves the hostname, opens a TCP connection through Tor's SOCKS5 proxy to `R1.onion:33445`, and performs the TCP relay handshake:

1. **Cookie request/response** (`NET_PACKET_COOKIE_REQUEST` / `NET_PACKET_COOKIE_RESPONSE`) — obtains a temporary cookie for the crypto handshake.
2. **Crypto handshake** (`NET_PACKET_CRYPTO_HS`) — establishes an encrypted session with R1's TCP relay server.
3. **TCP relay registration** — A is now a connected TCP relay client. R1 knows A's Tor IP (the Tor exit node's IP or hidden service IP) and can route packets to A.

Same flow for B → R2.

### Step 2: Populating the DHT routing table

A sends `NET_PACKET_NODES_REQUEST` to R1. Under Tor, this packet is serialized and sent over the TCP relay connection using `tcp_send_onion_request()`.

R1's `handle_nodes_request()` (DHT.c:1363) decrypts the request, extracts the **target public key** (A's own key in this case — asking "who is close to me?"), and calls `send_nodes_response()`.

#### What `send_nodes_response()` does (DHT.c:1313)

```c
// 1. Get up to 4 nodes closest to the requested key
Node_format nodes_list[MAX_SENT_NODES];  // MAX_SENT_NODES = 4
uint32_t num_nodes = get_close_nodes(dht, client_id, nodes_list,
    net_family_unspec(), ip_is_lan(&source->ip), false);

// 2. Pack them into the response
int nodes_length = pack_nodes(..., nodes_list, num_nodes);

// 3. Send: [0x04][sender_pubkey[32]][nonce[24]][encrypted payload]
// Payload: [num_nodes(1 byte)][packed nodes][sendback_data(8 bytes)]
sendpacket(dht->net, source, data, len);
```

#### `get_close_nodes()` scans TWO data structures (DHT.c:729)

**First**: the `close_clientlist[1024]` (R1's 128 buckets × 8 nodes closest to R1's own key).

**Second**: every friend's `client_list[8]` (R1's friends lists).

For each entry, `get_close_nodes_inner()` (DHT.c:635) checks:
```
1. Is the node's association non-timed-out? (assoc_timeout: timestamp + 122s > now)
2. Is the address family right? (IPv4/IPv6/unspec)
3. Is LAN IP allowed? (depends if requester is on LAN)
4. If want_announce: does the node support announce protocol?
```

If all checks pass, the node is added to a list of up to 4 entries using XOR-distance sorting.

#### How "closest" is computed — pure XOR on public keys only

The function `id_closest()` (DHC.c:218):

```c
int id_closest(const uint8_t *pk, const uint8_t *pk1, const uint8_t *pk2) {
    for (size_t i = 0; i < 32; ++i) {
        uint8_t distance1 = pk[i] ^ pk1[i];
        uint8_t distance2 = pk[i] ^ pk2[i];
        if (distance1 < distance2) return 1;  // pk1 is closer
        if (distance1 > distance2) return 2;  // pk2 is closer
    }
    return 0;  // equal
}
```

**Byte-by-byte XOR** from index 0 (most significant) to index 31 (least significant). The first byte where the XOR differs determines which node is closer — this is equivalent to comparing 256-bit XOR distances as big-endian integers, but short-circuits at the first differing byte.

**IP addresses are NOT used in the distance calculation.** Only the public key matters.

#### What is actually returned — `Node_format` (key + IP together)

Each entry in the response is a `Node_format`:

```c
typedef struct Node_format {
    uint8_t  public_key[32];   // The node's DHT public key
    IP_Port  ip_port;          // The IP:port where R1 last successfully pinged this node
} Node_format;
```

The `ip_port` is taken from the node's `IPPTsPng.ip_port` field (line 684: `nodes_list[num_nodes].ip_port = ipptp->ip_port`). This is the **node's own listening address** as last verified by R1 — NOT the friend's return address.

So concretely, the response wire format for up to 4 nodes is:

```
[0x04]                    -- packet type (NET_PACKET_NODES_RESPONSE)
[sender_pubkey 32 bytes]  -- R1's public key
[nonce 24 bytes]
[encrypted:
  [num_nodes 1 byte]      -- 0 to 4
  [node 1:
    [family 1 byte]       -- 2=IPv4, 10=IPv6
    [IP 4 or 16 bytes]
    [port 2 bytes]
    [public_key 32 bytes]
  ]
  [node 2 ... up to 4]
  [sendback_data 8 bytes] -- echoes the ping_id from the request
]
```

**Example**: A asks for nodes close to A's key. R1 has these entries in its close list:

| Node | XOR distance to A's key | IP:port |
|------|------------------------|---------|
| NodeX | `0x00...05` | 203.0.113.1:33445 |
| NodeY | `0x00...42` | 198.51.100.9:22845 |
| NodeZ | `0x01...00` | 192.0.2.77:33445 |

R1 returns: `[NodeX(pubkey, 203.0.113.1:33445), NodeY(pubkey, 198.51.100.9:22845)]`

#### How A processes the response

`handle_nodes_response()` (DHT.c:1484):

```c
// 1. Decrypt, verify ping_id matches what we sent
if (!sent_nodes_request_to_node(dht, packet+1, source, ping_id))
    return false;

// 2. Unpack the nodes
Node_format plain_nodes[MAX_SENT_NODES];
unpack_nodes(plain_nodes, num_nodes, ...);

// 3. Add the responder (R1) to our lists
addto_lists(dht, source, packet+1);

// 4. For each returned node, queue it for pinging
for (i = 0; i < num_nodes; i++) {
    ping_node_from_nodes_response_ok(dht, ...);
}
```

`addto_lists()` inserts R1 into both A's `close_clientlist` and any relevant friend lists, creating a `Client_data` entry with R1's public key and IP:port.

The returned nodes (NodeX, NodeY, etc.) go through `ping_node_from_nodes_response_ok()` which calls `ping_add()` → they are placed into the `to_ping` buffer. Every 2 seconds (`TIME_TO_PING`), `ping_iterate()` sends actual ping requests to each buffered node.

A then sends nodes-requests to those newly discovered nodes, asking *them* for nodes closer to A's key. This iterative process fills A's routing table within seconds.

**Key**: Under Tor, all these packets travel through TCP relay chains, not as raw UDP datagrams. The `sendpacket()` call goes through `TCP_connection.c` which wraps it in the TCP relay protocol.

### Step 3: Adding a friend

A calls the high-level API (`tox_friend_add`), which reaches `dht_addfriend(dht, B_pubkey, ip_callback, ...)`.

This creates a `DHT_Friend` entry in A's `friends_list[]`:

```c
struct DHT_Friend {
    uint8_t     public_key[32];          // B's DHT public key
    Client_data client_list[8];          // 8 nodes XOR-closest to B → initially empty
    uint64_t    last_nodes_request;      // 0 → will send immediately
    uint32_t    bootstrap_times;         // 0
    NAT         nat;                     // hole punching state (unused under Tor)
    ...
};
```

### Step 4: Iterative lookup for B

A's `do_dht_friends()` runs every `do_dht()` tick:

```c
static void do_dht_friends(DHT *dht) {
    for (size_t i = 0; i < dht->num_friends; ++i) {
        // 1. Send any queued bootstrap nodes
        for (size_t j = 0; j < dht_friend->num_to_bootstrap; ++j)
            dht_send_nodes_request(dht, &to_bootstrap[j], friend_pk);

        // 2. Main loop: ping + nodes-request every NODES_REQUEST_INTERVAL
        do_ping_and_sendnode_requests(dht, &last_nodes_request,
            friend_pk, client_list, MAX_FRIEND_CLIENTS, &bootstrap_times, true);
    }
}
```

The main loop inside `do_ping_and_sendnode_requests()` does two things:

**Every 60s** (`PING_INTERVAL`): For every node in B's `client_list[8]` that hasn't hit `KILL_NODE_TIMEOUT` (182s), send a `NET_PACKET_NODES_REQUEST`. This doubles as a keepalive ping and a lookup.

**Every 20s** (`NODES_REQUEST_INTERVAL`): Pick a random *good* node from B's client list and send a nodes-request specifically to discover closer nodes.

The request targets B's public key: *"Who is XOR-close to B?"*

Each response returns up to 4 nodes. `addto_lists()` inserts them into:

1. `close_clientlist` — if they're XOR-close to A.
2. B's `client_list[8]` — if they're XOR-close to B (via `replace_all()`).

The `replace_all()` function keeps `client_list[8]` sorted:

```c
// Sort order: non-timed-out nodes first (by XOR distance),
// then timed-out nodes (by XOR distance).
// New node replaces an existing one if:
//   - there's a "bad" (timed-out) slot, OR
//   - the new node is closer to B's key than the worst good node.
```

### Step 5: `ret_ip_port` — how A learns B's alleged IP

Every node in B's `client_list[8]` stores an `IPPTsPng` structure. The field `ret_ip_port` contains the IP address that the node *claims the friend (B) has*.

When A pings a node N in B's client list, N responds. A's `handle_ping_response()` calls `addto_lists()`, which triggers `update_client_data()`:

```c
// DHT.c ~line 1215
static bool update_client_data(..., const IP_Port *ip_port, ...) {
    // ...
    assoc->ret_ip_port = received_ip_port;  // "N says B is at this IP"
    assoc->ret_timestamp = now;
    assoc->ret_ip_self = is_our_own_ip;
}
```

So after enough pings, A's view of B looks like:

```
B's client_list[8]:
  Node 1: ret_ip_port = 203.0.113.5:33445  (timestamp: 2s ago)
  Node 2: ret_ip_port = 203.0.113.5:33445  (timestamp: 5s ago)
  Node 3: ret_ip_port = 198.51.100.7:22845 (timestamp: 10s ago)
  ...etc
```

`friend_iplist()` collects all non-timed-out `ret_ip_port` values. If at least 4 out of 8 nodes report the same IP, that IP is considered B's current address.

When B's own public key appears in its own `client_list[8]` (because a node reported B's IP and that IP matched B's DHT key), the `ip_callback` registered in `dht_addfriend()` fires:

```c
// DHT.c ~line 1204
if (pk_equal(public_key, dht_friend->public_key)) {
    for (each callback) {
        callback(data, number, &ip_port);  // "Found B at X:Y!"
    }
}
```

### Step 6: Why direct DHT doesn't work under Tor

Under clearnet, `route_to_friend()` would now send UDP packets to those IPs. Under Tor, UDP is blocked. So c-toxcore falls back to the **onion routing layer**.

### Step 7: Onion path construction

A builds **3-hop onion paths** through known DHT nodes. Path construction uses `create_onion_path()`:

```c
// onion.c
int create_onion_path(Onion *onion, Onion_Path *path, ...) {
    // Pick 3 nodes from fake friend lists or close list
    Node_format nodes[ONION_PATH_LENGTH];  // 3 nodes
    randfriends_nodes(dht, nodes, ...);     // from fake friends (privacy!)
    // or closelist_nodes(dht, nodes, ...); // from close list

    // For each hop, generate ephemeral keypair, compute shared key
    for (i = 0; i < ONION_PATH_LENGTH; i++) {
        random_keypair(...);                     // ephemeral key for this hop
        encrypt_precompute(...);                 // ECDH shared key
        path->ip_port[i] = nodes[i].ip_port;
        path->node_public_key[i] = nodes[i].public_key;
    }
}
```

Each path: `A → Hop1 → Hop2 → Hop3 → destination`

A maintains 6 paths (`NUMBER_ONION_PATHS`) simultaneously, refreshing them every 20 minutes (`ONION_PATH_MAX_LIFETIME`).

Under Tor, these onion packets are sent via TCP relay connections using `tcp_send_onion_request()`:

```c
// TCP_connection.c
int tcp_send_onion_request(TCP_Connections *tcp_c, unsigned int tcp_connections_number,
                           const uint8_t *packet, uint16_t length)
{
    // Wraps the onion packet in TCP relay protocol and sends over the
    // established encrypted TCP connection through Tor
}
```

### Step 8: Announce protocol

Once paths are built, A announces itself to DHT nodes that support the announce protocol. A sends `NET_PACKET_ANNOUNCE_REQUEST` through a 3-hop path:

```
A → Hop1 → Hop2 → Hop3 → Announce_Server_S

Hop1 strips its layer, sees the inner packet addressed to Hop2, forwards.
Hop2 strips its layer, sees the inner packet addressed to Hop3, forwards.
Hop3 strips its layer, sees NET_PACKET_ANNOUNCE_REQUEST, processes it.
```

The announce request contains:

```c
struct announce_request {
    uint8_t real_pk[32];           // A's long-term public key
    uint8_t data_pk[32];           // Key for data packet encryption
    uint8_t sendback_data[ONION_RETURN_3];  // 3-hop encrypted return path
};
```

The announce server stores this as an `Onion_Announce_Entry`:

```c
struct Onion_Announce_Entry {
    uint8_t  public_key[32];       // A's real public key
    IP_Port  ret_ip_port;          // A's IP as seen by Hop3 (under Tor: Hop3's view)
    uint8_t  ret[ONION_RETURN_3];  // 3-hop return path (encrypted)
    uint8_t  data_public_key[32];  // Key for data encryption
    uint64_t announce_time;        // Last refresh timestamp
};
```

Entries expire after 300s (`ONION_ANNOUNCE_TIMEOUT`) and are refreshed periodically.

A announces itself to **12** (`MAX_ONION_CLIENTS_ANNOUNCE`) different DHT nodes for redundancy.

B does the same through its own paths.

### Step 9: DHT public key exchange

A and B each have a *temporary* DHT public key (different from their long-term Tox ID). These are exchanged so that `route_to_friend()` can work in the DHT layer.

**Via onion** (every 30s): `send_onion_data()` in `onion_client.c:1289`:

```c
int send_onion_data(Onion_Client *onion_c, int friend_num,
                    const uint8_t *data, uint16_t length)
{
    // 1. Find valid onion nodes where friend announced
    // 2. Pick a random path
    // 3. Encrypt data with friend's long-term key:
    encrypt_data(onion_c->friends_list[friend_num].real_public_key,
                 nc_get_self_secret_key(onion_c->c), nonce, data, length, ...);
    // 4. Send as NET_PACKET_ONION_DATA_REQUEST through path
    // 5. The announce server receives it, wraps it in a response,
    //    and sends it back along the friend's 3-hop return path
}
```

**Via DHT** (every 20s): directly through `route_to_friend()`:

```c
// onion_client.c ~line 1397
len = create_request(dht_self_pk, dht_self_sk,
                     friend_dht_pk, encrypted_data, CRYPTO_PACKET_DHTPK);
route_to_friend(onion_c->dht, friend_dht_pk, &packet);
```

Under Tor, "via DHT" means the packet travels through TCP relay connections. `route_to_friend()` broadcasts to all IPs in B's client list — the TCP relays that B uses will forward the packets to B.

### Step 10: Data delivery

Once A and B know each other's DHT public keys, they can exchange application data (text messages, file transfers, etc.) through two paths:

**Path 1 — Onion routing (works under Tor)**:

```
A creates encrypted message
  → send_onion_data() picks a valid announce server of B
  → Sends NET_PACKET_ONION_DATA_REQUEST through a 3-hop path
  → Server wraps it in NET_PACKET_ONION_DATA_RESPONSE
  → Response travels back through B's 3-hop return path
  → B receives it, decrypts 3 layers of onion routing
  → B decrypts the inner message with the session key
```

**Path 2 — Direct DHT (would work over clearnet UDP)**:

```
A calls route_to_friend(B_dht_pk, packet)
  → friend_iplist() collects ret_ip_port from B's 8 client nodes
  → Sends packet to each alleged IP simultaneously
  → If both A and B are behind NAT, this creates a NAT hole:
    B's reply to A punches a hole in B's NAT, A's packet punches a hole in A's NAT
  → The connection becomes bidirectional
```

Under clearnet, Path 2 is preferred (lower latency). The NAT hole punching (`punch_holes()`) makes this work even when both peers are behind NAT — by sending from multiple ports simultaneously, one combination gets through.

Under Tor, only Path 1 works.

### Step 11: Lossless crypto connection

Regardless of which path delivered the first packet, the `net_crypto` layer performs a handshake:

```
A sends: NET_PACKET_CRYPTO_HS
  [cookie (prevents replay) + A's DH public key + encrypted with B's long-term key]

B responds: NET_PACKET_CRYPTO_HS
  [cookie + B's DH public key + encrypted with A's long-term key]

→ Both derive session keys from the DH exchange
→ A sends NET_PACKET_CRYPTO_DATA (data packets with sequence numbers + ACKs)
→ B acknowledges, connection established
```

This handshake works over either the onion path or the DHT path. Once established, the connection switches to direct UDP under clearnet, or stays on onion/TCP-relay under Tor.

### Complete data flow diagram

```
                       Tor network
                           |
        +------------------+------------------+
        |                                     |
  [A --SOCKS5--> R1.onion]             [B --SOCKS5--> R2.onion]
        |                                     |
   TCP relay connection                  TCP relay connection
        |                                     |
   Step 2: nodes-req → R1              Step 2: nodes-req → R2
           ↓                                      ↓
   close_clientlist[1024] filled       close_clientlist[1024] filled
   via iterative lookup                via iterative lookup
        |                                     |
   Step 3: dht_addfriend(B_pk)         Step 3: dht_addfriend(A_pk)
        |                                     |
   Step 4: periodic nodes-req          Step 4: periodic nodes-req
   for B's client_list[8]              for A's client_list[8]
        |                                     |
   Step 5: ret_ip_port collected       Step 5: ret_ip_port collected
   from B's 8 client nodes             from A's 8 client nodes
        |                                     |
   Step 7: 6 onion paths built         Step 7: 6 onion paths built
   via TCP relay connections           via TCP relay connections
        |                                     |
   Step 8: announced to DHT            Step 8: announced to DHT
   (12 announce servers)               (12 announce servers)
        |                                     |
   Step 9: DHT PK exchanged ─── onion data ──→ DHT PK exchanged
        |                                     |
   Step 10: messages ─── onion data ────────→ messages
                                  ─── onion data ───→
```

### Summary of DHT's role in this scenario

| Layer | Role | Under Tor |
|-------|------|-----------|
| DHT | Populates routing tables (close list + friend client lists) | Works over TCP relay connections instead of UDP |
| DHT `ret_ip_port` | Discovers peer IPs | Works but IPs are not reachable (no UDP) |
| Onion paths | Built from DHT-discovered nodes | Works over TCP relay connections |
| Onion announce | Registers return path on DHT nodes | Works over TCP relay connections |
| Onion data | Delivers encrypted payloads | **The only working path** under Tor |
| Net crypto | Establishes lossless encrypted channel | Works over onion data delivery |

The DHT's fundamental job — **finding nodes that are XOR-close to a target key** — is the same regardless of transport. Under clearnet UDP, the result is direct IP discovery + NAT hole punching. Under Tor, the result is a populated routing table that enables onion path construction.

---

## Implementation Plan: Tor-Only DHT with Onion Addresses

This section describes the changes needed to make the DHT operate exclusively over Tor, using `.onion` addresses instead of clearnet IP addresses. All UDP-based transport is replaced with TCP connections through Tor's SOCKS5 proxy. NAT hole punching is removed. The DHT routing table stores onion addresses.

### Why this is needed

Currently `Node_format` carries an `IP_Port` which holds a clearnet IPv4/IPv6 address:

```c
typedef struct Node_format {
    uint8_t  public_key[32];       // Curve25519 DHT key
    IP_Port  ip_port;              // clearnet IP + port (19 bytes)
} Node_format;
```

Tor onion addresses (v3) are 56 base32 characters, decoded to 35 bytes — too large for the existing `IP` union (which only has 16 bytes for `IP6`). The entire addressing layer needs to be extended.

### Phase 1: Onion address representation [DONE]

Implemented in `network.h` and `network.c`: `ONION_V3_ADDRESS_SIZE`, `SIZE_ONION`, `IP_Union.onion[35]`, `TOX_AF_ONION`, `net_family_is_onion()`, `net_is_onion()`, `onion_addr_from/to_string()`, `ip_set/get_onion()`, `ip_equal/cmp/isset/reset/parse_addr` onion handling. 10 test cases in `network_test.cc`.

#### 1a. New constants in `network.h`

```c
#define ONION_V3_ADDRESS_SIZE     35   // decoded .onion v3 address bytes
#define SIZE_ONION                ONION_V3_ADDRESS_SIZE
#define PACKED_NODE_SIZE_ONION    (1 + SIZE_ONION + sizeof(uint16_t) + CRYPTO_PUBLIC_KEY_SIZE)
// = 1 + 35 + 2 + 32 = 70 bytes
```

#### 1b. Extend `IP` to hold onion addresses

Current `IP` is 17 bytes (1 family + 16 ip6). Increase the union:

```c
typedef union IP_Union {
    IP4      v4;                      //  4 bytes
    IP6      v6;                      // 16 bytes
    uint8_t  onion[ONION_V3_ADDRESS_SIZE];  // 35 bytes
} IP_Union;

typedef struct IP {
    Family   family;
    IP_Union ip;
} IP;
```

`IP` becomes 36 bytes instead of 17. `IP_Port` becomes 38 bytes instead of 19. This is the most invasive change — every structure containing `IP_Port` grows.

#### 1c. Family helpers

```c
#define TOX_AF_ONION 15   // already defined, but not fully wired

bool net_family_is_onion(Family family);  // already declared
Family net_family_onion(void);             // already declared
```

Wire the `TOX_AF_ONION` case into `make_family()` in `network.c` to resolve to `AF_INET` (needed for the TCP socket to the SOCKS5 proxy — the DNS resolution of `.onion` is handled by Tor, not the OS).

#### 1d. Address helper functions

```c
// Parse "x.onion" → 35-byte decoded address
bool onion_addr_from_string(const char *host, uint8_t *addr);

// 35-byte decoded address → "x.onion"
const char *onion_addr_to_string(const uint8_t *addr, char *buf, size_t bufsz);

// Set IP to onion address
void ip_set_onion(IP *ip, const uint8_t *addr);

// Extract onion address from IP
bool ip_get_onion(const IP *ip, uint8_t *addr);
```

#### 1e. Update address validation functions

```c
bool ip_isset(const IP *ip);       // handle onion family
void ip_reset(IP *ip);             // handle onion family
bool ipport_equal(IP_Port *a, *b); // handle onion family
bool ipport_isset(const IP_Port *ipport); // handle onion family
```

### Phase 2: Wire protocol — pack/unpack onion addresses [DONE]

Implemented in `network.c`: `bin_pack_ip_port()` packs `TOX_AF_ONION` family (1+35+2 = 38 bytes), `unpack_ip_port()` unpacks it. `packed_node_size()` in `DHT.c` returns `PACKED_NODE_SIZE_ONION` (70). 4 pack/unpack round-trip tests in `network_test.cc`.

#### 2a. `bin_pack_ip_port()` in `network.c`

Add a branch for `net_family_is_onion()`:

```c
if (net_family_is_onion(ip_port->ip.family)) {
    return bin_pack_u08_b(bp, TOX_AF_ONION)
           && bin_pack_bin_b(bp, ip_port->ip.ip.onion, SIZE_ONION)
           && bin_pack_u16_b(bp, net_ntohs(ip_port->port));
}
```

#### 2b. `unpack_ip_port()` in `network.c`

Add a branch for `data[0] == TOX_AF_ONION`:

```c
if (data[0] == TOX_AF_ONION) {
    const uint32_t size = 1 + SIZE_ONION + sizeof(uint16_t);  // 38 bytes
    if (size > length) return -1;
    ipport_reset(ip_port);
    ip_port->ip.family = net_family_onion();
    memcpy(ip_port->ip.ip.onion, data + 1, SIZE_ONION);
    memcpy(&ip_port->port, data + 1 + SIZE_ONION, sizeof(uint16_t));
    return size;
}
```

#### 2c. `packed_node_size()` in `DHT.h`

```c
int packed_node_size(Family ip_family) {
    if (net_family_is_onion(ip_family)) return PACKED_NODE_SIZE_ONION;
    // ...existing ipv4/ipv6/tcp cases...
}
```

### Phase 3: Tor transport layer (new module) [DONE]

Files created: `toxcore/tor_transport.h`, `toxcore/tor_transport.c`, `toxcore/tor_transport_test.cc`.
Registered in `CMakeLists.txt`. All 8 unit tests passing.

This replaces `Networking_Core` (UDP socket) as the DHT's I/O backend.

#### 3a. Core structure

```c
typedef struct Tor_Transport Tor_Transport;

typedef struct Tor_Transport_Config {
    char     proxy_host[256];       // e.g. "127.0.0.1"
    uint16_t proxy_port;            // e.g. 9050
    uint8_t  self_public_key[32];   // our DHT key (for incoming routing)
} Tor_Transport_Config;

Tor_Transport *tor_transport_new(const Logger *log, const Memory *mem,
                                  const Mono_Time *mono_time, const Random *rng,
                                  Tor_Transport_Config *cfg);

void tor_transport_kill(Tor_Transport *tran);
```

#### 3b. Connection management

```c
// A TCP connection to one DHT node reachable at an onion address
typedef struct Tor_Node_Connection {
    uint8_t  onion_addr[ONION_V3_ADDRESS_SIZE];  // remote node's onion address
    uint16_t port;                                // remote port
    uint8_t  public_key[32];                      // remote node's DHT key
    Socket   sock;                                // TCP socket through Tor
    uint64_t last_active;                         // for idle timeout
    // send/receive buffers
    uint8_t  recv_buf[4096];
    uint16_t recv_len;
    uint8_t  send_buf[4096];
    uint16_t send_len;
} Tor_Node_Connection;
```

Connection pool (hash map keyed by onion_addr + port):
```c
#define MAX_TOR_CONNECTIONS 128

struct Tor_Transport {
    Tor_Transport_Config  config;
    Tor_Node_Connection   connections[MAX_TOR_CONNECTIONS];
    uint32_t              num_connections;
    // Incoming packet dispatch table
    tor_packet_handler_cb handlers[256];
    void                 *handler_objects[256];
};
```

#### 3c. SOCKS5 connect

Reuse the existing SOCKS5 code from `TCP_client.c`. The flow:

```
1. Create TCP socket → AF_INET, SOCK_STREAM
2. Connect to proxy_host:proxy_port (the Tor SOCKS5 proxy)
3. SOCKS5 handshake:
   - Send: [0x05][0x01][0x00]              (no auth)
   - Recv: [0x05][0x00]                     (auth accepted)
   - Send: [0x05][0x01][0x03][len][host][port]  (connect to .onion)
   - Recv: [0x05][0x00][0x00][0x01|0x03]...    (connected)
4. Wrap DHT packets with length-prefixed framing
```

#### 3d. Message framing

DHT packets over TCP need framing since TCP is a stream protocol:

```c
// Wire format for each DHT packet over TCP:
// [uint16_t length][packet bytes(length)]
//
// length = total packet size including the 2-byte length prefix
// packet = the same bytes that would have been sent over UDP
```

#### 3e. Send/receive API

```c
// Send a DHT packet to a node. Creates/reuses a TCP connection.
int tor_transport_send(Tor_Transport *tran,
                       const uint8_t *onion_addr, uint16_t port,
                       const uint8_t *data, uint16_t length);

// Register a handler for incoming DHT packets by their first byte (type).
typedef void (*tor_packet_handler_cb)(void *object,
                                       const uint8_t *source_pubkey,
                                       const uint8_t *packet, uint16_t length,
                                       void *userdata);

void tor_transport_register_handler(Tor_Transport *tran, uint8_t type,
                                     tor_packet_handler_cb cb,
                                     void *object, void *userdata);

// Main loop — poll all TCP connections, read data, dispatch to handlers.
void tor_transport_iterate(Tor_Transport *tran);
```

#### 3f. Connection reuse and timeout

```c
// Keep connections alive for REUSE_TIMEOUT seconds after last use.
#define TOR_CONNECTION_REUSE_TIMEOUT 30  // seconds
#define TOR_CONNECTION_IDLE_TIMEOUT  300 // seconds — close if totally idle

// On tor_transport_send():
//   1. Look up connection by (onion_addr, port) in pool
//   2. If found and still connected, reuse it
//   3. If not found or stale, open new SOCKS5 connection
//   4. Frame and send the packet
```

### Phase 4: DHT adaptation

#### 4a. Replace `Networking_Core *net` with `Tor_Transport *tran`

In `struct DHT`:

```c
struct DHT {
    // Replace: Networking_Core *net;
    Tor_Transport *tran;               // TCP-over-Tor transport
    // ...
};
```

The constructor `new_dht()` takes a `Tor_Transport *` instead of a `Networking_Core *`.

#### 4b. Replace all `sendpacket()` calls

Current pattern (in `route_packet`, `dht_send_nodes_request`, `send_nodes_response`, ping, etc.):

```c
sendpacket(dht->net, &assoc->ip_port, packet, length);
```

New pattern:

```c
// Extract onion address from the IP_Port
uint8_t onion_addr[ONION_V3_ADDRESS_SIZE];
ip_get_onion(&assoc->ip_port.ip, onion_addr);
tor_transport_send(dht->tran, onion_addr, assoc->ip_port.port, packet, length);
```

#### 4c. Simplify `Client_data` — single association instead of dual

Current `Client_data` has `assoc4` and `assoc6` (two `IPPTsPng` structures). With onion addresses, there is only one address family:

```c
typedef struct Client_data {
    uint8_t  public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port  ip_port;               // onion address + port
    uint64_t timestamp;             // last successful ping
    uint64_t last_pinged;           // last time we sent a ping
    bool     announce_node;         // supports announce protocol
} Client_data;
```

This replaces `IPPTsPng` — no need for dual-stack or `ret_ip_port` (under Tor, return addresses are irrelevant since direct UDP connectivity doesn't exist).

#### 4d. Remove `ret_ip_port` logic

The entire `ret_ip_port` / `ret_timestamp` / `ret_ip_self` mechanism in `IPPTsPng` is for NAT traversal. Under Tor, NAT traversal is handled by the Tor network itself. Remove:

- `IPPTsPng` struct — replaced by a simpler association
- `friend_iplist()` — no longer needed (nobody collects return IPs)
- `returnedip_ports()` in nodes-response handler — removed
- `ipport_self_copy()` — no longer needed

#### 4e. Remove NAT hole punching

Delete the entire NAT section in `DHT.c`:

- `NAT` struct
- `send_nat_ping()` / `handle_nat_ping()`
- `punch_holes()` / `do_nat()` / `nat_commonip()`
- `CRYPTO_PACKET_NAT_PING` constant (or keep it unused)
- `hole_punching_enabled` flag in `DHT`

In the constructor `new_dht()`, the `hole_punching_enabled` and `lan_discovery_enabled` parameters become unused; remove them.

#### 4f. Update `do_dht()` main loop

```c
void do_dht(DHT *dht) {
    // Read incoming packets from Tor TCP connections
    tor_transport_iterate(dht->tran);

    // Existing logic (no changes needed here):
    do_close(dht);
    do_dht_friends(dht);
    do_nat(dht);                // ← DELETE this entire call
}
```

#### 4g. Update `route_packet()` and `route_to_friend()`

`route_packet()` scans the close list for a matching public key. Instead of:

```c
sendpacket(dht->net, &assoc->ip_port, packet, length);
```

It does:

```c
tor_transport_send(dht->tran, assoc->onion_addr, assoc->port, packet, length);
```

`route_to_friend()` broadcasts to all nodes in the friend's client list. Since there's no UDP, `friend_iplist()` is replaced by simply iterating the client list and sending via `tor_transport_send()`.

### Phase 5: Bootstrap changes

#### 5a. Bootstrap node format

Current bootstrap nodes are listed as `IP:port + public_key`. For Tor:

```c
// other/DHTnodes format changes from:
// ip=203.0.113.1 port=33445 key=...
// to:
// onion=z6p3h4x...d.onion port=33445 key=...
```

#### 5b. `dht_bootstrap_from_address()` update

When the hostname ends in `.onion`, resolve using the Tor SOCKS5 proxy (not DNS), then establish a TCP connection through Tor:

```c
bool dht_bootstrap_from_address(DHT *dht, const char *address, ...) {
    if (net_is_onion(address)) {
        uint8_t onion_addr[ONION_V3_ADDRESS_SIZE];
        if (!onion_addr_from_string(address, onion_addr))
            return false;
        // Connect through Tor transport directly
        tor_transport_send(dht->tran, onion_addr, port, nodes_request_packet, len);
        return true;
    }
    // ... existing clearnet path (removed in tor-only build) ...
}
```

### Phase 6: Clearnet code removal

#### 6a. What to remove

| Module | What | Reason |
|--------|------|--------|
| `Networking_Core` | UDP socket, `net_socket()` with `SOCK_DGRAM` | No UDP |
| `DHT.c` | `NAT`, `IPPTsPng.ret_ip_port`, `do_nat()`, `friend_iplist()` | No NAT traversal needed |
| `LAN_discovery.h/c` | UDP broadcast discovery | No LAN, no UDP |
| `network.h` | `IP4`/`IP6` unions (keep only `onion`) | Only onion addresses |
| `network.c` | `net_sendto()`/`net_recvfrom()` for UDP | No UDP |
| `DHT.h` | `hole_punching_enabled`, `lan_discovery_enabled` | No NAT/LAN |

#### 6b. Simplifications enabled

- **`IPPTsPng` removed** → `Client_data` shrinks from dual-assoc to single-assoc
- **`assoc_timeout()` simplified** — no need to check IPv4/IPv6 separately
- **`ip_port_normalize()` removed** — only onion family exists
- **`get_close_nodes_inner()` simplified** — no IPv4/IPv6 preference, no LAN filtering, no family switch
- **`add_to_close()` simplified** — single association per node
- **`replace_all()` simplified** — single association per node

### Phase 7: Implementation order (10 steps)

#### Step 1: Extend `IP` union

Edit `network.h` — add `uint8_t onion[ONION_V3_ADDRESS_SIZE]` to `IP_Union`. Update `IP` struct. Define `SIZE_ONION`, `PACKED_NODE_SIZE_ONION`.

**Impact**: All files that include `network.h` will see `IP` grow from 17 to 36 bytes. This requires a full rebuild. Every `memcpy`, `sizeof`, serialization of `IP_Port` must be checked.

#### Step 2: Wire onion address family

Edit `network.c`:
- `make_family()` — handle `TOX_AF_ONION` → `AF_INET`
- `bin_pack_ip_port()` — handle onion family
- `unpack_ip_port()` — handle `data[0] == TOX_AF_ONION`
- `ip_isset()`, `ip_reset()`, `ipport_equal()` — handle onion family
- `net_ip_ntoa()` — display `.onion` address

Edit `network.h`:
- `net_family_is_onion()` — implement (already declared)
- `net_is_onion()` — implement (already declared)

#### Step 3: Address conversion helpers

New functions in `network.c` / `network.h`:
- `onion_addr_from_string()` — base32 decode 56 chars → 35 bytes
- `onion_addr_to_string()` — 35 bytes → base32 encode + ".onion"
- `ip_set_onion()` / `ip_get_onion()`

#### Step 4: Create `tor_transport` module

New files `tor_transport.h` / `tor_transport.c`:
- `Tor_Transport` struct
- SOCKS5 connection via Tor proxy
- Connection pool with reuse/timeout
- Length-prefixed message framing
- `tor_transport_send()` — send DHT packet to onion address
- `tor_transport_register_handler()` — dispatch incoming packets
- `tor_transport_iterate()` — poll connections, read, dispatch

Also: `tor_packet_handler_cb` typedef, `Tor_Transport_Config`.

#### Step 5: Simplify `Client_data`

Replace the dual-`IPPTsPng` model with a single `IP_Port` (onion) in `DHT.h`:

```c
typedef struct Client_data {
    uint8_t  public_key[CRYPTO_PUBLIC_KEY_SIZE];
    IP_Port  ip_port;          // onion address + port (38 bytes)
    uint64_t timestamp;
    uint64_t last_pinged;
    bool     announce_node;
} Client_data;
```

Remove `IPPTsPng` and `IPPTs` typedefs entirely.

#### Step 6: Remove `ret_ip_port` and `NAT`

Edit `DHT.c`:
- Delete `NAT` struct, `send_nat_ping()`, `handle_nat_ping()`, `punch_holes()`, `do_nat()`
- Delete `friend_iplist()`, `returnedip_ports()`
- Delete `ipport_self_copy()`
- In `handle_nodes_response()` — remove the `returnedip_ports()` call
- Remove `CRYPTO_PACKET_NAT_PING` from `DHT.h` (or keep as unused constant)
- Remove `hole_punching_enabled` and `lan_discovery_enabled` from struct DHT and `new_dht()`

#### Step 7: Adapt DHT to use `Tor_Transport`

Edit `DHT.c` and `DHT.h`:
- Replace `Networking_Core *net` with `Tor_Transport *tran` in `struct DHT`
- `new_dht()` takes `Tor_Transport *` instead of `Networking_Core *`
- All `sendpacket(dht->net, ip_port, ...)` → `tor_transport_send(dht->tran, onion_addr, port, ...)`
- Registration of packet handlers: `networking_registerhandler(dht->net, ...)` → `tor_transport_register_handler(dht->tran, ...)`
- Update `dht_get_net()` → `dht_get_transport()` return type change
- Remove `LAN_discovery.h` include

#### Step 8: Update ping subsystem

Edit `ping.c`:
- `send_packet()` call → `tor_transport_send()`
- Remove the `IP_Port` verification in `handle_ping_response()` (IP matching after source check still works — `ipport_equal` handles onion addresses)
- `ping_add()` — update `in_list()` check for onion-only client data

#### Step 9: Update bootstrap

Edit `DHT.c`:
- `dht_bootstrap_from_address()` — detect `.onion`, use `tor_transport_send()`
- `dht_bootstrap()` — takes an onion address instead of `IP_Port`
- Update `dht_connect_after_load()` — handle onion nodes from saved state

Edit `other/DHTnodes` — update to list `.onion` addresses.

#### Step 10: Remove clearnet dependencies

- Remove `Networking_Core` from build (or make it a no-op)
- Remove `LAN_discovery` module from build
- Remove UDP-related code from `network.c` (keep only TCP socket functions for SOCKS5)
- Remove `IP4`/`IP6` from `IP_Union` (keep only `onion`)
- Clean up `new_dht()` signature — remove `hole_punching_enabled`, `lan_discovery_enabled`

### Summary of file changes

| File | Change |
|------|--------|
| `toxcore/network.h` | Extend `IP_Union` with `onion[35]`; new constants; new helper declarations |
| `toxcore/network.c` | Wire onion in pack/unpack/display; implement helpers; remove UDP functions |
| `toxcore/tor_transport.h` | **New** — `Tor_Transport` API, SOCKS5 config, handler registration |
| `toxcore/tor_transport.c` | **New** — SOCKS5 connections, TCP framing, connection pool, iterate loop |
| `toxcore/DHT.h` | `Client_data` → single assoc; remove `IPPTsPng`, `NAT`, `IPPTs`; update `new_dht()` |
| `toxcore/DHT.c` | Replace `sendpacket()` → `tor_transport_send()`; remove NAT, `ret_ip_port`, LAN; update bootstrap |
| `toxcore/ping.h` / `ping.c` | Update send/recv to use `Tor_Transport` |
| `toxcore/ping_array.h` / `ping_array.c` | No changes needed (works on byte arrays) |
| `toxcore/crypto_core.h` | No changes needed |
| `toxcore/shared_key_cache.h` / `shared_key_cache.c` | No changes needed |
| `toxcore/LAN_discovery.h` / `LAN_discovery.c` | Remove from build (not deleted) |
| `toxcore/onion.h` / `onion.c` | May simplify — 3-hop onion is redundant over Tor |
| `toxcore/onion_announce.h` / `onion_announce.c` | No changes needed |
| `toxcore/onion_client.h` / `onion_client.c` | Will work over Tor transport automatically |
| `toxcore/TCP_connection.h` / `TCP_connection.c` | May be simplified — less need for TCP relays with direct Tor connections |
| `toxcore/Messenger.h` / `Messenger.c` | Update `new_dht()` calls; remove proxy fallback logic |
| `other/DHTnodes` | Replace IPs with .onion addresses |
| `docs/updates/DHT.md` | Update protocol spec for onion address family |

### Key design decisions

1. **Why extend `IP` instead of a separate `Onion_Addr` type?** Because `IP_Port` is used everywhere (routing tables, packet handling, saving/loading). Changing it in one place propagates automatically through existing code paths.

2. **Why a connection pool instead of one connection per packet?** Tor circuit creation is expensive (~1-2s). Keeping TCP connections alive to frequently contacted nodes (close list neighbors) reduces latency dramatically.

3. **Why not reuse `TCP_Client_Connection` from the relay code?** The TCP relay protocol is designed for the relay use case (routing connections to other peers). For direct DHT node-to-node communication over Tor, a simpler length-prefixed framing is sufficient and avoids the overhead of the relay routing protocol.

4. **Why remove `ret_ip_port`?** This mechanism exists so that NAT-ed peers learn their own public IP. Under Tor, every connection goes through the Tor network — the concept of a "public IP" is irrelevant because the Tor exit node or hidden service provides connectivity regardless of the client's actual IP. No hole-punching is needed.

5. **Can the onion routing layer be simplified?** The existing 3-hop onion path (used for friend-to-friend messaging when UDP is blocked) is redundant over Tor, since Tor already provides multi-hop anonymity. However, removing it would break compatibility. For a clean tor-only build, it could be removed — but for incremental adoption, it can stay.

## Relevant Files

| File | Purpose |
|------|---------|
| `toxcore/DHT.h` | DHT header (structures, API) |
| `toxcore/DHT.c` | DHT implementation |
| `toxcore/ping.h` / `ping.c` | Ping subsystem |
| `toxcore/ping_array.h` / `ping_array.c` | Ping ID storage |
| `toxcore/crypto_core.h` | Crypto constants |
| `toxcore/network.h` | Packet types, IP_Port |
| `toxcore/shared_key_cache.h` / `shared_key_cache.c` | ECDH cache |
| `toxcore/onion.h` / `onion.c` | Onion routing |
| `toxcore/onion_announce.h` / `onion_announce.c` | Announce protocol |
| `toxcore/onion_client.h` / `onion_client.c` | Onion client |
| `toxcore/TCP_connection.h` / `TCP_connection.c` | TCP relay connection |
| `toxcore/LAN_discovery.h` / `LAN_discovery.c` | LAN discovery |
| `docs/updates/DHT.md` | Original protocol spec |
| `other/DHTnodes` | Bootstrap node list |
