# Plan: Native .onion / Tor support for c-toxcore

## Problem

c-toxcore has SOCKS5 proxy support for TCP relay connections, but cannot
handle `.onion` addresses:

- **DNS resolution**: `net_getipport()` → `sys_getaddrinfo()` uses system DNS,
  which cannot resolve `.onion` (`network.c:599`)
- **SOCKS5 handshake**: `proxy_socks5_generate_connection_request()` only
  sends `ATYP_IPV4` (0x01) and `ATYP_IPV6` (0x04), not `ATYP_DOMAINNAME`
  (0x03). No domain name support (`TCP_client.c:254-264`)
- **`IP_Port` size constraint**: `IP` struct is 1 byte family + 16 bytes
  union (`IP4`/`IP6`). `.onion` addresses are up to 56 chars — can't fit.

## Design

Thread the `.onion` domain name alongside `IP_Port` through the TCP connection
chain. Use a new `net_family_onion()` sentinel family to signal that the IP
field is a placeholder and the real destination is a domain name stored
separately in the `TCP_Client_Connection`.

## Changes

### 1. New address family: `net_family_onion`

**Files:** `toxcore/network.c`, `toxcore/network.h`

- Add `static const Family family_onion = {TOX_AF_ONION};` (define `TOX_AF_ONION`
  as a new sentinel value, e.g. `AF_UNSPEC - 1`)
- Add `Family net_family_onion(void)` and `bool net_family_is_onion(Family)`
- Update `make_tox_family()` in `network.c` to handle the new family

### 2. `.onion` detection utility

**Files:** `toxcore/network.c`, `toxcore/network.h`

```c
bool net_is_onion(const char *host);
```
Returns true if host ends with `.onion`.

### 3. Domain name storage in `TCP_Client_Connection`

**File:** `toxcore/TCP_client.c` (struct definition is internal to this file)

Add field to the `TCP_Client_Connection` struct:
```c
char onion_domain[TOX_MAX_HOSTNAME_LENGTH]; // 255 bytes
```

Initialised to empty string. When `net_family_is_onion(ip_port.ip.family)`,
this field holds the `.onion` address.

### 4. Thread domain through connection chain

**Files:** `toxcore/tox.c`, `toxcore/net_crypto.c`, `toxcore/TCP_connection.c`,
`toxcore/TCP_connection.h`, `toxcore/TCP_client.c`

**`tox_add_tcp_relay()`** (`tox.c:1131`):
- Before calling `resolve_bootstrap_node()`, check `net_is_onion(host)`
- If `.onion`:
  - Build a synthetic `IP_Port` with `net_family_onion()`, zeroed IP, given port
  - Call `add_tcp_relay_onion(m->net_crypto, &ip_port, host, public_key)` (new function)
  - Return (skip normal `resolve_bootstrap_node()` path)
- If not `.onion`: existing code path unchanged

**`net_crypto.c`**: Add `add_tcp_relay_onion()`:
```c
int add_tcp_relay_onion(Net_Crypto *c, const IP_Port *ip_port,
                         const char *domain, const uint8_t *public_key);
```
→ calls `add_tcp_relay_global_onion(c->tcp_c, ip_port, domain, public_key)`

**`TCP_connection.c`**: 
- Add `add_tcp_relay_global_onion()` and `add_tcp_relay_instance_onion()`
- These mirror the existing `add_tcp_relay_global/instance` but accept a
  `const char *domain` parameter
- At `new_tcp_connection()` call site, they copy `domain` into the connection
  via a new `tcp_con_set_onion_domain()` setter or parameter

**`TCP_client.c` — `new_tcp_connection()`** (`TCP_client.c:586`):
- Accept `const char *onion_domain` parameter (NULL if not onion)
- After creating the connection, copy domain: `strcpy(temp->onion_domain, onion_domain)`
- Relax the family check at line 597 to also accept `net_family_is_onion()`

### 5. SOCKS5 domain name handshake

**File:** `toxcore/TCP_client.c`

**`proxy_socks5_generate_connection_request()`** (`TCP_client.c:247`):
- Add `ATYP_DOMAINNAME = 0x03` constant
- When `net_family_is_onion(tcp_conn->ip_port.ip.family)`:
  - Send `ATYP_DOMAINNAME` + 1-byte length + domain string + port
  - Domain comes from `tcp_conn->onion_domain`
- The existing IPv4/IPv6 paths remain unchanged for non-onion addresses

**`proxy_socks5_read_connection_response()`** (`TCP_client.c:278`):
- Handle variable-length domain name responses (different response size
  than fixed IPv4/IPv6)
- For domain name ATYP, the response is: VER(1) + REP(1) + RSV(1) + ATYP(1)
  + LEN(1) + DOMAIN(LEN) + PORT(2) — variable length

**`proxy_socks5_generate_greetings()`** (`TCP_client.c:215`):
- No change needed (greeting is independent of destination type)

### 6. `connect_sock_to()`: connect to proxy for onion

**File:** `toxcore/TCP_client.c` (`connect_sock_to()`, line 110)

When proxy is set, the socket already connects to the proxy's IP (line 115).
For `.onion` addresses, the flow is:
- Socket connects to proxy's IP (unchanged — already works)
- SOCKS5 handshake sends the `.onion` domain (new — from step 5)
- Tor resolves the `.onion` and connects

No change needed in `connect_sock_to()` itself — it already connects to the
proxy when `proxy_info->proxy_type != TCP_PROXY_NONE`. The domain name is
only used in the SOCKS5 handshake which happens after connecting.

Wait — check: `connect_sock_to()` at line 114-115 connects to `proxy_info->ip_port`,
not to `ip_port`. Then the SOCKS5 handshake in step 5 sends the actual destination
(`onion_domain`). This is correct for SOCKS5 protocol.

### 7. `tox_bootstrap()`: onion path node support

**File:** `toxcore/tox.c`

When `.onion` address and proxy is set (UDP is disabled):
- Skip UDP bootstrap (`tox_bootstrap()` at line 1105-1110 already skips
  UDP when `udp_disabled`, which is auto-set when proxy is active)
- Need `onion_add_bs_path_node()` to accept a domain instead of just `IP_Port`

**Option A:** Extend `onion_add_bs_path_node()` to accept domain name:
- Current: `bool onion_add_bs_path_node(Onion_Client *onion_c, const IP_Port *ip_port, const uint8_t *public_key)`
- New overload: `bool onion_add_bs_path_node_onion(Onion_Client *onion_c, const IP_Port *ip_port, const char *domain, const uint8_t *public_key)`
- Internally stores the domain alongside the path node entry for later TCP connection setup

**Option B:** Store domain in `IP_Port` using a side-channel (hash table):
- Hash fake IP → domain mapping
- More complex but less invasive

**Recommendation:** Option A — it's explicit and follows the same pattern
as the TCP connection chain.

### 8. Path node usage: connecting via path nodes

**File:** `toxcore/onion_client.c`

When building onion paths via TCP, the path node's `IP_Port` is used to
create a TCP connection. When the path node has `net_family_onion`:
- The stored domain name must be passed through to `new_tcp_connection()`
- This means the path node storage (`onion_add_bs_path_node`) needs to
  retain the domain string and pass it forward when creating connections

### 9. `add_tcp_relay_peer()` and `add_tcp_relay_connection()`

**Files:** `toxcore/net_crypto.c`, `toxcore/TCP_connection.c`

These are used for relaying to specific peers. When the peer's relay is an
`.onion` address, the domain name must flow through these paths too. Same
pattern: new `_onion` variants of these functions.

### 10. Error handling / family validation updates

Many places in the code validate IP families with assertions like:
- `TCP_client.c:597`: `if (!net_family_is_ipv4(...) && !net_family_is_ipv6(...))`
- `TCP_connection.c:1273`: same pattern
- `DHT.c` and other files check families

All such checks must be updated to also accept `net_family_is_onion()` or
`net_family_is_tcp_onion()` as appropriate, or at minimum not assert-fail
on the new family.

## Summary of files changed

| File | Change |
|---|---|
| `toxcore/network.h` | `net_family_onion()`, `net_is_onion()` declarations, `TOX_AF_ONION` |
| `toxcore/network.c` | `family_onion` constant, `net_family_onion()`/`net_is_onion()`/`net_family_is_onion()` impl, `make_tox_family()` update |
| `toxcore/TCP_client.c` | `onion_domain` field in struct, `new_tcp_connection()` domain param, SOCKS5 `ATYP_DOMAINNAME` handshake, family validation update |
| `toxcore/TCP_client.h` | Updated `new_tcp_connection()` declaration |
| `toxcore/TCP_connection.c` | `add_tcp_relay_instance_onion()`, `add_tcp_relay_global_onion()`, family validation updates |
| `toxcore/TCP_connection.h` | New function declarations, `TCP_con` domain field (optional) |
| `toxcore/net_crypto.c` | `add_tcp_relay_onion()`, `add_tcp_relay_peer_onion()` |
| `toxcore/net_crypto.h` | New function declarations |
| `toxcore/tox.c` | `.onion` handling in `tox_bootstrap()` and `tox_add_tcp_relay()` |
| `toxcore/onion_client.c` | Path node domain storage and forwarding |
| `toxcore/onion_client.h` | `onion_add_bs_path_node_onion()` declaration |
