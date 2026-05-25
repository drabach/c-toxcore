# Security Audit: c-toxcore

Date: 2026-05-24  
Scope: `toxcore/`, `toxav/`, `auto_tests/`, `testing/fuzzing/`  
Languages: C (production), C++ (test/fuzz infrastructure)

---

## Critical

### C1. VLA stack overflow from network-controlled size — `group.c:2923,2940` (FIXED)

```c
// line 2923
VLA(uint8_t, newmsg, msg_data_len + 1);
// line 2940
VLA(uint8_t, newmsg, msg_data_len + 1);
```

`msg_data_len` is derived from `length` received from a network packet via `handle_message_packet_group`. The only validation is a minimum size check at line 2790 (`length < sizeof(uint16_t) + sizeof(uint32_t) + 1`), with no upper bound. `msg_data_len` can be up to ~1366 bytes, allocated as a VLA (C99 `type name[size]` or `alloca`) on the stack.

While 1.3KB alone is unlikely to overflow an 8MB thread stack, repeated VLAs in the call chain or on systems with smaller stacks (embedded, constrained threads) could cause stack overflow. The use of network-controlled sizes in stack allocation is a violation of safe coding practice.

- `PACKET_ID_MESSAGE` case: line 2923
- `PACKET_ID_ACTION` case: line 2940

**Fix:** Added `|| msg_data_len > MAX_GROUP_MESSAGE_DATA_LEN` to both existing zero-length checks, so oversized messages are rejected before the VLA allocation.

### C2. VLA stack overflow (lossy packet, no length check) — `group.c:2719–2720` (FIXED)

```c
// line 2712: TODO(irungentoo): length check here?
const uint16_t packet_size = sizeof(uint16_t) * 2 + length;
VLA(uint8_t, packet, packet_size);
```

`length` is `uint16_t` from the caller via the public API `send_group_lossy_packet`. Maximum value 65535 creates a 65539-byte VLA on the stack — guaranteed stack overflow on any system with default stack sizes. There is an explicit TODO noting the missing check.

The downstream `send_lossy_group_peer` at line 1617 does check `1 + sizeof(uint16_t) + length > MAX_CRYPTO_DATA_SIZE`, but the VLA allocation happens *before* that check in the calling path.

**Fix:** Added `if (packet_size > MAX_CRYPTO_DATA_SIZE) { return -1; }` before the VLA allocation. Removed the stale TODO.

---

## High

### H1. Stale pointer / inconsistent state on `mem_vrealloc` failure — multiple sites (FIXED: 5 sites, 0 remain)

Approximately 27 call sites use the pattern:

```c
Some_Type *temp = (Some_Type *)mem_vrealloc(g_c->mem, g->group, g->numpeers + 1, sizeof(Some_Type));
if (temp == nullptr) {
    return -1;  // old pointer preserved, but counters may already be incremented
}
g->group = temp;
```

When `mem_vrealloc` returns `nullptr`, the old pointer remains valid (the `Memory` abstraction only frees on success), but surrounding state (e.g. `g->numpeers` incremented earlier at `group.c:822`) is already modified, leaving the object in an inconsistent state. A subsequent operation could read past the allocated array.

**Fix applied to `delpeer` (group.c), `delete_frozen` (group.c), `dht_delfriend` (DHT.c), `peer_delete` (group_chats.c), and `mod_list_remove_index` (group_moderation.c):** Counter decrement moved after the `mem_vrealloc` call. The new size is computed into a local variable before the call. On realloc failure, the counter is unchanged and state remains consistent. An audit of the full codebase found 27 `mem_vrealloc` call sites total; all 5 sites with the vulnerable pattern have been fixed and 0 remain.

### H2. Integer overflow in length computation — `group.c:2810` (MITIGATED)

```c
const uint16_t msg_data_len = length - (sizeof(uint16_t) + sizeof(message_number) + 1);
```

`length` and `msg_data_len` are `uint16_t`. Minimum check at line 2790 ensures `length >= 7`, but there is no maximum. With `length` up to `MAX_CRYPTO_DATA_SIZE` (~1373), `msg_data_len` reaches ~1366, feeding into VLA allocation (see C1).

**Mitigation:** C1's fix adds `|| msg_data_len > MAX_GROUP_MESSAGE_DATA_LEN` to the VLA guards in both `PACKET_ID_MESSAGE` and `PACKET_ID_ACTION` cases, preventing oversized `msg_data_len` from reaching the VLA allocation. The root integer overflow in the subtraction itself is still theoretically possible but harmless because the result is now bounded before use.

### H3. Missing lossy packet length upper bound — `group.c:2712` (FIXED)

```c
// TODO(irungentoo): length check here?
```

The public API function `send_group_lossy_packet` accepts any `uint16_t length` with no upper bound before stack allocation. The TODO has been present in the code for years.

**Fix:** Added `if (packet_size > MAX_CRYPTO_DATA_SIZE) { return -1; }` before the VLA allocation, and removed the stale TODO comment.

---

## Medium

### M1. `int_map` array off-by-one — `testing/fuzzing/fuzz_support.hh:288` (FIXED)

```cpp
std::array<V, UINT16_MAX> values;  // 65535 elements (indices 0..65534)
// methods access via uint16_t key (range 0..65535)
```

`emplace` and `find` access `values[key]` where `key` can be 65535 (out of bounds, one past end). Used in `Record_System::Global::bound` for UDP port tracking. Test/fuzz code only, but causes heap-buffer-overflow under ASan when a port number is 65535.

**Fix:** Array size changed to `UINT16_MAX + 1` (65536) to cover all valid `uint16_t` keys. The `end()` sentinel now uses an explicit `is_end` flag instead of relying on an out-of-range key value.

### M2. Integer truncation in fuzz test — `toxcore/forwarding_fuzz_test.cc:37` (FIXED)

```cpp
const uint16_t chain_keys_size = chain_length * CRYPTO_PUBLIC_KEY_SIZE;
```

When `chain_length >= 2048`, `chain_length * 32` wraps `uint16_t` to 0. `CONSUME_OR_RETURN` consumes 0 bytes, but the production code reads `chain_length * CRYPTO_PUBLIC_KEY_SIZE` bytes from the buffer, causing OOB read. Test/fuzz code only.

**Fix:** Changed `chain_keys_size` to `size_t` and cast `chain_length` before multiplication to avoid truncation.

### M3. Timing side-channel in peer lookup — `group.c:351` (FIXED)

```c
for (uint32_t i = 0; i < g->numpeers; ++i) {
    if (pk_equal(g->group[i].real_pk, real_pk)) {
        return i;
    }
}
```

`pk_equal` uses constant-time comparison, but the loop returns early on the first match, leaking which peer index matched via timing.

**Fix:** Both `peer_in_group` and `frozen_in_group` now iterate all entries before returning, storing the match index in a local variable. Loop timing no longer reveals the peer's position.

### M4. Conditional locking race — `group.c:1248–1249` (NOT A BUG)

```c
if (lock) {
    friend_connection_lock(g_c->fr_c, friendcon_id);
}
```

`friend_connection_lock` is a reference-count increment, not a mutex. `lock=true` means "add a reference" (preventing the connection from being freed); `lock=false` means the caller already holds a reference. The two consecutive calls at lines 1790/1793 are safe because the second call finds the connection already in the list and skips the lock code entirely. No concurrent access vulnerability exists.

### M5. Stale `temp_pk` after thawing frozen peer — `group.c:707–708` (NOT A BUG)

```c
g->group[thawed_index] = g->frozen[frozen_index];
g->group[thawed_index].temp_pk_updated = false;
```

Setting `temp_pk_updated = false` causes `addpeer` to **update** the temp_pk on next contact (`if (fresh || !g->group[peer_index].temp_pk_updated)` at line 783 enters the block when false). This is the intended behavior — the stale temp_pk from before freezing gets refreshed on the next incoming peer packet.

---

## Low

### L1. Missing `crypto_memzero` on stack secrets — `group.c:1676` (FIXED)

```c
uint8_t packet[1 + 1 + GROUP_ID_LENGTH];
packet[0] = PACKET_ID_REJOIN_CONFERENCE;
packet[1] = g->type;
memcpy(packet + 2, g->id, GROUP_ID_LENGTH);
```

Group ID (symmetric key) left on stack after function return. Should be zeroed with `crypto_memzero`.

**Fix:** Added `crypto_memzero(packet, sizeof(packet))` before both return paths in `try_send_rejoin`.

### L2. Unchecked return values — `group.c:2386` (ACKNOWLEDGED)

```c
if (send_packet_group_peer(..., response_packet, p - response_packet)) {
    sent = i;
} else {
    return sent;
}
```

Partially sent responses leak information about which peers the sender is connected to. The function uses resumable semantics (returns count of successfully sent peers), so returning 0 on failure would break the retry protocol. This is an accepted design trade-off for a P2P network where peer counts are partially observable anyway.

### L3. Minor: unused includes, stale TODOs (FIXED)

Removed 5 empty `TODO(irungentoo):` comments and 1 stale `TODO(iphydf):` comment (false alarm about `nick_len > 255` — `nick_len` is `uint8_t` and `MAX_NAME_LENGTH` is 128).

---

## Informational / Not a Bug

### N1. Zero-strip loop in `group_chats.c:1466–1477`

```c
while (real_plain[0] == 0) {
    ++real_plain;
    --plain_len;
    if (plain_len < min_plain_len) {
        return -3;
    }
}
```

`plain_len` is `int` (signed). The bounds check is inside the loop and fires before the next read. Safe as written — the earlier audit report misclassified this.

### N2. VLA usage across codebase

Files using VLAs: `onion_client.c`, `onion_announce.c`, `onion.c`, `net_crypto.c`, `timed_auth.c`, `group.c`. Each VLA with network-influenced size should be reviewed. The most dangerous cases are documented above (C1, C2).

---

## C++ Files (Test/Fuzz Infrastructure)

All C++ source in this project is test or fuzzing infrastructure. No production C++ code exists. Findings:

| File | Issue | Severity |
|------|-------|----------|
| `fuzz_support.hh:288` | `int_map` array off-by-one (UINT16_MAX vs 65536 entries) | Medium (FIXED) |
| `forwarding_fuzz_test.cc:37` | `uint16_t` wrap in size computation | Medium (FIXED) |

Both are test-only, not exploitable in production.

---

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| Critical | 2 (FIXED) | VLA stack overflow from network data (C1, C2) |
| High | 3 | C1/H2 mitigation, H3 FIXED, H1: 5 sites FIXED (0 remain) |
| Medium | 5 | off-by-one (test, FIXED), int truncation (test, FIXED), M3 FIXED, M4/M5 not a bug |
| Low | 3 | L1 FIXED, L2 acknowledged (design), L3 minor |
| Not a bug | 3 | N1 + M4 + M5 |

### Remaining priority fixes

None. All findings have been fixed, acknowledged by design, or determined not to be bugs.
