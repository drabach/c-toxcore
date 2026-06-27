/** Auto Tests: basic network profile functionality test (TCP only)
 */

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "../toxcore/tox_private.h"
#include "../toxcore/util.h"

#include "auto_test_support.h"
#include "check_compat.h"

#define NUM_TOXES 2

static void test_netprof(AutoTox *autotoxes)
{
    for (size_t i = 0; i < 256; ++i) {
        for (uint32_t j = 0; j < NUM_TOXES; ++j) {
            tox_friend_send_message(autotoxes[j].tox, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"test", 4, nullptr);
        }

        iterate_all_wait(autotoxes, NUM_TOXES, ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < 100; ++i) {
        iterate_all_wait(autotoxes, NUM_TOXES, ITERATION_INTERVAL);
    }

    const Tox *tox1 = autotoxes[0].tox;

    const uint64_t TCP_count_sent1 = tox_netprof_get_packet_total_count(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
                                     TOX_NETPROF_DIRECTION_SENT);
    const uint64_t TCP_count_recv1 = tox_netprof_get_packet_total_count(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
                                     TOX_NETPROF_DIRECTION_RECV);
    const uint64_t TCP_bytes_sent1 = tox_netprof_get_packet_total_bytes(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
                                     TOX_NETPROF_DIRECTION_SENT);
    const uint64_t TCP_bytes_recv1 = tox_netprof_get_packet_total_bytes(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
                                     TOX_NETPROF_DIRECTION_RECV);

    ck_assert(TCP_count_recv1 > 0 && TCP_count_sent1 > 0);
    ck_assert(TCP_bytes_recv1 > 0 && TCP_bytes_sent1 > 0);

    uint64_t total_sent_count = 0;
    uint64_t total_recv_count = 0;
    uint64_t total_sent_bytes = 0;
    uint64_t total_recv_bytes = 0;

    for (size_t i = 0; i < 256; ++i) {
        total_sent_count += tox_netprof_get_packet_id_count(tox1, TOX_NETPROF_PACKET_TYPE_TCP, i,
                            TOX_NETPROF_DIRECTION_SENT);
        total_recv_count += tox_netprof_get_packet_id_count(tox1, TOX_NETPROF_PACKET_TYPE_TCP, i,
                            TOX_NETPROF_DIRECTION_RECV);

        total_sent_bytes += tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_TCP, i,
                            TOX_NETPROF_DIRECTION_SENT);
        total_recv_bytes += tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_TCP, i,
                            TOX_NETPROF_DIRECTION_RECV);
    }

    const uint64_t total_packets = total_sent_count + total_recv_count;
    ck_assert_msg(total_packets == TCP_count_sent1 + TCP_count_recv1,
                  "%" PRIu64 " does not match %" PRIu64 "\n", total_packets, TCP_count_sent1 + TCP_count_recv1);

    ck_assert_msg(total_sent_count == TCP_count_sent1, "%" PRIu64 " does not match %" PRIu64 "\n", total_sent_count, TCP_count_sent1);
    ck_assert_msg(total_recv_count == TCP_count_recv1, "%" PRIu64 " does not match %" PRIu64 "\n", total_recv_count, TCP_count_recv1);

    const uint64_t total_bytes = total_sent_bytes + total_recv_bytes;
    ck_assert_msg(total_bytes == TCP_bytes_sent1 + TCP_bytes_recv1,
                  "%" PRIu64 " does not match %" PRIu64 "\n", total_bytes, TCP_bytes_sent1 + TCP_bytes_recv1);

    ck_assert_msg(total_sent_bytes == TCP_bytes_sent1, "%" PRIu64 " does not match %" PRIu64 "\n", total_sent_bytes, TCP_bytes_sent1);
    ck_assert_msg(total_recv_bytes == TCP_bytes_recv1, "%" PRIu64 " does not match %" PRIu64 "\n", total_recv_bytes, TCP_bytes_recv1);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotox_opts = default_run_auto_options();
    autotox_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_TOXES, test_netprof, 0, &autotox_opts);

    return 0;
}

#undef NUM_TOXES
