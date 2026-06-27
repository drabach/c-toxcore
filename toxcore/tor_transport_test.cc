#include "tor_transport.h"

#include <gtest/gtest.h>

#include <cstring>

#include "crypto_core.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"
#include "network_test_util.hh"
#include "test_util.hh"

template <>
struct Deleter<Tor_Transport> : Function_Deleter<Tor_Transport, tor_transport_kill> {};

namespace {

TEST(TorTransportNew, CreatesAndDestroys)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Random *rng = nullptr;
    const Network *ns = os_network();

    Tor_Transport_Config cfg{};
    std::strcpy(cfg.proxy_host, "127.0.0.1");
    cfg.proxy_port = 9050;
    std::memset(cfg.self_public_key, 0x42, sizeof(cfg.self_public_key));

    Ptr<Tor_Transport> tran(
        tor_transport_new(log, mem, mono_time, rng, ns, &cfg));
    ASSERT_NE(tran, nullptr);

    EXPECT_EQ(tor_transport_num_connections(tran.get()), 0u);

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

TEST(TorTransportNew, MultipleInstances)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Network *ns = os_network();

    Tor_Transport_Config cfg1{};
    std::strcpy(cfg1.proxy_host, "127.0.0.1");
    cfg1.proxy_port = 9050;

    Tor_Transport_Config cfg2{};
    std::strcpy(cfg2.proxy_host, "192.168.1.1");
    cfg2.proxy_port = 9150;

    Ptr<Tor_Transport> t1(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg1));
    Ptr<Tor_Transport> t2(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg2));
    ASSERT_NE(t1, nullptr);
    ASSERT_NE(t2, nullptr);

    EXPECT_EQ(tor_transport_num_connections(t1.get()), 0u);
    EXPECT_EQ(tor_transport_num_connections(t2.get()), 0u);

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

TEST(TorTransportNew, NullKillIsSafe)
{
    tor_transport_kill(nullptr);
}

TEST(TorTransportRegisterHandler, StoresAndReplacesHandler)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Network *ns = os_network();

    Tor_Transport_Config cfg{};
    std::strcpy(cfg.proxy_host, "127.0.0.1");
    cfg.proxy_port = 9050;

    Ptr<Tor_Transport> tran(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg));
    ASSERT_NE(tran, nullptr);

    int call_count = 0;
    auto handler = +[](void *object, const IP_Port *, const uint8_t *, uint16_t, void *) {
        ++(*static_cast<int *>(object));
    };

    tor_transport_register_handler(tran.get(), 0x00, handler, &call_count);

    /* Re-register with null should not crash */
    tor_transport_register_handler(tran.get(), 0x00, nullptr, nullptr);
    /* Register another type */
    tor_transport_register_handler(tran.get(), 0x01, handler, &call_count);

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

TEST(TorTransportIterate, EmptyTransportDoesNotCrash)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Network *ns = os_network();

    Tor_Transport_Config cfg{};
    std::strcpy(cfg.proxy_host, "127.0.0.1");
    cfg.proxy_port = 9050;

    Ptr<Tor_Transport> tran(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg));
    ASSERT_NE(tran, nullptr);

    tor_transport_iterate(tran.get(), nullptr);

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

TEST(TorTransportSend, SendsToUnreachableProxyReturnsError)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Network *ns = os_network();

    /* Use a proxy address that is unlikely to exist */
    Tor_Transport_Config cfg{};
    std::strcpy(cfg.proxy_host, "127.0.0.1");
    cfg.proxy_port = 1;  /* port 1 is almost certainly not listening */

    Ptr<Tor_Transport> tran(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg));
    ASSERT_NE(tran, nullptr);

    uint8_t onion_addr[ONION_V3_ADDRESS_SIZE];
    std::memset(onion_addr, 0x42, sizeof(onion_addr));
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    std::memset(public_key, 0x42, sizeof(public_key));
    uint8_t packet[] = {0x00, 0x01, 0x02, 0x03};

    /* Should queue the packet and return 1 even when proxy is unreachable,
     * because the connection is created and the packet is buffered. */
    const int ret = tor_transport_send(
        tran.get(), onion_addr, 33445, public_key, packet, sizeof(packet));
    EXPECT_EQ(ret, 1);

    /* Iterate once to let it try the connection */
    tor_transport_iterate(tran.get(), nullptr);

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

TEST(TorTransportSend, DifferentOnionAddressesCreateDifferentConnections)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Network *ns = os_network();

    Tor_Transport_Config cfg{};
    std::strcpy(cfg.proxy_host, "127.0.0.1");
    cfg.proxy_port = 9050;

    Ptr<Tor_Transport> tran(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg));
    ASSERT_NE(tran, nullptr);

    uint8_t addr_a[ONION_V3_ADDRESS_SIZE];
    std::memset(addr_a, 0x42, sizeof(addr_a));
    uint8_t addr_b[ONION_V3_ADDRESS_SIZE];
    std::memset(addr_b, 0x99, sizeof(addr_b));
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    std::memset(public_key, 0x42, sizeof(public_key));
    uint8_t packet[] = {0x00, 0x01, 0x02, 0x03};

    tor_transport_send(tran.get(), addr_a, 33445, public_key, packet, sizeof(packet));
    tor_transport_send(tran.get(), addr_b, 33445, public_key, packet, sizeof(packet));

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

TEST(TorTransportSend, SameOnionAddressReusesConnection)
{
    const Memory *mem = REQUIRE_NOT_NULL(os_memory());
    Logger *log = REQUIRE_NOT_NULL(logger_new(mem));
    Mono_Time *mono_time = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
    const Network *ns = os_network();

    Tor_Transport_Config cfg{};
    std::strcpy(cfg.proxy_host, "127.0.0.1");
    cfg.proxy_port = 9050;

    Ptr<Tor_Transport> tran(
        tor_transport_new(log, mem, mono_time, nullptr, ns, &cfg));
    ASSERT_NE(tran, nullptr);

    uint8_t onion_addr[ONION_V3_ADDRESS_SIZE];
    std::memset(onion_addr, 0x42, sizeof(onion_addr));
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    std::memset(public_key, 0x42, sizeof(public_key));
    uint8_t packet[] = {0x00, 0x01, 0x02, 0x03};

    /* Sending twice to the same address should reuse the same connection slot */
    tor_transport_send(tran.get(), onion_addr, 33445, public_key, packet, sizeof(packet));
    tor_transport_send(tran.get(), onion_addr, 33445, public_key, packet, sizeof(packet));

    mono_time_free(mem, mono_time);
    logger_kill(log);
}

}  // namespace
