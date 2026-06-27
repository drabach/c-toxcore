#include "DHT.h"
#include "network.h"

#include <gtest/gtest.h>

#include "network_test_util.hh"

namespace {

TEST(TestUtil, ProducesNonNullNetwork)
{
    Test_Network net;
    const Network *ns = net;
    EXPECT_NE(ns, nullptr);
}

TEST(IpNtoa, DoesntWriteOutOfBounds)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.family = net_family_ipv6();
    ip.ip.v6.uint64[0] = -1;
    ip.ip.v6.uint64[1] = -1;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_LT(std::string(ip_str.buf).length(), IP_NTOA_LEN);
}

TEST(IpNtoa, ReportsInvalidIpFamily)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.family.value = 255 - net_family_ipv6().value;
    ip.ip.v4.uint32 = 0;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "(IP invalid, family 245)");
}

TEST(IpNtoa, FormatsIPv4)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.family = net_family_ipv4();
    ip.ip.v4.uint8[0] = 192;
    ip.ip.v4.uint8[1] = 168;
    ip.ip.v4.uint8[2] = 0;
    ip.ip.v4.uint8[3] = 13;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv4)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv4();
    ip.ip.v4.uint8[0] = 192;
    ip.ip.v4.uint8[1] = 168;
    ip.ip.v4.uint8[2] = 0;
    ip.ip.v4.uint8[3] = 13;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv6)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.family = net_family_ipv6();
    ip.ip.v6.uint64[0] = -1;
    ip.ip.v6.uint64[1] = -1;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

TEST(IpportCmp, BehavesLikeMemcmp)
{
    auto cmp_val = [](int val) { return val < 0 ? -1 : val > 0 ? 1 : 0; };

    IP_Port a = {0};
    IP_Port b = {0};

    a.ip.family = net_family_ipv4();
    b.ip.family = net_family_ipv4();

    a.port = 10;
    b.port = 20;

    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)), -1)
        << "a=" << a << "\n"
        << "b=" << b;
    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)),  //
        cmp_val(memcmp(&a, &b, sizeof(IP_Port))))
        << "a=" << a << "\n"
        << "b=" << b;

    a.ip.ip.v4.uint8[0] = 192;
    b.ip.ip.v4.uint8[0] = 10;

    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 1)
        << "a=" << a << "\n"
        << "b=" << b;
    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)),  //
        cmp_val(memcmp(&a, &b, sizeof(IP_Port))))
        << "a=" << a << "\n"
        << "b=" << b;
}

TEST(IpportCmp, Ipv6BeginAndEndCompareCorrectly)
{
    IP_Port a = {0};
    IP_Port b = {0};

    a.ip.family = net_family_ipv6();
    b.ip.family = net_family_ipv6();

    a.ip.ip.v6.uint8[0] = 0xab;
    b.ip.ip.v6.uint8[0] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), -1);

    a.ip.ip.v6.uint8[0] = 0;
    b.ip.ip.v6.uint8[0] = 0;

    a.ip.ip.v6.uint8[15] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 1);
}

TEST(IpportCmp, UnspecAlwaysComparesEqual)
{
    IP_Port a = {0};
    IP_Port b = {0};

    a.ip.family = net_family_unspec();
    b.ip.family = net_family_unspec();

    a.ip.ip.v4.uint8[0] = 0xab;
    b.ip.ip.v4.uint8[0] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 0);
}

TEST(IpportCmp, InvalidAlwaysComparesEqual)
{
    IP_Port a = {0};
    IP_Port b = {0};

    a.ip.family.value = 0xff;
    b.ip.family.value = 0xff;

    a.ip.ip.v4.uint8[0] = 0xab;
    b.ip.ip.v4.uint8[0] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 0);
}

TEST(NetIsOnion, DetectsOnionSuffix)
{
    EXPECT_TRUE(net_is_onion("xyz.onion"));
    EXPECT_TRUE(net_is_onion("3g2upl4pq6kufc4m.onion"));
    EXPECT_TRUE(net_is_onion("a.b.onion"));
}

TEST(NetIsOnion, RejectsNonOnion)
{
    EXPECT_FALSE(net_is_onion("example.com"));
    EXPECT_FALSE(net_is_onion("127.0.0.1"));
    EXPECT_FALSE(net_is_onion("onion"));
    EXPECT_FALSE(net_is_onion("fakeonion.com"));
    EXPECT_FALSE(net_is_onion("x.onion."));
    EXPECT_FALSE(net_is_onion(""));
    EXPECT_FALSE(net_is_onion(nullptr));
}

TEST(NetFamilyOnion, FamilyFunctions)
{
    const Family onion = net_family_onion();
    EXPECT_TRUE(net_family_is_onion(onion));
    EXPECT_FALSE(net_family_is_ipv4(onion));
    EXPECT_FALSE(net_family_is_ipv6(onion));

    const Family ipv4 = net_family_ipv4();
    EXPECT_FALSE(net_family_is_onion(ipv4));

    const Family ipv6 = net_family_ipv6();
    EXPECT_FALSE(net_family_is_onion(ipv6));
}

TEST(NetFamilyOnion, OnionReturnsTrueForOnionFamily)
{
    IP_Port ipp = {{{0}}};
    ipp.ip.family = net_family_onion();
    EXPECT_TRUE(net_family_is_onion(ipp.ip.family));
}

TEST(OnionAddrFromString, Valid56CharRoundTrip)
{
    const char *input = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2m5i5t2zdyumhjlnqadii";
    std::string with_suffix = std::string(input) + ".onion";

    uint8_t addr[ONION_V3_ADDRESS_SIZE];
    ASSERT_TRUE(onion_addr_from_string(input, addr));

    uint8_t addr2[ONION_V3_ADDRESS_SIZE];
    ASSERT_TRUE(onion_addr_from_string(with_suffix.c_str(), addr2));
    EXPECT_EQ(memcmp(addr, addr2, ONION_V3_ADDRESS_SIZE), 0);

    char buf[128];
    const char *result = onion_addr_to_string(addr, buf, sizeof(buf));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(std::string(result), with_suffix);
}

TEST(OnionAddrFromString, RejectsShortInput)
{
    uint8_t addr[ONION_V3_ADDRESS_SIZE];
    EXPECT_FALSE(onion_addr_from_string("tooshort", addr));
}

TEST(OnionAddrFromString, RejectsInvalidBase32)
{
    uint8_t addr[ONION_V3_ADDRESS_SIZE];
    // "!" is not valid base32
    EXPECT_FALSE(onion_addr_from_string(
        "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!", addr));
}

TEST(IpSetOnion, SetsFamilyAndCopiesAddr)
{
    uint8_t addr[ONION_V3_ADDRESS_SIZE];
    memset(addr, 0x42, sizeof(addr));

    IP ip;
    ip_reset(&ip);
    ip_set_onion(&ip, addr);

    EXPECT_TRUE(net_family_is_onion(ip.family));

    uint8_t addr_out[ONION_V3_ADDRESS_SIZE];
    ASSERT_TRUE(ip_get_onion(&ip, addr_out));
    EXPECT_EQ(memcmp(addr, addr_out, ONION_V3_ADDRESS_SIZE), 0);
}

TEST(IpSetOnion, GetReturnsFalseForNonOnion)
{
    uint8_t addr[ONION_V3_ADDRESS_SIZE];
    IP ip;
    ip.family = net_family_ipv4();
    EXPECT_FALSE(ip_get_onion(&ip, addr));
}

TEST(IpEqual, OnionAddressesCompareCorrectly)
{
    uint8_t addr_a[ONION_V3_ADDRESS_SIZE];
    memset(addr_a, 0x42, sizeof(addr_a));
    uint8_t addr_b[ONION_V3_ADDRESS_SIZE];
    memset(addr_b, 0x42, sizeof(addr_b));

    IP ip_a, ip_b;
    ip_reset(&ip_a);
    ip_reset(&ip_b);
    ip_set_onion(&ip_a, addr_a);
    ip_set_onion(&ip_b, addr_b);

    EXPECT_TRUE(ip_equal(&ip_a, &ip_b));

    addr_b[0] = 0x00;
    ip_set_onion(&ip_b, addr_b);
    EXPECT_FALSE(ip_equal(&ip_a, &ip_b));
}

TEST(IpParseAddr, FormatsOnionAddress)
{
    uint8_t addr[ONION_V3_ADDRESS_SIZE];
    const char *input = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2m5i5t2zdyumhjlnqadii";
    ASSERT_TRUE(onion_addr_from_string(input, addr));

    IP ip;
    ip_reset(&ip);
    ip_set_onion(&ip, addr);

    char buf[128];
    ASSERT_TRUE(ip_parse_addr(&ip, buf, sizeof(buf)));
    EXPECT_EQ(std::string(buf), std::string(input) + ".onion");
}

TEST(IpCmp, OnionAddressesCompareCorrectly)
{
    auto cmp_val = [](int val) { return val < 0 ? -1 : val > 0 ? 1 : 0; };

    uint8_t addr_a[ONION_V3_ADDRESS_SIZE];
    memset(addr_a, 0x42, sizeof(addr_a));
    uint8_t addr_b[ONION_V3_ADDRESS_SIZE];
    memset(addr_b, 0x42, sizeof(addr_b));

    IP_Port ipp_a = {{{0}}};
    IP_Port ipp_b = {{{0}}};
    ip_set_onion(&ipp_a.ip, addr_a);
    ip_set_onion(&ipp_b.ip, addr_b);
    ipp_a.port = 12345;
    ipp_b.port = 12345;

    EXPECT_EQ(ipport_cmp_handler(&ipp_a, &ipp_b, sizeof(IP_Port)), 0);
    EXPECT_EQ(
        ipport_cmp_handler(&ipp_a, &ipp_b, sizeof(IP_Port)),
        cmp_val(memcmp(&ipp_a, &ipp_b, sizeof(IP_Port))));

    addr_b[0] = 0x00;
    ip_set_onion(&ipp_b.ip, addr_b);
    EXPECT_NE(ipport_cmp_handler(&ipp_a, &ipp_b, sizeof(IP_Port)), 0);
}

TEST(PackedNodeSize, OnionReturnsCorrectSize)
{
    EXPECT_EQ(packed_node_size(net_family_onion()), PACKED_NODE_SIZE_ONION);
}

TEST(PackUnpackIpPort, OnionRoundTrip)
{
    IP_Port orig = {{{0}}};
    orig.ip.family = net_family_onion();
    memset(orig.ip.ip.onion, 0x42, ONION_V3_ADDRESS_SIZE);
    orig.port = net_htons(12345);

    uint8_t buf[64];
    const int packed = pack_ip_port(nullptr, buf, sizeof(buf), &orig);
    ASSERT_GT(packed, 0);
    EXPECT_EQ(packed, 1 + SIZE_ONION + 2);

    IP_Port unpacked = {{{0}}};
    const int unpked = unpack_ip_port(&unpacked, buf, sizeof(buf), false);
    ASSERT_EQ(unpked, packed);

    EXPECT_EQ(unpacked.ip.family.value, TOX_AF_ONION);
    EXPECT_EQ(memcmp(unpacked.ip.ip.onion, orig.ip.ip.onion, ONION_V3_ADDRESS_SIZE), 0);
    EXPECT_EQ(unpacked.port, orig.port);
}

TEST(PackUnpackIpPort, OnionTcpDisabledStillWorks)
{
    IP_Port orig = {{{0}}};
    orig.ip.family = net_family_onion();
    memset(orig.ip.ip.onion, 0x42, ONION_V3_ADDRESS_SIZE);
    orig.port = net_htons(9999);

    uint8_t buf[64];
    const int packed = pack_ip_port(nullptr, buf, sizeof(buf), &orig);
    ASSERT_GT(packed, 0);

    IP_Port unpacked = {{{0}}};
    const int unpked = unpack_ip_port(&unpacked, buf, sizeof(buf), true);
    ASSERT_EQ(unpked, packed);
    EXPECT_EQ(unpacked.ip.family.value, TOX_AF_ONION);
}

TEST(PackUnpackIpPort, OnionBufferTooSmall)
{
    IP_Port orig = {{{0}}};
    orig.ip.family = net_family_onion();
    memset(orig.ip.ip.onion, 0x42, ONION_V3_ADDRESS_SIZE);
    orig.port = net_htons(12345);

    uint8_t buf[4];  // too small for onion
    const int packed = pack_ip_port(nullptr, buf, sizeof(buf), &orig);
    EXPECT_EQ(packed, -1);
}

TEST(PackUnpackIpPort, OnionRejectsNonOnionData)
{
    uint8_t buf[] = {TOX_AF_ONION, 0x01, 0x02};  // truncated
    IP_Port unpacked = {{{0}}};
    const int unpked = unpack_ip_port(&unpacked, buf, sizeof(buf), false);
    EXPECT_EQ(unpked, -1);
}

}  // namespace
