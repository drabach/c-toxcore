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

}  // namespace
