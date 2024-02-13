/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ip.h"
#include <arpa/inet.h>
#include <dpack/codec.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>

#define INCFGUT_NOASSERT_TEST(_name) \
	CUTE_TEST(_name) \
	{ \
		cute_skip("assertion support disabled"); \
	}

#define INCFGUT_NOIPV4_TEST(_name) \
	CUTE_TEST(_name) \
	{ \
		cute_skip("IPv4 support disabled"); \
	}

#define INCFGUT_NOIPV6_TEST(_name) \
	CUTE_TEST(_name) \
	{ \
		cute_skip("IPv6 support disabled"); \
	}

static void
incfgut_ip_addr_test_check_str_ok(const char * addr)
{
	cute_check_sint(incfg_ip_addr_check_str(addr), equal, 0);
}

static void
incfgut_ip_addr_test_check_str_nok(const char * addr)
{
	cute_check_sint(incfg_ip_addr_check_str(addr), equal, -EINVAL);
}

static void
incfgut_ip_addr_test_check_nstr_ok(const char * addr, size_t len)
{
	cute_check_sint(incfg_ip_addr_check_nstr(addr, len), equal, 0);
}

static void
incfgut_ip_addr_test_check_nstr_nok(const char * addr, size_t len)
{
	cute_check_sint(incfg_ip_addr_check_nstr(addr, len), equal, -EINVAL);
}

#if defined(CONFIG_INCFG_IPV4)

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ip_addr_set_saddr4_assert)
{
	cute_expect_assertion(incfg_ip_addr_set_saddr4(NULL, INADDR_ANY));
}

CUTE_TEST(incfgut_ip_addr_set_inet4_assert)
{
	union incfg_ip_addr  addr;
	const struct in_addr inet;

	incfg_ip_addr_init(&addr);

	cute_expect_assertion(incfg_ip_addr_set_inet4(NULL, &inet));
	cute_expect_assertion(incfg_ip_addr_set_inet4(&addr, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_ip_addr_set_saddr4_assert);
INCFGUT_NOASSERT_TEST(incfgut_ip_addr_set_inet4_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ip_addr_test_set_saddr4(in_addr_t addr)
{
	union incfg_ip_addr  val;
	const struct in_addr ref = { .s_addr = htonl(addr) };

	incfg_ip_addr_init(&val);
	incfg_ip_addr_set_saddr4(&val, addr);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_ip_addr_get_inet4(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_ip_addr_fini(&val);
}

CUTE_TEST(incfgut_ip_addr_set_saddr4)
{
	incfgut_ip_addr_test_set_saddr4(INADDR_ANY);
	incfgut_ip_addr_test_set_saddr4(INADDR_BROADCAST);
	incfgut_ip_addr_test_set_saddr4(INADDR_LOOPBACK);
	incfgut_ip_addr_test_set_saddr4(INADDR_ALLSNOOPERS_GROUP);
}

static void
incfgut_ip_addr_test_set_inet4(in_addr_t addr)
{
	union incfg_ip_addr  val;
	const struct in_addr ref = { .s_addr = htonl(addr) };

	incfg_ip_addr_init(&val);
	incfg_ip_addr_set_inet4(&val, &ref);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_ip_addr_get_inet4(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_ip_addr_fini(&val);
}

CUTE_TEST(incfgut_ip_addr_set_inet4)
{
	incfgut_ip_addr_test_set_inet4(INADDR_ANY);
	incfgut_ip_addr_test_set_inet4(INADDR_BROADCAST);
	incfgut_ip_addr_test_set_inet4(INADDR_LOOPBACK);
	incfgut_ip_addr_test_set_inet4(INADDR_ALLSNOOPERS_GROUP);
}

static void
incfgut_ip_addr_test_get_str4(in_addr_t saddr)
{
	union incfg_ip_addr         addr;
	char                        ref[INET_ADDRSTRLEN];
	const struct stroll_lvstr * str;

	incfg_ip_addr_init(&addr);
	incfg_ip_addr_set_saddr4(&addr, saddr);

	cute_check_ptr(inet_ntop(AF_INET,
	                         incfg_ip_addr_get_inet4(&addr),
	                         ref,
	                         sizeof(ref)),
	               equal,
	               ref);

	str = incfg_ip_addr_get_str(&addr);
	cute_check_str(stroll_lvstr_cstr(str), equal, ref);

	incfg_ip_addr_fini(&addr);
}

CUTE_TEST(incfgut_ip_addr_get_str4)
{
	incfgut_ip_addr_test_get_str4(INADDR_ANY);
	incfgut_ip_addr_test_get_str4(INADDR_BROADCAST);
	incfgut_ip_addr_test_get_str4(INADDR_LOOPBACK);
	incfgut_ip_addr_test_get_str4(INADDR_ALLSNOOPERS_GROUP);
}

CUTE_TEST(incfgut_ip_addr_check_str4_ok)
{
	incfgut_ip_addr_test_check_str_ok("0.0.0.0");
	incfgut_ip_addr_test_check_str_ok("255.255.255.255");
	incfgut_ip_addr_test_check_str_ok("127.0.0.1");
	incfgut_ip_addr_test_check_str_ok("224.0.0.106");
}

CUTE_TEST(incfgut_ip_addr_check_str4_nok)
{
	incfgut_ip_addr_test_check_str_nok("0.0.0.0.");
	incfgut_ip_addr_test_check_str_nok("0.0.0.");
	incfgut_ip_addr_test_check_str_nok("256.0.0.1");
	incfgut_ip_addr_test_check_str_nok("254.300.0.1");
	incfgut_ip_addr_test_check_str_nok("254.254.260.1");
	incfgut_ip_addr_test_check_str_nok("fail");
	incfgut_ip_addr_test_check_str_nok("");
}

CUTE_TEST(incfgut_ip_addr_check_nstr4_ok)
{
	incfgut_ip_addr_test_check_nstr_ok("0.0.0.0", 7);
	incfgut_ip_addr_test_check_nstr_ok("255.255.255.255", 15);
	incfgut_ip_addr_test_check_nstr_ok("127.0.0.1", 9);
	incfgut_ip_addr_test_check_nstr_ok("224.0.0.106", 11);

	incfgut_ip_addr_test_check_nstr_ok("0.0.0.0xxxx", 7);
	incfgut_ip_addr_test_check_nstr_ok("255.255.255.255xxxx", 15);
	incfgut_ip_addr_test_check_nstr_ok("127.0.0.1xxxx", 9);
	incfgut_ip_addr_test_check_nstr_ok("224.0.0.106xxxx", 11);
}

CUTE_TEST(incfgut_ip_addr_check_nstr4_nok)
{
	incfgut_ip_addr_test_check_nstr_nok("0.0.0.0.", 8);
	incfgut_ip_addr_test_check_nstr_nok("0.0.0.", 6);
	incfgut_ip_addr_test_check_nstr_nok("256.0.0.1", 9);
	incfgut_ip_addr_test_check_nstr_nok("254.300.0.1", 11);
	incfgut_ip_addr_test_check_nstr_nok("254.254.260.1", 13);
	incfgut_ip_addr_test_check_nstr_nok("fail", 4);
	incfgut_ip_addr_test_check_nstr_nok("", 0);
}

#else  /* !defined(CONFIG_INCFG_IPV4) */

INCFGUT_NOIPV4_TEST(incfgut_ip_addr_set_saddr4_assert);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_set_saddr4);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_set_inet4_assert);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_set_inet4);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_get_str4);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_check_str4_ok);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_check_str4_nok);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_check_nstr4_ok);
INCFGUT_NOIPV4_TEST(incfgut_ip_addr_check_nstr4_nok);

#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ip_addr_set_inet6_assert)
{
	union incfg_ip_addr   addr;
	const struct in6_addr inet;

	incfg_ip_addr_init(&addr);

	cute_expect_assertion(incfg_ip_addr_set_inet6(NULL, &inet));
	cute_expect_assertion(incfg_ip_addr_set_inet6(&addr, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_ip_addr_set_inet6_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ip_addr_test_set_inet6(const struct in6_addr * addr)
{
	union incfg_ip_addr   val;
	const struct in6_addr ref = *addr;

	incfg_ip_addr_init(&val);
	incfg_ip_addr_set_inet6(&val, &ref);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV6_TYPE);
	cute_check_mem(incfg_ip_addr_get_inet6(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_ip_addr_fini(&val);
}

CUTE_TEST(incfgut_ip_addr_set_inet6)
{
	incfgut_ip_addr_test_set_inet6(&in6addr_any);
	incfgut_ip_addr_test_set_inet6(&in6addr_loopback);
	incfgut_ip_addr_test_set_inet6(&in6addr_linklocal_allnodes);
	incfgut_ip_addr_test_set_inet6(&in6addr_linklocal_allrouters);
	incfgut_ip_addr_test_set_inet6(&in6addr_sitelocal_allrouters);
}

static void
incfgut_ip_addr_test_get_str6(const struct in6_addr * addr)
{
	union incfg_ip_addr         val;
	char                        ref[INET6_ADDRSTRLEN];
	const struct stroll_lvstr * str;

	incfg_ip_addr_init(&val);
	incfg_ip_addr_set_inet6(&val, addr);

	cute_check_ptr(inet_ntop(AF_INET6, addr, ref, sizeof(ref)),
	               equal,
	               ref);

	str = incfg_ip_addr_get_str(&val);
	cute_check_str(stroll_lvstr_cstr(str), equal, ref);

	incfg_ip_addr_fini(&val);
}

CUTE_TEST(incfgut_ip_addr_get_str6)
{
	incfgut_ip_addr_test_get_str6(&in6addr_any);
	incfgut_ip_addr_test_get_str6(&in6addr_loopback);
	incfgut_ip_addr_test_get_str6(&in6addr_linklocal_allnodes);
	incfgut_ip_addr_test_get_str6(&in6addr_linklocal_allrouters);
	incfgut_ip_addr_test_get_str6(&in6addr_sitelocal_allrouters);
}

CUTE_TEST(incfgut_ip_addr_check_str6_ok)
{
	incfgut_ip_addr_test_check_str_ok("::");
	incfgut_ip_addr_test_check_str_ok("::1");
	incfgut_ip_addr_test_check_str_ok("ff02::1");
	incfgut_ip_addr_test_check_str_ok("ff05::2");
	incfgut_ip_addr_test_check_str_ok("2002:c000:0204::");
	incfgut_ip_addr_test_check_str_ok("::ffff:192.0.2.4");
}

CUTE_TEST(incfgut_ip_addr_check_str6_nok)
{
	incfgut_ip_addr_test_check_str_nok(":");
	incfgut_ip_addr_test_check_str_nok(":::");
	incfgut_ip_addr_test_check_str_nok("ff02:::");
	incfgut_ip_addr_test_check_str_nok("fffff::2");
	incfgut_ip_addr_test_check_str_nok("f:f:f:f:f:f:f:f:f");
	incfgut_ip_addr_test_check_str_nok("f:");
	incfgut_ip_addr_test_check_str_nok(":f");
	incfgut_ip_addr_test_check_str_nok("fail");
	incfgut_ip_addr_test_check_str_nok("");
}

CUTE_TEST(incfgut_ip_addr_check_nstr6_ok)
{
	incfgut_ip_addr_test_check_nstr_ok("::", 2);
	incfgut_ip_addr_test_check_nstr_ok("::1", 3);
	incfgut_ip_addr_test_check_nstr_ok("ff02::1", 7);
	incfgut_ip_addr_test_check_nstr_ok("ff05::2", 7);
	incfgut_ip_addr_test_check_nstr_ok("2002:c000:0204::", 16);
	incfgut_ip_addr_test_check_nstr_ok("::ffff:192.0.2.4", 16);

	incfgut_ip_addr_test_check_nstr_ok("::xxxx", 2);
	incfgut_ip_addr_test_check_nstr_ok("::1xxxx", 3);
	incfgut_ip_addr_test_check_nstr_ok("ff02::1xxxx", 7);
	incfgut_ip_addr_test_check_nstr_ok("ff05::2xxxx", 7);
	incfgut_ip_addr_test_check_nstr_ok("2002:c000:0204::xxxx", 16);
	incfgut_ip_addr_test_check_nstr_ok("::ffff:192.0.2.4xxxx", 16);
}

CUTE_TEST(incfgut_ip_addr_check_nstr6_nok)
{
	incfgut_ip_addr_test_check_nstr_nok(":", 1);
	incfgut_ip_addr_test_check_nstr_nok(":::", 3);
	incfgut_ip_addr_test_check_nstr_nok("ff02:::", 7);
	incfgut_ip_addr_test_check_nstr_nok("fffff::2", 8);
	incfgut_ip_addr_test_check_nstr_nok("f:f:f:f:f:f:f:f:f", 17);
	incfgut_ip_addr_test_check_nstr_nok("f:", 2);
	incfgut_ip_addr_test_check_nstr_nok(":f", 2);
	incfgut_ip_addr_test_check_nstr_nok("fail", 4);
	incfgut_ip_addr_test_check_nstr_nok("", 0);
}

#else  /* !defined(CONFIG_INCFG_IPV6) */

INCFGUT_NOIPV6_TEST(incfgut_ip_addr_set_inet6_assert);
INCFGUT_NOIPV6_TEST(incfgut_ip_addr_set_inet6);
INCFGUT_NOIPV6_TEST(incfgut_ip_addr_get_str6);
INCFGUT_NOIPV6_TEST(incfgut_ip_addr_check_str6_ok);
INCFGUT_NOIPV6_TEST(incfgut_ip_addr_check_str6_nok);
INCFGUT_NOIPV6_TEST(incfgut_ip_addr_check_nstr6_ok);
INCFGUT_NOIPV6_TEST(incfgut_ip_addr_check_nstr6_nok);

#endif /* defined(CONFIG_INCFG_IPV6) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ip_addr_get_str_assert)
{
	cute_expect_assertion(incfg_ip_addr_get_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_ip_addr_get_str_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ip_addr_check_str_assert)
{
	cute_expect_assertion(incfg_ip_addr_check_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_ip_addr_check_str_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ip_addr_check_nstr_assert)
{
	cute_expect_assertion(incfg_ip_addr_check_nstr(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_ip_addr_check_nstr_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_GROUP(incfgut_ip_group) = {
	CUTE_REF(incfgut_ip_addr_set_saddr4_assert),
	CUTE_REF(incfgut_ip_addr_set_saddr4),
	CUTE_REF(incfgut_ip_addr_set_inet4_assert),
	CUTE_REF(incfgut_ip_addr_set_inet4),

	CUTE_REF(incfgut_ip_addr_set_inet6_assert),
	CUTE_REF(incfgut_ip_addr_set_inet6),

	CUTE_REF(incfgut_ip_addr_get_str_assert),
	CUTE_REF(incfgut_ip_addr_get_str4),
	CUTE_REF(incfgut_ip_addr_get_str6),

	CUTE_REF(incfgut_ip_addr_check_str_assert),
	CUTE_REF(incfgut_ip_addr_check_str4_ok),
	CUTE_REF(incfgut_ip_addr_check_str4_nok),
	CUTE_REF(incfgut_ip_addr_check_str6_ok),
	CUTE_REF(incfgut_ip_addr_check_str6_nok),

	CUTE_REF(incfgut_ip_addr_check_nstr_assert),
	CUTE_REF(incfgut_ip_addr_check_nstr4_ok),
	CUTE_REF(incfgut_ip_addr_check_nstr4_nok),
	CUTE_REF(incfgut_ip_addr_check_nstr6_ok),
	CUTE_REF(incfgut_ip_addr_check_nstr6_nok),
};

CUTE_SUITE_EXTERN(incfgut_ip_suite,
                  incfgut_ip_group,
                  incfgut_setup,
                  incfgut_teardown,
                  CUTE_DFLT_TMOUT);
