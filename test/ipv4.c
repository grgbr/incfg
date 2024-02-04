/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ipv4.h"
#include <dpack/codec.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <errno.h>

#define INCFGUT_SADDR(...) \
	((const uint8_t []) { __VA_ARGS__ })

static void * incfgut_ipv4_tofree = NULL;

static void
incfgut_ipv4_teardown(void)
{
	free(incfgut_ipv4_tofree);
	incfgut_ipv4_tofree = NULL;
	incfgut_teardown();
}

static void
incfgut_ipv4_addr_check_init(const union incfg_ipv4_addr * any,
                             const union incfg_ipv4_addr * bcast,
                             const union incfg_ipv4_addr * loop,
                             const union incfg_ipv4_addr * mcast)
{
	cute_check_mem(&any->inet.s_addr,
	               equal,
	               INCFGUT_SADDR(0, 0, 0, 0), 4);
	cute_check_mem(&bcast->inet.s_addr,
	               equal,
	               INCFGUT_SADDR(255, 255, 255, 255), 4);
	cute_check_mem(&loop->inet.s_addr,
	               equal,
	               INCFGUT_SADDR(127, 0, 0, 1), 4);
	cute_check_mem(&mcast->inet.s_addr,
	               equal,
	               INCFGUT_SADDR(224, 0, 0, 106), 4);
}

CUTE_TEST(incfgut_ipv4_addr_init_saddr)
{
	const union incfg_ipv4_addr addr0 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_ANY);
	const union incfg_ipv4_addr addr1 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_BROADCAST);
	const union incfg_ipv4_addr addr2 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_LOOPBACK);
	const union incfg_ipv4_addr addr3 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_ALLSNOOPERS_GROUP);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_setup_saddr_assert)
{
	cute_expect_assertion(incfg_ipv4_addr_setup_saddr(NULL, INADDR_ANY));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_saddr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_saddr)
{
	union incfg_ipv4_addr addr0, addr1, addr2, addr3;

	incfg_ipv4_addr_setup_saddr(&addr0, INADDR_ANY);
	incfg_ipv4_addr_setup_saddr(&addr1, INADDR_BROADCAST);
	incfg_ipv4_addr_setup_saddr(&addr2, INADDR_LOOPBACK);
	incfg_ipv4_addr_setup_saddr(&addr3, INADDR_ALLSNOOPERS_GROUP);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);
}

static void
incfgut_ipv4_addr_check_create_saddr(in_addr_t addr, const uint8_t ref[4])
{
	union incfg_ipv4_addr * incfg;

	incfgut_ipv4_tofree = incfg_ipv4_addr_create_saddr(addr);
	incfg = incfgut_ipv4_tofree;

	cute_check_ptr(incfg, unequal, NULL);
	cute_check_mem(&incfg->inet.s_addr, equal, ref, 4);

	incfg_ipv4_addr_destroy(incfg);
	incfgut_ipv4_tofree = NULL;
}

CUTE_TEST(incfgut_ipv4_addr_create_saddr)
{
	incfgut_ipv4_addr_check_create_saddr(INADDR_ANY,
	                                     INCFGUT_SADDR(0, 0, 0, 0));
	incfgut_ipv4_addr_check_create_saddr(INADDR_BROADCAST,
	                                     INCFGUT_SADDR(255, 255, 255, 255));
	incfgut_ipv4_addr_check_create_saddr(INADDR_LOOPBACK,
	                                     INCFGUT_SADDR(127, 0, 0, 1));
	incfgut_ipv4_addr_check_create_saddr(INADDR_ALLSNOOPERS_GROUP,
	                                     INCFGUT_SADDR(224, 0, 0, 106));

	if (!incfgut_expect_malloc()) {
		cute_check_ptr(incfg_ipv4_addr_create_saddr(INADDR_ANY),
		               equal,
		               NULL);
		cute_check_sint(errno, equal, ENOMEM);
	}
}

CUTE_TEST(incfgut_ipv4_addr_init_inet)
{
	const struct in_addr        inaddr0 = {
		.s_addr = htonl(INADDR_ANY)
	};
	const union incfg_ipv4_addr addr0 = INCFG_IPV4_ADDR_INIT_INET(inaddr0);

	const struct in_addr        inaddr1 = {
		.s_addr = htonl(INADDR_BROADCAST)
	};
	const union incfg_ipv4_addr addr1 = INCFG_IPV4_ADDR_INIT_INET(inaddr1);

	const struct in_addr        inaddr2 = {
		.s_addr = htonl(INADDR_LOOPBACK)
	};
	const union incfg_ipv4_addr addr2 = INCFG_IPV4_ADDR_INIT_INET(inaddr2);

	const struct in_addr        inaddr3 = {
		.s_addr = htonl(INADDR_ALLSNOOPERS_GROUP)
	};
	const union incfg_ipv4_addr addr3 = INCFG_IPV4_ADDR_INIT_INET(inaddr3);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_setup_inet_assert)
{
	const struct in_addr  inaddr0 = { .s_addr = htonl(INADDR_ANY) };
	union incfg_ipv4_addr addr0;

	cute_expect_assertion(incfg_ipv4_addr_setup_inet(NULL, &inaddr0));
	cute_expect_assertion(incfg_ipv4_addr_setup_inet(&addr0, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_inet_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_inet)
{
	const struct in_addr  inaddr0 = {
		.s_addr = htonl(INADDR_ANY)
	};
	union incfg_ipv4_addr addr0;

	const struct in_addr  inaddr1 = {
		.s_addr = htonl(INADDR_BROADCAST)
	};
	union incfg_ipv4_addr addr1;

	const struct in_addr  inaddr2 = {
		.s_addr = htonl(INADDR_LOOPBACK)
	};
	union incfg_ipv4_addr addr2;

	const struct in_addr  inaddr3 = {
		.s_addr = htonl(INADDR_ALLSNOOPERS_GROUP)
	};
	union incfg_ipv4_addr addr3;

	incfg_ipv4_addr_setup_inet(&addr0, &inaddr0);
	incfg_ipv4_addr_setup_inet(&addr1, &inaddr1);
	incfg_ipv4_addr_setup_inet(&addr2, &inaddr2);
	incfg_ipv4_addr_setup_inet(&addr3, &inaddr3);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_create_inet_assert)
{
	cute_expect_assertion(
		incfgut_ipv4_tofree = incfg_ipv4_addr_create_inet(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_create_inet_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_check_create_inet(in_addr_t addr, const uint8_t ref[4])
{
	const struct in_addr    inaddr = { .s_addr = htonl(addr) };
	union incfg_ipv4_addr * incfg;

	incfgut_ipv4_tofree = incfg_ipv4_addr_create_inet(&inaddr);
	incfg = incfgut_ipv4_tofree;

	cute_check_ptr(incfg, unequal, NULL);
	cute_check_mem(&incfg->inet.s_addr, equal, ref, 4);

	incfg_ipv4_addr_destroy(incfg);
	incfgut_ipv4_tofree = NULL;
}

CUTE_TEST(incfgut_ipv4_addr_create_inet)
{
	incfgut_ipv4_addr_check_create_inet(INADDR_ANY,
	                                    INCFGUT_SADDR(0, 0, 0, 0));
	incfgut_ipv4_addr_check_create_inet(INADDR_BROADCAST,
	                                    INCFGUT_SADDR(255, 255, 255, 255));
	incfgut_ipv4_addr_check_create_inet(INADDR_LOOPBACK,
	                                    INCFGUT_SADDR(127, 0, 0, 1));
	incfgut_ipv4_addr_check_create_inet(INADDR_ALLSNOOPERS_GROUP,
	                                    INCFGUT_SADDR(224, 0, 0, 106));

	if (!incfgut_expect_malloc()) {
		const struct in_addr inaddr = { .s_addr = htonl(INADDR_ANY) };

		cute_check_ptr(incfg_ipv4_addr_create_inet(&inaddr),
		               equal,
		               NULL);
		cute_check_sint(errno, equal, ENOMEM);
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_setup_str_assert)
{
	union incfg_ipv4_addr addr;
	const char            str[INCFG_IPV4_ADDR_STRSZ_MAX];

	cute_expect_assertion(incfg_ipv4_addr_setup_str(NULL, str));
	cute_expect_assertion(incfg_ipv4_addr_setup_str(&addr, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_str)
{
	union incfg_ipv4_addr addr0, addr1, addr2, addr3;

	cute_check_sint(incfg_ipv4_addr_setup_str(&addr0, "0.0.0.0"),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_setup_str(&addr1, "255.255.255.255"),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_setup_str(&addr2, "127.0.0.1"),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_setup_str(&addr3, "224.0.0.106"),
	                equal,
	                0);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);

	cute_check_sint(
		incfg_ipv4_addr_setup_str(&addr0,
		                          "This is not an IPv4 address !"),
		equal,
		-EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_setup_nstr_assert)
{
	union incfg_ipv4_addr addr;
	const char            str[INCFG_IPV4_ADDR_STRSZ_MAX];

	cute_expect_assertion(incfg_ipv4_addr_setup_nstr(NULL, str, 1));
	cute_expect_assertion(incfg_ipv4_addr_setup_nstr(&addr, NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_setup_nstr)
{
	union incfg_ipv4_addr addr0, addr1, addr2, addr3;

	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr0, "0.0.0.0abcd", 7),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr1,
	                                           "255.255.255.255abcd",
	                                           15),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr2, "127.0.0.1abcd", 9),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr3,
	                                           "224.0.0.106abcd",
	                                           11),
	                equal,
	                0);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);

	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr0,
	                                           "255.255.255.255abcd",
	                                           0),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr0,
	                                           "255.255.255.255abcd",
	                                           16),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_setup_nstr(&addr0,
	                                           "255.255.255.255",
	                                           4),
	                equal,
	                -EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_create_str_assert)
{
	cute_expect_assertion(
		incfgut_ipv4_tofree = incfg_ipv4_addr_create_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_create_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_check_create_str_ok(const char *  string,
                                      const uint8_t ref[4])
{
	union incfg_ipv4_addr * addr;

	incfgut_ipv4_tofree = incfg_ipv4_addr_create_str(string);
	addr = incfgut_ipv4_tofree;

	cute_check_ptr(addr, unequal, NULL);
	cute_check_mem(&addr->inet.s_addr, equal, ref, 4);

	incfg_ipv4_addr_destroy(addr);
	incfgut_ipv4_tofree = NULL;
}

static void
incfgut_ipv4_addr_check_create_str_nok(const char *  string, int error)
{
	union incfg_ipv4_addr * addr;

	incfgut_ipv4_tofree = incfg_ipv4_addr_create_str(string);
	addr = incfgut_ipv4_tofree;

	cute_check_ptr(addr, equal, NULL);
	cute_check_sint(errno, equal, error);

	incfg_ipv4_addr_destroy(addr);
	incfgut_ipv4_tofree = NULL;
}

CUTE_TEST(incfgut_ipv4_addr_create_str)
{
	incfgut_ipv4_addr_check_create_str_ok("0.0.0.0",
	                                      INCFGUT_SADDR(0, 0, 0, 0));
	incfgut_ipv4_addr_check_create_str_ok(
		"255.255.255.255",
		INCFGUT_SADDR(255, 255, 255, 255));
	incfgut_ipv4_addr_check_create_str_ok("127.0.0.1",
	                                      INCFGUT_SADDR(127, 0, 0, 1));
	incfgut_ipv4_addr_check_create_str_ok("224.0.0.106",
	                                      INCFGUT_SADDR(224, 0, 0, 106));

	incfgut_ipv4_addr_check_create_str_nok("256.0.0.1", EINVAL);
	incfgut_ipv4_addr_check_create_str_nok("1.300.0.1", EINVAL);
	incfgut_ipv4_addr_check_create_str_nok("1.0.925.1", EINVAL);
	incfgut_ipv4_addr_check_create_str_nok("1.0.0.925", EINVAL);
	incfgut_ipv4_addr_check_create_str_nok("This is not an IPv4 address !",
	                                       EINVAL);

	if (!incfgut_expect_malloc()) {
		cute_check_ptr(incfg_ipv4_addr_create_str("0.0.0.0"),
		               equal,
		               NULL);
		cute_check_sint(errno, equal, ENOMEM);
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_create_nstr_assert)
{
	cute_expect_assertion(
		incfgut_ipv4_tofree = incfg_ipv4_addr_create_nstr(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_create_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_check_create_nstr_ok(const char *  string,
                                       size_t        length,
                                       const uint8_t ref[4])
{
	union incfg_ipv4_addr * addr;

	incfgut_ipv4_tofree = incfg_ipv4_addr_create_nstr(string, length);
	addr = incfgut_ipv4_tofree;

	cute_check_ptr(addr, unequal, NULL);
	cute_check_mem(&addr->inet.s_addr, equal, ref, 4);

	incfg_ipv4_addr_destroy(addr);
	incfgut_ipv4_tofree = NULL;
}

static void
incfgut_ipv4_addr_check_create_nstr_nok(const char *  string,
                                        size_t        length,
                                        int           error)
{
	union incfg_ipv4_addr * addr;

	incfgut_ipv4_tofree = incfg_ipv4_addr_create_nstr(string, length);
	addr = incfgut_ipv4_tofree;

	cute_check_ptr(addr, equal, NULL);
	cute_check_sint(errno, equal, error);

	incfg_ipv4_addr_destroy(addr);
	incfgut_ipv4_tofree = NULL;
}

CUTE_TEST(incfgut_ipv4_addr_create_nstr)
{
	incfgut_ipv4_addr_check_create_nstr_ok("0.0.0.0",
	                                       7,
	                                       INCFGUT_SADDR(0, 0, 0, 0));
	incfgut_ipv4_addr_check_create_nstr_ok(
		"255.255.255.255",
		15,
		INCFGUT_SADDR(255, 255, 255, 255));
	incfgut_ipv4_addr_check_create_nstr_ok("127.0.0.1",
	                                       9,
	                                       INCFGUT_SADDR(127, 0, 0, 1));
	incfgut_ipv4_addr_check_create_nstr_ok("224.0.0.106",
	                                       11,
	                                       INCFGUT_SADDR(224, 0, 0, 106));

	incfgut_ipv4_addr_check_create_nstr_nok("This is not an IPv4 address !",
	                                        0,
	                                        EINVAL);
	incfgut_ipv4_addr_check_create_nstr_nok("This is not an IPv4 address !",
	                                        29,
	                                        EINVAL);
	incfgut_ipv4_addr_check_create_nstr_nok("255.255.255.255",
	                                        4,
	                                        EINVAL);
	incfgut_ipv4_addr_check_create_nstr_nok("256.0.0.1", 9, EINVAL);
	incfgut_ipv4_addr_check_create_nstr_nok("1.300.0.1", 9, EINVAL);
	incfgut_ipv4_addr_check_create_nstr_nok("1.0.925.1", 9, EINVAL);
	incfgut_ipv4_addr_check_create_nstr_nok("1.0.0.925", 9, EINVAL);

	if (!incfgut_expect_malloc()) {
		cute_check_ptr(incfg_ipv4_addr_create_nstr("0.0.0.0", 7),
		               equal,
		               NULL);
		cute_check_sint(errno, equal, ENOMEM);
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_str_assert)
{
	const union incfg_ipv4_addr addr;
	char                        str[INCFG_IPV4_ADDR_STRSZ_MAX];

	cute_expect_assertion(incfg_ipv4_addr_str(&addr, NULL));
	cute_expect_assertion(incfg_ipv4_addr_str(NULL, str));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_str)
{
	const union incfg_ipv4_addr addr0 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_ANY);
	const union incfg_ipv4_addr addr1 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_BROADCAST);
	const union incfg_ipv4_addr addr2 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_LOOPBACK);
	const union incfg_ipv4_addr addr3 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_ALLSNOOPERS_GROUP);
	char                        str[INCFG_IPV4_ADDR_STRSZ_MAX];

	cute_check_ptr(incfg_ipv4_addr_str(&addr0, str), equal, str);
	cute_check_str(str, equal, "0.0.0.0");

	cute_check_ptr(incfg_ipv4_addr_str(&addr1, str), equal, str);
	cute_check_str(str, equal, "255.255.255.255");

	cute_check_ptr(incfg_ipv4_addr_str(&addr2, str), equal, str);
	cute_check_str(str, equal, "127.0.0.1");

	cute_check_ptr(incfg_ipv4_addr_str(&addr3, str), equal, str);
	cute_check_str(str, equal, "224.0.0.106");
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_check_str_assert)
{
	cute_expect_assertion(incfg_ipv4_addr_check_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_check_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_check_str)
{
	cute_check_sint(incfg_ipv4_addr_check_str("0.0.0.0"), equal, 0);
	cute_check_sint(incfg_ipv4_addr_check_str("255.255.255.255"), equal, 0);
	cute_check_sint(incfg_ipv4_addr_check_str("127.0.0.1"), equal, 0);
	cute_check_sint(incfg_ipv4_addr_check_str("224.0.0.106"), equal, 0);
	cute_check_sint(incfg_ipv4_addr_check_str(""), equal, -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("fail"), equal, -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.16."),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.16.fail"),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.16.9.10."),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("1000.192.16.9"),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.1000.16.9"),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.16.1000.9"),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.16.9.1000"),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("192.16.9.1\n"),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("256.0.0.1"), equal, -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("1.300.0.1"), equal, -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("1.0.925.1"), equal, -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_str("1.0.0.925"), equal, -EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_check_nstr_assert)
{
	cute_expect_assertion(incfg_ipv4_addr_check_nstr(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_check_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_check_nstr)
{
	cute_check_sint(incfg_ipv4_addr_check_nstr("0.0.0.0", 7),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_check_nstr("255.255.255.255", 15),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_check_nstr("127.0.0.1", 9),
	                equal,
	                0);
	cute_check_sint(incfg_ipv4_addr_check_nstr("224.0.0.106", 11),
	                equal,
	                0);

	cute_check_sint(incfg_ipv4_addr_check_nstr("", 0),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("fail", 4),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.16.", 7),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.16.fail", 11),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.16.9.10.", 12),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("1000.192.16.9", 13),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.1000.16.9", 13),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.16.1000.9", 13),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.16.9.1000", 13),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("192.16.9.1\n", 11),
	                equal,
	                -EINVAL);
	cute_check_sint(
		incfg_ipv4_addr_check_nstr("This is not an IPv4 address !", 29),
		equal,
		-EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("256.0.0.1", 9),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("1.300.0.1", 9),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("1.0.925.1", 9),
	                equal,
	                -EINVAL);
	cute_check_sint(incfg_ipv4_addr_check_nstr("1.0.0.925", 9),
	                equal,
	                -EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_pack_assert)
{
	struct dpack_encoder        enc;
	const union incfg_ipv4_addr addr;

	cute_expect_assertion(incfg_ipv4_addr_pack(&enc, NULL));
	cute_expect_assertion(incfg_ipv4_addr_pack(NULL, &addr));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_pack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_pack)
{
	struct dpack_encoder        enc;
	char                        buff[INCFG_IPV4_ADDR_PACKSZ + 2];
	const union incfg_ipv4_addr addr =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_LOOPBACK);
	const uint8_t               ref[] = "\xc4\x04\x7f\x00\x00\x01\xff\xff";

	cute_check_uint(INCFG_IPV4_ADDR_PACKSZ, equal, 6);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	cute_check_sint(incfg_ipv4_addr_pack(&enc, &addr), equal, 0);
	cute_check_uint(dpack_encoder_space_used(&enc),
	                equal,
	                INCFG_IPV4_ADDR_PACKSZ);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - INCFG_IPV4_ADDR_PACKSZ);
	cute_check_mem(buff, equal, ref, sizeof(ref) - 1);

	dpack_encoder_fini(&enc, DPACK_DONE);
}

CUTE_TEST(incfgut_ipv4_addr_pack_short)
{
	struct dpack_encoder        enc;
	char                        buff = '\xff';
	char                        ref = '\xff';
	const union incfg_ipv4_addr addr =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_LOOPBACK);

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_ipv4_addr_pack(&enc, &addr), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 0);
	cute_check_uint(dpack_encoder_space_left(&enc), equal, sizeof(buff));
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_unpack_assert)
{
	struct dpack_decoder  dec;
	union incfg_ipv4_addr addr;

	cute_expect_assertion(incfg_ipv4_addr_unpack(&dec, NULL));
	cute_expect_assertion(incfg_ipv4_addr_unpack(NULL, &addr));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_unpack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_unpack)
{
	struct dpack_decoder        dec;
	const char                  buff[] = "\xc4\x04\x7f\x00\x00\x01";
	union incfg_ipv4_addr       addr;
	const union incfg_ipv4_addr ref =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_LOOPBACK);

	memset(&addr, 0xff, sizeof(addr));
	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv4_addr_unpack(&dec, &addr),
	                equal,
	                (ssize_t)sizeof(addr));
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_mem(&addr, equal, &ref, sizeof(ref));

	dpack_decoder_fini(&dec);
}

CUTE_TEST(incfgut_ipv4_addr_unpack_short)
{
	struct dpack_decoder        dec;
	const char                  buff[] = "\xc4\x04";
	union incfg_ipv4_addr       addr;

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv4_addr_unpack(&dec, &addr), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);
}

CUTE_GROUP(incfgut_ipv4_group) = {
	CUTE_REF(incfgut_ipv4_addr_init_saddr),
	CUTE_REF(incfgut_ipv4_addr_setup_saddr_assert),
	CUTE_REF(incfgut_ipv4_addr_setup_saddr),
	CUTE_REF(incfgut_ipv4_addr_create_saddr),
	CUTE_REF(incfgut_ipv4_addr_init_inet),
	CUTE_REF(incfgut_ipv4_addr_setup_inet_assert),
	CUTE_REF(incfgut_ipv4_addr_setup_inet),
	CUTE_REF(incfgut_ipv4_addr_create_inet_assert),
	CUTE_REF(incfgut_ipv4_addr_create_inet),
	CUTE_REF(incfgut_ipv4_addr_setup_str_assert),
	CUTE_REF(incfgut_ipv4_addr_setup_str),
	CUTE_REF(incfgut_ipv4_addr_setup_nstr_assert),
	CUTE_REF(incfgut_ipv4_addr_setup_nstr),
	CUTE_REF(incfgut_ipv4_addr_create_str_assert),
	CUTE_REF(incfgut_ipv4_addr_create_str),
	CUTE_REF(incfgut_ipv4_addr_create_nstr_assert),
	CUTE_REF(incfgut_ipv4_addr_create_nstr),
	CUTE_REF(incfgut_ipv4_addr_str_assert),
	CUTE_REF(incfgut_ipv4_addr_str),
	CUTE_REF(incfgut_ipv4_addr_check_str_assert),
	CUTE_REF(incfgut_ipv4_addr_check_str),
	CUTE_REF(incfgut_ipv4_addr_check_nstr_assert),
	CUTE_REF(incfgut_ipv4_addr_check_nstr),
	CUTE_REF(incfgut_ipv4_addr_pack_assert),
	CUTE_REF(incfgut_ipv4_addr_pack),
	CUTE_REF(incfgut_ipv4_addr_pack_short),
	CUTE_REF(incfgut_ipv4_addr_unpack_assert),
	CUTE_REF(incfgut_ipv4_addr_unpack),
	CUTE_REF(incfgut_ipv4_addr_unpack_short)
};

CUTE_SUITE_EXTERN(incfgut_ipv4_suite,
                  incfgut_ipv4_group,
                  incfgut_setup,
                  incfgut_ipv4_teardown,
                  CUTE_DFLT_TMOUT);
