/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ipv4.h"
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <errno.h>

#define INCFGUT_SADDR(...) \
	((const uint8_t []) { __VA_ARGS__ })

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

CUTE_TEST(incfgut_ipv4_addr_setup_saddr)
{
	union incfg_ipv4_addr addr0, addr1, addr2, addr3;

	incfg_ipv4_addr_setup_saddr(&addr0, INADDR_ANY);
	incfg_ipv4_addr_setup_saddr(&addr1, INADDR_BROADCAST);
	incfg_ipv4_addr_setup_saddr(&addr2, INADDR_LOOPBACK);
	incfg_ipv4_addr_setup_saddr(&addr3, INADDR_ALLSNOOPERS_GROUP);

	incfgut_ipv4_addr_check_init(&addr0, &addr1, &addr2, &addr3);
}

CUTE_TEST(incfgut_ipv4_addr_create_saddr)
{
	union incfg_ipv4_addr * addr0, * addr1, * addr2, * addr3;

	addr0 = incfg_ipv4_addr_create_saddr(INADDR_ANY);
	cute_check_ptr(addr0, unequal, NULL);
	addr1 = incfg_ipv4_addr_create_saddr(INADDR_BROADCAST);
	cute_check_ptr(addr1, unequal, NULL);
	addr2 = incfg_ipv4_addr_create_saddr(INADDR_LOOPBACK);
	cute_check_ptr(addr2, unequal, NULL);
	addr3 = incfg_ipv4_addr_create_saddr(INADDR_ALLSNOOPERS_GROUP);
	cute_check_ptr(addr3, unequal, NULL);

	incfgut_ipv4_addr_check_init(addr0, addr1, addr2, addr3);

	incfg_ipv4_addr_destroy(addr0);
	incfg_ipv4_addr_destroy(addr1);
	incfg_ipv4_addr_destroy(addr2);
	incfg_ipv4_addr_destroy(addr3);
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

CUTE_TEST(incfgut_ipv4_addr_create_inet)
{
	const struct in_addr inaddr0 = {
		.s_addr = htonl(INADDR_ANY)
	};
	const struct in_addr inaddr1 = {
		.s_addr = htonl(INADDR_BROADCAST)
	};
	const struct in_addr inaddr2 = {
		.s_addr = htonl(INADDR_LOOPBACK)
	};
	const struct in_addr inaddr3 = {
		.s_addr = htonl(INADDR_ALLSNOOPERS_GROUP)
	};
	union incfg_ipv4_addr * addr0, * addr1, * addr2, * addr3;

	addr0 = incfg_ipv4_addr_create_inet(&inaddr0);
	cute_check_ptr(addr0, unequal, NULL);
	addr1 = incfg_ipv4_addr_create_inet(&inaddr1);
	cute_check_ptr(addr1, unequal, NULL);
	addr2 = incfg_ipv4_addr_create_inet(&inaddr2);
	cute_check_ptr(addr2, unequal, NULL);
	addr3 = incfg_ipv4_addr_create_inet(&inaddr3);
	cute_check_ptr(addr3, unequal, NULL);

	incfgut_ipv4_addr_check_init(addr0, addr1, addr2, addr3);

	incfg_ipv4_addr_destroy(addr0);
	incfg_ipv4_addr_destroy(addr1);
	incfg_ipv4_addr_destroy(addr2);
	incfg_ipv4_addr_destroy(addr3);
}

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

CUTE_TEST(incfgut_ipv4_addr_create_str)
{
	union incfg_ipv4_addr * addr0, * addr1, * addr2, * addr3;

	addr0 = incfg_ipv4_addr_create_str("0.0.0.0");
	cute_check_ptr(addr0, unequal, NULL);
	addr1 = incfg_ipv4_addr_create_str("255.255.255.255");
	cute_check_ptr(addr1, unequal, NULL);
	addr2 = incfg_ipv4_addr_create_str("127.0.0.1");
	cute_check_ptr(addr2, unequal, NULL);
	addr3 = incfg_ipv4_addr_create_str("224.0.0.106");
	cute_check_ptr(addr3, unequal, NULL);

	incfgut_ipv4_addr_check_init(addr0, addr1, addr2, addr3);

	incfg_ipv4_addr_destroy(addr0);
	incfg_ipv4_addr_destroy(addr1);
	incfg_ipv4_addr_destroy(addr2);
	incfg_ipv4_addr_destroy(addr3);

	addr0 = incfg_ipv4_addr_create_str("This is not an IPv4 address !");
	cute_check_ptr(addr0, equal, NULL);
	cute_check_sint(errno, equal, EINVAL);
}

CUTE_TEST(incfgut_ipv4_addr_to_str)
{
	const union incfg_ipv4_addr addr0 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_ANY);
	const union incfg_ipv4_addr addr1 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_BROADCAST);
	const union incfg_ipv4_addr addr2 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_LOOPBACK);
	const union incfg_ipv4_addr addr3 =
		INCFG_IPV4_ADDR_INIT_SADDR(INADDR_ALLSNOOPERS_GROUP);
	char                        str[INCFG_IPV4_ADDR_STRSZ];

	cute_check_ptr(incfg_ipv4_addr_to_str(&addr0, str), equal, str);
	cute_check_str(str, equal, "0.0.0.0");

	cute_check_ptr(incfg_ipv4_addr_to_str(&addr1, str), equal, str);
	cute_check_str(str, equal, "255.255.255.255");

	cute_check_ptr(incfg_ipv4_addr_to_str(&addr2, str), equal, str);
	cute_check_str(str, equal, "127.0.0.1");

	cute_check_ptr(incfg_ipv4_addr_to_str(&addr3, str), equal, str);
	cute_check_str(str, equal, "224.0.0.106");
}

CUTE_GROUP(incfgut_ipv4_group) = {
	CUTE_REF(incfgut_ipv4_addr_init_saddr),
	CUTE_REF(incfgut_ipv4_addr_setup_saddr),
	CUTE_REF(incfgut_ipv4_addr_create_saddr),
	CUTE_REF(incfgut_ipv4_addr_init_inet),
	CUTE_REF(incfgut_ipv4_addr_setup_inet),
	CUTE_REF(incfgut_ipv4_addr_create_inet),
	CUTE_REF(incfgut_ipv4_addr_setup_str),
	CUTE_REF(incfgut_ipv4_addr_create_str),
	CUTE_REF(incfgut_ipv4_addr_to_str)
};

CUTE_SUITE_EXTERN(incfgut_ipv4_suite,
                  incfgut_ipv4_group,
                  CUTE_NULL_SETUP,
                  CUTE_NULL_TEARDOWN,
                  CUTE_DFLT_TMOUT);
