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

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_str_assert)
{
	const union incfg_ipv4_addr addr;
	char                        str[INCFG_IPV4_ADDR_STRSZ];

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
	char                        str[INCFG_IPV4_ADDR_STRSZ];

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
	CUTE_REF(incfgut_ipv4_addr_setup_str),
	CUTE_REF(incfgut_ipv4_addr_create_str_assert),
	CUTE_REF(incfgut_ipv4_addr_create_str),
	CUTE_REF(incfgut_ipv4_addr_str_assert),
	CUTE_REF(incfgut_ipv4_addr_str),
	CUTE_REF(incfgut_ipv4_addr_check_str_assert),
	CUTE_REF(incfgut_ipv4_addr_check_str),
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
