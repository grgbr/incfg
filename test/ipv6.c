/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ipv6.h"
#include <arpa/inet.h>
#include <dpack/codec.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>

/*
 * Well known IPv6 addresses borrowed from <linux>/include/linux/in6.h
 *
 * NOTE: Be aware the IN6ADDR_* constants and in6addr_* variables are defined
 * in network byte order, not in host byte order as are the IPv4 equivalents.
 */

#define IN6ADDR_LINKLOCAL_ALLNODES_INIT \
	{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,1 } } }

static const struct in6_addr
in6addr_linklocal_allnodes = IN6ADDR_LINKLOCAL_ALLNODES_INIT;

#define IN6ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{ { { 0xff,2,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }

static const struct in6_addr
in6addr_linklocal_allrouters = IN6ADDR_LINKLOCAL_ALLROUTERS_INIT;

#define IN6ADDR_SITELOCAL_ALLROUTERS_INIT \
	{ { { 0xff,5,0,0,0,0,0,0,0,0,0,0,0,0,0,2 } } }

static const struct in6_addr
in6addr_sitelocal_allrouters = IN6ADDR_SITELOCAL_ALLROUTERS_INIT;

static void
incfgut_ipv6_addr_test_set_inet(const struct in6_addr * addr)
{
	struct incfg_ipv6_addr val;
	const struct in6_addr  ref = *addr;

	incfg_ipv6_addr_init(&val);

	incfg_ipv6_addr_set_inet(&val, &ref);

	cute_check_mem(incfg_ipv6_addr_get_inet(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_ipv6_addr_fini(&val);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_set_inet_assert)
{
	struct incfg_ipv6_addr val;
	struct in6_addr        addr;

	incfg_ipv6_addr_init(&val);

	cute_expect_assertion(incfg_ipv6_addr_set_inet(NULL, &addr));
	cute_expect_assertion(incfg_ipv6_addr_set_inet(&val, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_set_inet_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_set_inet)
{
	incfgut_ipv6_addr_test_set_inet(&in6addr_any);
	incfgut_ipv6_addr_test_set_inet(&in6addr_loopback);
	incfgut_ipv6_addr_test_set_inet(&in6addr_linklocal_allnodes);
	incfgut_ipv6_addr_test_set_inet(&in6addr_linklocal_allrouters);
	incfgut_ipv6_addr_test_set_inet(&in6addr_sitelocal_allrouters);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_get_str_assert)
{
	cute_expect_assertion(incfg_ipv6_addr_get_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_get_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv6_addr_test_get_str(const struct in6_addr * addr)
{
	struct incfg_ipv6_addr      val;
	const struct stroll_lvstr * str;
	char                        ref[INET6_ADDRSTRLEN];

	incfg_ipv6_addr_init(&val);
	incfg_ipv6_addr_set_inet(&val, addr);

	cute_check_ptr(inet_ntop(AF_INET6, addr, ref, sizeof(ref)),
	               equal,
	               ref);

	str = incfg_ipv6_addr_get_str(&val);
	cute_check_str(stroll_lvstr_cstr(str), equal, ref);

	incfg_ipv6_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv6_addr_get_str)
{
	incfgut_ipv6_addr_test_get_str(&in6addr_any);
	incfgut_ipv6_addr_test_get_str(&in6addr_loopback);
	incfgut_ipv6_addr_test_get_str(&in6addr_linklocal_allnodes);
	incfgut_ipv6_addr_test_get_str(&in6addr_linklocal_allrouters);
	incfgut_ipv6_addr_test_get_str(&in6addr_sitelocal_allrouters);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_check_str_assert)
{
	cute_expect_assertion(incfg_ipv6_addr_check_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_check_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv6_addr_test_check_str_ok(const char * addr)
{
	cute_check_sint(incfg_ipv6_addr_check_str(addr), equal, 0);
}

CUTE_TEST(incfgut_ipv6_addr_check_str_ok)
{
	incfgut_ipv6_addr_test_check_str_ok("::");
	incfgut_ipv6_addr_test_check_str_ok("::1");
	incfgut_ipv6_addr_test_check_str_ok("ff02::1");
	incfgut_ipv6_addr_test_check_str_ok("ff05::2");
	incfgut_ipv6_addr_test_check_str_ok("2002:c000:0204::");
	incfgut_ipv6_addr_test_check_str_ok("::ffff:192.0.2.4");
}

static void
incfgut_ipv6_addr_test_check_str_nok(const char * addr)
{
	cute_check_sint(incfg_ipv6_addr_check_str(addr), equal, -EINVAL);
}

CUTE_TEST(incfgut_ipv6_addr_check_str_nok)
{
	incfgut_ipv6_addr_test_check_str_nok(":");
	incfgut_ipv6_addr_test_check_str_nok(":::");
	incfgut_ipv6_addr_test_check_str_nok("ff02:::");
	incfgut_ipv6_addr_test_check_str_nok("fffff::2");
	incfgut_ipv6_addr_test_check_str_nok("f:f:f:f:f:f:f:f:f");
	incfgut_ipv6_addr_test_check_str_nok("f:");
	incfgut_ipv6_addr_test_check_str_nok(":f");
	incfgut_ipv6_addr_test_check_str_nok("fail");
	incfgut_ipv6_addr_test_check_str_nok("");
}

#if 0
#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_check_nstr_assert)
{
	cute_expect_assertion(incfg_ipv6_addr_check_nstr(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_check_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv6_addr_test_check_nstr_ok(const char * addr)
{
	cute_check_sint(incfg_ipv6_addr_check_nstr(addr, strlen(addr)),
	                equal,
	                0);
}

CUTE_TEST(incfgut_ipv6_addr_check_nstr_ok)
{
	incfgut_ipv6_addr_test_check_nstr_ok("::");
	incfgut_ipv6_addr_test_check_nstr_ok("::1");
	incfgut_ipv6_addr_test_check_nstr_ok("ff02::1");
	incfgut_ipv6_addr_test_check_nstr_ok("ff05::2");
	incfgut_ipv6_addr_test_check_nstr_ok("2002:c000:0204::");
	incfgut_ipv6_addr_test_check_nstr_ok("::ffff:192.0.2.4");
}

static void
incfgut_ipv6_addr_test_check_nstr_nok(const char * addr)
{
	cute_check_sint(incfg_ipv6_addr_check_nstr(addr, strlen(addr)),
	                equal,
	                -EINVAL);
}

CUTE_TEST(incfgut_ipv6_addr_check_nstr_nok)
{
	incfgut_ipv6_addr_test_check_nstr_nok(":");
	incfgut_ipv6_addr_test_check_nstr_nok(":::");
	incfgut_ipv6_addr_test_check_nstr_nok("ff02:::");
	incfgut_ipv6_addr_test_check_nstr_nok("fffff::2");
	incfgut_ipv6_addr_test_check_nstr_nok("f:f:f:f:f:f:f:f:f");
	incfgut_ipv6_addr_test_check_nstr_nok("f:");
	incfgut_ipv6_addr_test_check_nstr_nok(":f");
	incfgut_ipv6_addr_test_check_nstr_nok("fail");
	incfgut_ipv6_addr_test_check_nstr_nok("");
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_set_str_assert)
{
	struct in6_addr addr;
	const char *    str = str;

	cute_expect_assertion(incfg_ipv6_addr_set_str(&addr, NULL));
	cute_expect_assertion(incfg_ipv6_addr_set_str(NULL, str));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_set_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv6_addr_test_set_str_ok(const char * addr)
{
	struct in6_addr val;
	struct in6_addr ref;

	cute_check_sint(inet_pton(AF_INET6, addr, &ref), equal, 1);

	cute_check_sint(incfg_ipv6_addr_set_str(&val, addr), equal, 0);

	cute_check_mem(&val, equal, &ref, sizeof(ref));
}

CUTE_TEST(incfgut_ipv6_addr_set_str_ok)
{
	incfgut_ipv6_addr_test_set_str_ok("::");
	incfgut_ipv6_addr_test_set_str_ok("::1");
	incfgut_ipv6_addr_test_set_str_ok("ff02::1");
	incfgut_ipv6_addr_test_set_str_ok("ff05::2");
	incfgut_ipv6_addr_test_set_str_ok("2002:c000:0204::");
	incfgut_ipv6_addr_test_set_str_ok("::ffff:192.0.2.4");
}

static void
incfgut_ipv6_addr_test_set_str_nok(const char * addr)
{
	struct in6_addr val;

	cute_check_sint(incfg_ipv6_addr_set_str(&val, addr), equal, -EINVAL);
}

CUTE_TEST(incfgut_ipv6_addr_set_str_nok)
{
	incfgut_ipv6_addr_test_set_str_nok(":");
	incfgut_ipv6_addr_test_set_str_nok(":::");
	incfgut_ipv6_addr_test_set_str_nok("ff02:::");
	incfgut_ipv6_addr_test_set_str_nok("fffff::2");
	incfgut_ipv6_addr_test_set_str_nok("f:f:f:f:f:f:f:f:f");
	incfgut_ipv6_addr_test_set_str_nok("f:");
	incfgut_ipv6_addr_test_set_str_nok(":f");
	incfgut_ipv6_addr_test_set_str_nok("fail");
	incfgut_ipv6_addr_test_set_str_nok("");
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_set_nstr_assert)
{
	struct in6_addr addr;
	const char *    str = str;

	cute_expect_assertion(incfg_ipv6_addr_set_nstr(&addr, NULL, 1));
	cute_expect_assertion(incfg_ipv6_addr_set_nstr(NULL, str, 1));
	cute_expect_assertion(incfg_ipv6_addr_set_nstr(&addr, "too long", 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_set_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv6_addr_test_set_nstr_ok(const char * addr)
{
	struct in6_addr val;
	struct in6_addr ref;

	cute_check_sint(inet_pton(AF_INET6, addr, &ref), equal, 1);

	cute_check_sint(incfg_ipv6_addr_set_nstr(&val, addr, strlen(addr)),
	                equal,
	                0);

	cute_check_mem(&val, equal, &ref, sizeof(ref));
}

CUTE_TEST(incfgut_ipv6_addr_set_nstr_ok)
{
	incfgut_ipv6_addr_test_set_nstr_ok("::");
	incfgut_ipv6_addr_test_set_nstr_ok("::1");
	incfgut_ipv6_addr_test_set_nstr_ok("ff02::1");
	incfgut_ipv6_addr_test_set_nstr_ok("ff05::2");
	incfgut_ipv6_addr_test_set_nstr_ok("2002:c000:0204::");
	incfgut_ipv6_addr_test_set_nstr_ok("::ffff:192.0.2.4");
}

static void
incfgut_ipv6_addr_test_set_nstr_nok(const char * addr)
{
	struct in6_addr val;

	cute_check_sint(incfg_ipv6_addr_set_nstr(&val, addr, strlen(addr)),
	                equal,
	                -EINVAL);
}

CUTE_TEST(incfgut_ipv6_addr_set_nstr_nok)
{
	incfgut_ipv6_addr_test_set_nstr_nok(":");
	incfgut_ipv6_addr_test_set_nstr_nok(":::");
	incfgut_ipv6_addr_test_set_nstr_nok("ff02:::");
	incfgut_ipv6_addr_test_set_nstr_nok("fffff::2");
	incfgut_ipv6_addr_test_set_nstr_nok("f:f:f:f:f:f:f:f:f");
	incfgut_ipv6_addr_test_set_nstr_nok("f:");
	incfgut_ipv6_addr_test_set_nstr_nok(":f");
	incfgut_ipv6_addr_test_set_nstr_nok("fail");
	incfgut_ipv6_addr_test_set_nstr_nok("");
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_pack_assert)
{
	struct dpack_encoder  enc;
	const struct in6_addr addr;

	cute_expect_assertion(incfg_ipv6_addr_pack(&addr, NULL));
	cute_expect_assertion(incfg_ipv6_addr_pack(NULL, &enc));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_pack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_pack)
{
	struct dpack_encoder  enc;
	char                  buff[INCFG_IPV6_ADDR_PACKSZ + 2];
	const struct in6_addr addr = in6addr_loopback;
	const uint8_t         ref[] = "\xc4\x10"
	                              "\x00\x00\x00\x00\x00\x00\x00\x00"
	                              "\x00\x00\x00\x00\x00\x00\x00\x01";

	cute_check_uint(INCFG_IPV6_ADDR_PACKSZ, equal, 18);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	cute_check_sint(incfg_ipv6_addr_pack(&addr, &enc), equal, 0);
	cute_check_uint(dpack_encoder_space_used(&enc),
	                equal,
	                INCFG_IPV6_ADDR_PACKSZ);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - INCFG_IPV6_ADDR_PACKSZ);
	cute_check_mem(buff, equal, ref, sizeof(ref) - 1);

	dpack_encoder_fini(&enc, DPACK_DONE);
}

CUTE_TEST(incfgut_ipv6_addr_pack_short)
{
	struct dpack_encoder  enc;
	char                  buff = '\xff';
	char                  ref = '\xff';
	const struct in6_addr addr = in6addr_loopback;

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_ipv6_addr_pack(&addr, &enc), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 0);
	cute_check_uint(dpack_encoder_space_left(&enc), equal, sizeof(buff));
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_unpack_assert)
{
	struct dpack_decoder dec;
	struct in6_addr      addr;

	cute_expect_assertion(incfg_ipv6_addr_unpack(&addr, NULL));
	cute_expect_assertion(incfg_ipv6_addr_unpack(NULL, &dec));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_unpack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_unpack)
{
	struct dpack_decoder  dec;
	const char            buff[] = "\xc4\x10"
	                               "\x00\x00\x00\x00\x00\x00\x00\x00"
	                               "\x00\x00\x00\x00\x00\x00\x00\x01";
	struct in6_addr       addr;
	const struct in6_addr ref = in6addr_loopback;

	memset(&addr, 0xff, sizeof(addr));
	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv6_addr_unpack(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_mem(&addr, equal, &ref, sizeof(ref));

	dpack_decoder_fini(&dec);
}

CUTE_TEST(incfgut_ipv6_addr_unpack_short)
{
	struct dpack_decoder dec;
	const char           buff[] = "\xc4\x10";
	struct in6_addr      addr;

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv6_addr_unpack(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);
}
#endif

CUTE_GROUP(incfgut_ipv6_group) = {
	CUTE_REF(incfgut_ipv6_addr_set_inet_assert),
	CUTE_REF(incfgut_ipv6_addr_set_inet),
	CUTE_REF(incfgut_ipv6_addr_get_str_assert),
	CUTE_REF(incfgut_ipv6_addr_get_str),

	CUTE_REF(incfgut_ipv6_addr_check_str_assert),
	CUTE_REF(incfgut_ipv6_addr_check_str_ok),
	CUTE_REF(incfgut_ipv6_addr_check_str_nok),
#if 0
	CUTE_REF(incfgut_ipv6_addr_check_nstr_assert),
	CUTE_REF(incfgut_ipv6_addr_check_nstr_ok),
	CUTE_REF(incfgut_ipv6_addr_check_nstr_nok),

	CUTE_REF(incfgut_ipv6_addr_set_str_assert),
	CUTE_REF(incfgut_ipv6_addr_set_str_ok),
	CUTE_REF(incfgut_ipv6_addr_set_str_nok),
	CUTE_REF(incfgut_ipv6_addr_set_nstr_assert),
	CUTE_REF(incfgut_ipv6_addr_set_nstr_ok),
	CUTE_REF(incfgut_ipv6_addr_set_nstr_nok),

	CUTE_REF(incfgut_ipv6_addr_pack_assert),
	CUTE_REF(incfgut_ipv6_addr_pack),
	CUTE_REF(incfgut_ipv6_addr_pack_short),

	CUTE_REF(incfgut_ipv6_addr_unpack_assert),
	CUTE_REF(incfgut_ipv6_addr_unpack),
	CUTE_REF(incfgut_ipv6_addr_unpack_short)
#endif
};

CUTE_SUITE_EXTERN(incfgut_ipv6_suite,
                  incfgut_ipv6_group,
                  incfgut_setup,
                  incfgut_teardown,
                  CUTE_DFLT_TMOUT);
