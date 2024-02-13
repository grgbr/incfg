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
	struct incfg_ipv6_addr addr;
	const char *           str = str;

	incfg_ipv6_addr_init(&addr);
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
	struct incfg_ipv6_addr val;
	struct in6_addr        ref;

	incfg_ipv6_addr_init(&val);

	cute_check_sint(inet_pton(AF_INET6, addr, &ref), equal, 1);

	cute_check_sint(incfg_ipv6_addr_set_str(&val, addr), equal, 0);

	cute_check_mem(&val.inet, equal, &ref, sizeof(ref));

	incfg_ipv6_addr_fini(&val);
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
	struct incfg_ipv6_addr val;

	incfg_ipv6_addr_init(&val);
	cute_check_sint(incfg_ipv6_addr_set_str(&val, addr), equal, -EINVAL);
	incfg_ipv6_addr_fini(&val);
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
	struct incfg_ipv6_addr addr;
	const char *           str = str;

	incfg_ipv6_addr_init(&addr);
	cute_expect_assertion(incfg_ipv6_addr_set_nstr(&addr, NULL, 1));
	cute_expect_assertion(incfg_ipv6_addr_set_nstr(NULL, str, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv6_addr_set_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv6_addr_test_set_nstr_ok(const char * addr, size_t len)
{
	struct incfg_ipv6_addr val;
	char                   str[INET6_ADDRSTRLEN];
	struct in6_addr        ref;

	incfg_ipv6_addr_init(&val);

	memcpy(str, addr, len);
	str[len] = '\0';
	cute_check_sint(inet_pton(AF_INET6, str, &ref), equal, 1);

	cute_check_sint(incfg_ipv6_addr_set_nstr(&val, addr, len), equal, 0);

	cute_check_mem(&val.inet, equal, &ref, sizeof(ref));

	incfg_ipv6_addr_fini(&val);
}


CUTE_TEST(incfgut_ipv6_addr_set_nstr_ok)
{
	incfgut_ipv6_addr_test_set_nstr_ok("::", 2);
	incfgut_ipv6_addr_test_set_nstr_ok("::1", 3);
	incfgut_ipv6_addr_test_set_nstr_ok("ff02::1", 7);
	incfgut_ipv6_addr_test_set_nstr_ok("ff05::2", 7);
	incfgut_ipv6_addr_test_set_nstr_ok("2002:c000:0204::", 16);
	incfgut_ipv6_addr_test_set_nstr_ok("::ffff:192.0.2.4", 16);

	incfgut_ipv6_addr_test_set_nstr_ok("::xxxx", 2);
	incfgut_ipv6_addr_test_set_nstr_ok("::1xxxx", 3);
	incfgut_ipv6_addr_test_set_nstr_ok("ff02::1xxxx", 7);
	incfgut_ipv6_addr_test_set_nstr_ok("ff05::2xxxx", 7);
	incfgut_ipv6_addr_test_set_nstr_ok("2002:c000:0204::xxxx", 16);
	incfgut_ipv6_addr_test_set_nstr_ok("::ffff:192.0.2.4xxxx", 16);
}

static void
incfgut_ipv6_addr_test_set_nstr_nok(const char * addr, size_t len)
{
	struct incfg_ipv6_addr val;

	incfg_ipv6_addr_init(&val);

	cute_check_sint(incfg_ipv6_addr_set_nstr(&val, addr, len),
	                equal,
	                -EINVAL);

	incfg_ipv6_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv6_addr_set_nstr_nok)
{
	incfgut_ipv6_addr_test_set_nstr_nok(":", 1);
	incfgut_ipv6_addr_test_set_nstr_nok(":::", 3);
	incfgut_ipv6_addr_test_set_nstr_nok("ff02:::", 7);
	incfgut_ipv6_addr_test_set_nstr_nok("fffff::2", 8);
	incfgut_ipv6_addr_test_set_nstr_nok("f:f:f:f:f:f:f:f:f", 17);
	incfgut_ipv6_addr_test_set_nstr_nok("f:", 2);
	incfgut_ipv6_addr_test_set_nstr_nok(":f", 2);
	incfgut_ipv6_addr_test_set_nstr_nok("fail", 4);
	incfgut_ipv6_addr_test_set_nstr_nok("", 0);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_pack_assert)
{
	struct dpack_encoder   enc;
	struct incfg_ipv6_addr addr;

	incfg_ipv6_addr_init(&addr);

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
	struct dpack_encoder   enc;
	char                   buff[INCFG_IPV6_ADDR_PACKSZ + 2];
	struct incfg_ipv6_addr addr;
	const uint8_t          ref[] = "\xc4\x10"
	                               "\x00\x00\x00\x00\x00\x00\x00\x00"
	                               "\x00\x00\x00\x00\x00\x00\x00\x01";

	incfg_ipv6_addr_init(&addr);
	incfg_ipv6_addr_set_inet(&addr, &in6addr_loopback);

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
	incfg_ipv6_addr_fini(&addr);
}

CUTE_TEST(incfgut_ipv6_addr_pack_short)
{
	struct dpack_encoder   enc;
	char                   buff = '\xff';
	char                   ref = '\xff';
	struct incfg_ipv6_addr addr;

	incfg_ipv6_addr_init(&addr);
	incfg_ipv6_addr_set_inet(&addr, &in6addr_loopback);

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_ipv6_addr_pack(&addr, &enc), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 0);
	cute_check_uint(dpack_encoder_space_left(&enc), equal, sizeof(buff));
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);
	incfg_ipv6_addr_fini(&addr);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv6_addr_unpack_assert)
{
	struct dpack_decoder   dec;
	struct incfg_ipv6_addr addr;

	incfg_ipv6_addr_init(&addr);

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
	struct dpack_decoder   dec;
	const char             buff[] = "\xc4\x10"
	                                "\x00\x00\x00\x00\x00\x00\x00\x00"
	                                "\x00\x00\x00\x00\x00\x00\x00\x01";
	struct incfg_ipv6_addr addr;

	incfg_ipv6_addr_init(&addr);
	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv6_addr_unpack(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_mem(&addr.inet,
	               equal,
	               &in6addr_loopback,
	               sizeof(in6addr_loopback));

	dpack_decoder_fini(&dec);
	incfg_ipv6_addr_fini(&addr);
}

CUTE_TEST(incfgut_ipv6_addr_unpack_short)
{
	struct dpack_decoder   dec;
	const char             buff[] = "\xc4\x10";
	struct incfg_ipv6_addr addr;

	incfg_ipv6_addr_init(&addr);
	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv6_addr_unpack(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);
	incfg_ipv6_addr_fini(&addr);
}

CUTE_GROUP(incfgut_ipv6_group) = {
	CUTE_REF(incfgut_ipv6_addr_set_inet_assert),
	CUTE_REF(incfgut_ipv6_addr_set_inet),
	CUTE_REF(incfgut_ipv6_addr_get_str_assert),
	CUTE_REF(incfgut_ipv6_addr_get_str),

	CUTE_REF(incfgut_ipv6_addr_check_str_assert),
	CUTE_REF(incfgut_ipv6_addr_check_str_ok),
	CUTE_REF(incfgut_ipv6_addr_check_str_nok),
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
};

CUTE_SUITE_EXTERN(incfgut_ipv6_suite,
                  incfgut_ipv6_group,
                  incfgut_setup,
                  incfgut_teardown,
                  CUTE_DFLT_TMOUT);
