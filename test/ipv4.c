/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ipv4.h"
#include <arpa/inet.h>
#include <dpack/codec.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_set_saddr_assert)
{
	cute_expect_assertion(incfg_ipv4_addr_set_saddr(NULL, INADDR_ANY));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_set_saddr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_test_set_addr(in_addr_t addr)
{
	struct incfg_ipv4_addr val;
	const struct in_addr   ref = { .s_addr = htonl(addr) };

	incfg_ipv4_addr_init(&val);
	incfg_ipv4_addr_set_saddr(&val, addr);

	cute_check_mem(incfg_ipv4_addr_get_inet(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_ipv4_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv4_addr_set_saddr)
{
	incfgut_ipv4_addr_test_set_addr(INADDR_ANY);
	incfgut_ipv4_addr_test_set_addr(INADDR_BROADCAST);
	incfgut_ipv4_addr_test_set_addr(INADDR_LOOPBACK);
	incfgut_ipv4_addr_test_set_addr(INADDR_ALLSNOOPERS_GROUP);
}

static void
incfgut_ipv4_addr_test_set_inet(in_addr_t addr)
{
	struct incfg_ipv4_addr val;
	const struct in_addr   ref = { .s_addr = htonl(addr) };

	incfg_ipv4_addr_init(&val);
	incfg_ipv4_addr_set_inet(&val, &ref);

	cute_check_mem(incfg_ipv4_addr_get_inet(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_ipv4_addr_fini(&val);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_set_inet_assert)
{
	struct incfg_ipv4_addr addr;
	const struct in_addr   inet;

	incfg_ipv4_addr_init(&addr);

	cute_expect_assertion(incfg_ipv4_addr_set_inet(NULL, &inet));
	cute_expect_assertion(incfg_ipv4_addr_set_inet(&addr, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_set_inet_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_set_inet)
{
	incfgut_ipv4_addr_test_set_inet(INADDR_ANY);
	incfgut_ipv4_addr_test_set_inet(INADDR_BROADCAST);
	incfgut_ipv4_addr_test_set_inet(INADDR_LOOPBACK);
	incfgut_ipv4_addr_test_set_inet(INADDR_ALLSNOOPERS_GROUP);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_get_str_assert)
{
	cute_expect_assertion(incfg_ipv4_addr_get_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_get_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_test_get_str(in_addr_t saddr)
{
	struct incfg_ipv4_addr      addr;
	const struct stroll_lvstr * str;
	char                        ref[INET_ADDRSTRLEN];

	incfg_ipv4_addr_init(&addr);
	incfg_ipv4_addr_set_saddr(&addr, saddr);

	cute_check_ptr(inet_ntop(AF_INET, &addr.inet, ref, sizeof(ref)),
	               equal,
	               ref);

	str = incfg_ipv4_addr_get_str(&addr);
	cute_check_str(stroll_lvstr_cstr(str), equal, ref);

	incfg_ipv4_addr_fini(&addr);
}

CUTE_TEST(incfgut_ipv4_addr_get_str)
{
	incfgut_ipv4_addr_test_get_str(INADDR_ANY);
	incfgut_ipv4_addr_test_get_str(INADDR_BROADCAST);
	incfgut_ipv4_addr_test_get_str(INADDR_LOOPBACK);
	incfgut_ipv4_addr_test_get_str(INADDR_ALLSNOOPERS_GROUP);
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

static void
incfgut_ipv4_addr_test_check_str_ok(const char * addr)
{
	cute_check_sint(incfg_ipv4_addr_check_str(addr), equal, 0);
}

CUTE_TEST(incfgut_ipv4_addr_check_str_ok)
{
	incfgut_ipv4_addr_test_check_str_ok("0.0.0.0");
	incfgut_ipv4_addr_test_check_str_ok("255.255.255.255");
	incfgut_ipv4_addr_test_check_str_ok("127.0.0.1");
	incfgut_ipv4_addr_test_check_str_ok("224.0.0.106");
}

static void
incfgut_ipv4_addr_test_check_str_nok(const char * addr)
{
	cute_check_sint(incfg_ipv4_addr_check_str(addr), equal, -EINVAL);
}

CUTE_TEST(incfgut_ipv4_addr_check_str_nok)
{
	incfgut_ipv4_addr_test_check_str_nok("0.0.0.0.");
	incfgut_ipv4_addr_test_check_str_nok("0.0.0.");
	incfgut_ipv4_addr_test_check_str_nok("256.0.0.1");
	incfgut_ipv4_addr_test_check_str_nok("254.300.0.1");
	incfgut_ipv4_addr_test_check_str_nok("254.254.260.1");
	incfgut_ipv4_addr_test_check_str_nok("fail");
	incfgut_ipv4_addr_test_check_str_nok("");
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

static void
incfgut_ipv4_addr_test_check_nstr_ok(const char * addr, size_t len)
{
	cute_check_sint(incfg_ipv4_addr_check_nstr(addr, len), equal, 0);
}

CUTE_TEST(incfgut_ipv4_addr_check_nstr_ok)
{
	incfgut_ipv4_addr_test_check_nstr_ok("0.0.0.0", 7);
	incfgut_ipv4_addr_test_check_nstr_ok("255.255.255.255", 15);
	incfgut_ipv4_addr_test_check_nstr_ok("127.0.0.1", 9);
	incfgut_ipv4_addr_test_check_nstr_ok("224.0.0.106", 11);

	incfgut_ipv4_addr_test_check_nstr_ok("0.0.0.0xxxx", 7);
	incfgut_ipv4_addr_test_check_nstr_ok("255.255.255.255xxxx", 15);
	incfgut_ipv4_addr_test_check_nstr_ok("127.0.0.1xxxx", 9);
	incfgut_ipv4_addr_test_check_nstr_ok("224.0.0.106xxxx", 11);
}

static void
incfgut_ipv4_addr_test_check_nstr_nok(const char * addr, size_t len)
{
	cute_check_sint(incfg_ipv4_addr_check_nstr(addr, len), equal, -EINVAL);
}

CUTE_TEST(incfgut_ipv4_addr_check_nstr_nok)
{
	incfgut_ipv4_addr_test_check_nstr_nok("0.0.0.0.", 8);
	incfgut_ipv4_addr_test_check_nstr_nok("0.0.0.", 6);
	incfgut_ipv4_addr_test_check_nstr_nok("256.0.0.1", 9);
	incfgut_ipv4_addr_test_check_nstr_nok("254.300.0.1", 11);
	incfgut_ipv4_addr_test_check_nstr_nok("254.254.260.1", 13);
	incfgut_ipv4_addr_test_check_nstr_nok("fail", 4);
	incfgut_ipv4_addr_test_check_nstr_nok("", 0);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_set_str_assert)
{
	struct incfg_ipv4_addr addr;
	const char *           str = str;

	incfg_ipv4_addr_init(&addr);
	cute_expect_assertion(incfg_ipv4_addr_set_str(&addr, NULL));
	cute_expect_assertion(incfg_ipv4_addr_set_str(NULL, str));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_set_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_test_set_str_ok(const char * addr)
{
	struct incfg_ipv4_addr val;
	struct in_addr         ref;

	incfg_ipv4_addr_init(&val);

	cute_check_sint(inet_pton(AF_INET, addr, &ref), equal, 1);

	cute_check_sint(incfg_ipv4_addr_set_str(&val, addr), equal, 0);

	cute_check_mem(&val.inet, equal, &ref, sizeof(ref));

	incfg_ipv4_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv4_addr_set_str_ok)
{
	incfgut_ipv4_addr_test_set_str_ok("0.0.0.0");
	incfgut_ipv4_addr_test_set_str_ok("255.255.255.255");
	incfgut_ipv4_addr_test_set_str_ok("127.0.0.1");
	incfgut_ipv4_addr_test_set_str_ok("224.0.0.106");
}

static void
incfgut_ipv4_addr_test_set_str_nok(const char * addr)
{
	struct incfg_ipv4_addr val;

	incfg_ipv4_addr_init(&val);
	cute_check_sint(incfg_ipv4_addr_set_str(&val, addr), equal, -EINVAL);
	incfg_ipv4_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv4_addr_set_str_nok)
{
	incfgut_ipv4_addr_test_set_str_nok("0.0.0.0.");
	incfgut_ipv4_addr_test_set_str_nok("0.0.0.");
	incfgut_ipv4_addr_test_set_str_nok("256.0.0.1");
	incfgut_ipv4_addr_test_set_str_nok("254.300.0.1");
	incfgut_ipv4_addr_test_set_str_nok("254.254.260.1");
	incfgut_ipv4_addr_test_set_str_nok("fail");
	incfgut_ipv4_addr_test_set_str_nok("");
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_set_nstr_assert)
{
	struct incfg_ipv4_addr addr;
	const char *           str = str;

	incfg_ipv4_addr_init(&addr);
	cute_expect_assertion(incfg_ipv4_addr_set_nstr(&addr, NULL, 1));
	cute_expect_assertion(incfg_ipv4_addr_set_nstr(NULL, str, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_set_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_ipv4_addr_test_set_nstr_ok(const char * addr, size_t len)
{
	struct incfg_ipv4_addr val;
	char                   str[INET_ADDRSTRLEN];
	struct in_addr         ref;

	incfg_ipv4_addr_init(&val);

	memcpy(str, addr, len);
	str[len] = '\0';
	cute_check_sint(inet_pton(AF_INET, str, &ref), equal, 1);

	cute_check_sint(incfg_ipv4_addr_set_nstr(&val, addr, len), equal, 0);

	cute_check_mem(&val.inet, equal, &ref, sizeof(ref));

	incfg_ipv4_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv4_addr_set_nstr_ok)
{
	incfgut_ipv4_addr_test_set_nstr_ok("0.0.0.0", 7);
	incfgut_ipv4_addr_test_set_nstr_ok("255.255.255.255", 15);
	incfgut_ipv4_addr_test_set_nstr_ok("127.0.0.1", 9);
	incfgut_ipv4_addr_test_set_nstr_ok("224.0.0.106", 11);

	incfgut_ipv4_addr_test_set_nstr_ok("0.0.0.0xxxx", 7);
	incfgut_ipv4_addr_test_set_nstr_ok("255.255.255.255xxxx", 15);
	incfgut_ipv4_addr_test_set_nstr_ok("127.0.0.1xxxx", 9);
	incfgut_ipv4_addr_test_set_nstr_ok("224.0.0.106xxxx", 11);
}

static void
incfgut_ipv4_addr_test_set_nstr_nok(const char * addr, size_t len)
{
	struct incfg_ipv4_addr val;

	incfg_ipv4_addr_init(&val);

	cute_check_sint(incfg_ipv4_addr_set_nstr(&val, addr, len),
	                equal,
	                -EINVAL);

	incfg_ipv4_addr_fini(&val);
}

CUTE_TEST(incfgut_ipv4_addr_set_nstr_nok)
{
	incfgut_ipv4_addr_test_set_nstr_nok("0.0.0.0.", 8);
	incfgut_ipv4_addr_test_set_nstr_nok("0.0.0.", 6);
	incfgut_ipv4_addr_test_set_nstr_nok("256.0.0.1", 9);
	incfgut_ipv4_addr_test_set_nstr_nok("254.300.0.1", 11);
	incfgut_ipv4_addr_test_set_nstr_nok("254.254.260.1", 13);
	incfgut_ipv4_addr_test_set_nstr_nok("fail", 4);
	incfgut_ipv4_addr_test_set_nstr_nok("", 0);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_pack_assert)
{
	struct dpack_encoder   enc;
	struct incfg_ipv4_addr addr;

	incfg_ipv4_addr_init(&addr);

	cute_expect_assertion(incfg_ipv4_addr_pack(&addr, NULL));
	cute_expect_assertion(incfg_ipv4_addr_pack(NULL, &enc));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_pack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_pack)
{
	struct dpack_encoder   enc;
	char                   buff[INCFG_IPV4_ADDR_PACKSZ + 2];
	struct incfg_ipv4_addr addr;
	const uint8_t          ref[] = "\xc4\x04\x7f\x00\x00\x01\xff\xff";

	incfg_ipv4_addr_init(&addr);
	incfg_ipv4_addr_set_saddr(&addr, INADDR_LOOPBACK);

	cute_check_uint(INCFG_IPV4_ADDR_PACKSZ, equal, 6);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	cute_check_sint(incfg_ipv4_addr_pack(&addr, &enc), equal, 0);
	cute_check_uint(dpack_encoder_space_used(&enc),
	                equal,
	                INCFG_IPV4_ADDR_PACKSZ);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - INCFG_IPV4_ADDR_PACKSZ);
	cute_check_mem(buff, equal, ref, sizeof(ref) - 1);

	dpack_encoder_fini(&enc, DPACK_DONE);
	incfg_ipv4_addr_fini(&addr);
}

CUTE_TEST(incfgut_ipv4_addr_pack_short)
{
	struct dpack_encoder   enc;
	char                   buff = '\xff';
	char                   ref = '\xff';
	struct incfg_ipv4_addr addr;

	incfg_ipv4_addr_init(&addr);
	incfg_ipv4_addr_set_saddr(&addr, INADDR_LOOPBACK);

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_ipv4_addr_pack(&addr, &enc), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 0);
	cute_check_uint(dpack_encoder_space_left(&enc), equal, sizeof(buff));
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);
	incfg_ipv4_addr_fini(&addr);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_ipv4_addr_unpack_assert)
{
	struct dpack_decoder   dec;
	struct incfg_ipv4_addr addr;

	incfg_ipv4_addr_init(&addr);

	cute_expect_assertion(incfg_ipv4_addr_unpack(&addr, NULL));
	cute_expect_assertion(incfg_ipv4_addr_unpack(NULL, &dec));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_unpack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_ipv4_addr_unpack)
{
	struct dpack_decoder   dec;
	const char             buff[] = "\xc4\x04\x7f\x00\x00\x01";
	struct incfg_ipv4_addr addr;
	const struct in_addr   ref = { .s_addr = htonl(INADDR_LOOPBACK) };

	incfg_ipv4_addr_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv4_addr_unpack(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_mem(&addr.inet, equal, &ref, sizeof(ref));

	dpack_decoder_fini(&dec);

	incfg_ipv4_addr_fini(&addr);
}

CUTE_TEST(incfgut_ipv4_addr_unpack_short)
{
	struct dpack_decoder   dec;
	const char             buff[] = "\xc4\x04";
	struct incfg_ipv4_addr addr;

	incfg_ipv4_addr_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_ipv4_addr_unpack(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_ipv4_addr_fini(&addr);
}

CUTE_GROUP(incfgut_ipv4_group) = {
	CUTE_REF(incfgut_ipv4_addr_set_saddr_assert),
	CUTE_REF(incfgut_ipv4_addr_set_saddr),

	CUTE_REF(incfgut_ipv4_addr_set_inet_assert),
	CUTE_REF(incfgut_ipv4_addr_set_inet),

	CUTE_REF(incfgut_ipv4_addr_get_str_assert),
	CUTE_REF(incfgut_ipv4_addr_get_str),

	CUTE_REF(incfgut_ipv4_addr_check_str_assert),
	CUTE_REF(incfgut_ipv4_addr_check_str_ok),
	CUTE_REF(incfgut_ipv4_addr_check_str_nok),
	CUTE_REF(incfgut_ipv4_addr_check_nstr_assert),
	CUTE_REF(incfgut_ipv4_addr_check_nstr_ok),
	CUTE_REF(incfgut_ipv4_addr_check_nstr_nok),

	CUTE_REF(incfgut_ipv4_addr_set_str_assert),
	CUTE_REF(incfgut_ipv4_addr_set_str_ok),
	CUTE_REF(incfgut_ipv4_addr_set_str_nok),
	CUTE_REF(incfgut_ipv4_addr_set_nstr_assert),
	CUTE_REF(incfgut_ipv4_addr_set_nstr_ok),
	CUTE_REF(incfgut_ipv4_addr_set_nstr_nok),

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
                  incfgut_teardown,
                  CUTE_DFLT_TMOUT);
