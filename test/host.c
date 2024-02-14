/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/host.h"
#include <arpa/inet.h>
#include <dpack/codec.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>

#define INCFGUT_NOIP_TEST(_name) \
	CUTE_TEST(_name) \
	{ \
		cute_skip("IP support disabled"); \
	}

#define INCFGUT_NODNAME_TEST(_name) \
	CUTE_TEST(_name) \
	{ \
		cute_skip("Domain name support disabled"); \
	}

static void
incfgut_host_test_check_str_ok(const char * addr)
{
	cute_check_sint(incfg_host_check_str(addr), equal, 0);
}

static void
incfgut_host_test_check_str_nok(const char * addr)
{
	cute_check_sint(incfg_host_check_str(addr), equal, -EINVAL);
}

static void
incfgut_host_test_check_nstr_ok(const char * addr, size_t len)
{
	cute_check_sint(incfg_host_check_nstr(addr, len), equal, 0);
}

static void
incfgut_host_test_check_nstr_nok(const char * addr, size_t len)
{
	cute_check_sint(incfg_host_check_nstr(addr, len), equal, -EINVAL);
}

#if defined(CONFIG_INCFG_IPV4)

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_set_saddr4_assert)
{
	cute_expect_assertion(incfg_host_set_saddr4(NULL, INADDR_ANY));
}

CUTE_TEST(incfgut_host_set_inet4_assert)
{
	union incfg_host     addr;
	const struct in_addr inet;

	incfg_host_init(&addr);

	cute_expect_assertion(incfg_host_set_inet4(NULL, &inet));
	cute_expect_assertion(incfg_host_set_inet4(&addr, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_saddr4_assert);
INCFGUT_NOASSERT_TEST(incfgut_host_set_inet4_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_host_test_set_saddr4(in_addr_t addr)
{
	union incfg_host     val;
	const struct in_addr ref = { .s_addr = htonl(addr) };

	incfg_host_init(&val);
	incfg_host_set_saddr4(&val, addr);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_host_get_inet4(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_saddr4)
{
	incfgut_host_test_set_saddr4(INADDR_ANY);
	incfgut_host_test_set_saddr4(INADDR_BROADCAST);
	incfgut_host_test_set_saddr4(INADDR_LOOPBACK);
	incfgut_host_test_set_saddr4(INADDR_ALLSNOOPERS_GROUP);
}

static void
incfgut_host_test_set_inet4(in_addr_t addr)
{
	union incfg_host     val;
	const struct in_addr ref = { .s_addr = htonl(addr) };

	incfg_host_init(&val);
	incfg_host_set_inet4(&val, &ref);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_host_get_inet4(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_inet4)
{
	incfgut_host_test_set_inet4(INADDR_ANY);
	incfgut_host_test_set_inet4(INADDR_BROADCAST);
	incfgut_host_test_set_inet4(INADDR_LOOPBACK);
	incfgut_host_test_set_inet4(INADDR_ALLSNOOPERS_GROUP);
}

static void
incfgut_host_test_get_str4(in_addr_t saddr)
{
	union incfg_host            addr;
	char                        ref[INET_ADDRSTRLEN];
	const struct stroll_lvstr * str;

	incfg_host_init(&addr);
	incfg_host_set_saddr4(&addr, saddr);

	cute_check_ptr(inet_ntop(AF_INET,
	                         incfg_host_get_inet4(&addr),
	                         ref,
	                         sizeof(ref)),
	               equal,
	               ref);

	str = incfg_host_get_str(&addr);
	cute_check_str(stroll_lvstr_cstr(str), equal, ref);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_get_str4)
{
	incfgut_host_test_get_str4(INADDR_ANY);
	incfgut_host_test_get_str4(INADDR_BROADCAST);
	incfgut_host_test_get_str4(INADDR_LOOPBACK);
	incfgut_host_test_get_str4(INADDR_ALLSNOOPERS_GROUP);
}

CUTE_TEST(incfgut_host_check_str4_ok)
{
	incfgut_host_test_check_str_ok("0.0.0.0");
	incfgut_host_test_check_str_ok("255.255.255.255");
	incfgut_host_test_check_str_ok("127.0.0.1");
	incfgut_host_test_check_str_ok("224.0.0.106");
}

CUTE_TEST(incfgut_host_check_str4_nok)
{
	incfgut_host_test_check_str_nok("");
	incfgut_host_test_check_str_nok("0.0.0.0-");
}

CUTE_TEST(incfgut_host_check_nstr4_ok)
{
	incfgut_host_test_check_nstr_ok("0.0.0.0", 7);
	incfgut_host_test_check_nstr_ok("255.255.255.255", 15);
	incfgut_host_test_check_nstr_ok("127.0.0.1", 9);
	incfgut_host_test_check_nstr_ok("224.0.0.106", 11);

	incfgut_host_test_check_nstr_ok("0.0.0.0----", 7);
	incfgut_host_test_check_nstr_ok("255.255.255.255----", 15);
	incfgut_host_test_check_nstr_ok("127.0.0.1----", 9);
	incfgut_host_test_check_nstr_ok("224.0.0.106----", 11);
}

CUTE_TEST(incfgut_host_check_nstr4_nok)
{
	incfgut_host_test_check_nstr_nok("", 0);
	incfgut_host_test_check_nstr_nok("0.0.0.0-", 8);
}

static void
incfgut_host_test_set_str4_ok(const char * addr)
{
	union incfg_host val;
	struct in_addr   ref;

	incfg_host_init(&val);

	cute_check_sint(inet_pton(AF_INET, addr, &ref), equal, 1);

	cute_check_sint(incfg_host_set_str(&val, addr), equal, 0);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_host_get_inet4(&val), equal, &ref, sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_str4_ok)
{
	incfgut_host_test_set_str4_ok("0.0.0.0");
	incfgut_host_test_set_str4_ok("255.255.255.255");
	incfgut_host_test_set_str4_ok("127.0.0.1");
	incfgut_host_test_set_str4_ok("224.0.0.106");
}

#if  defined(CONFIG_INCFG_ASSERT_API)

static void
incfgut_host_test_set_str4_nok(const char * addr)
{
	union incfg_host val;

	incfg_host_init(&val);
	cute_check_sint(incfg_host_set_str(&val, addr), equal, -EINVAL);
	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_str4_nok)
{
	cute_expect_assertion(incfgut_host_test_set_str4_nok(""));
	cute_expect_assertion(incfgut_host_test_set_str4_nok("0.0.0.0-"));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_str4_nok);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_host_test_set_nstr4_ok(const char * addr, size_t len)
{
	union incfg_host val;
	char             str[INET_ADDRSTRLEN];
	struct in_addr   ref;

	incfg_host_init(&val);

	memcpy(str, addr, len);
	str[len] = '\0';
	cute_check_sint(inet_pton(AF_INET, str, &ref), equal, 1);

	cute_check_sint(incfg_host_set_nstr(&val, addr, len), equal, 0);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_host_get_inet4(&val), equal, &ref, sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_nstr4_ok)
{
	incfgut_host_test_set_nstr4_ok("0.0.0.0", 7);
	incfgut_host_test_set_nstr4_ok("255.255.255.255", 15);
	incfgut_host_test_set_nstr4_ok("127.0.0.1", 9);
	incfgut_host_test_set_nstr4_ok("224.0.0.106", 11);

	incfgut_host_test_set_nstr4_ok("0.0.0.0----", 7);
	incfgut_host_test_set_nstr4_ok("255.255.255.255----", 15);
	incfgut_host_test_set_nstr4_ok("127.0.0.1----", 9);
	incfgut_host_test_set_nstr4_ok("224.0.0.106----", 11);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

static void
incfgut_host_test_set_nstr4_nok(const char * addr, size_t len)
{
	union incfg_host val;

	incfg_host_init(&val);

	cute_check_sint(incfg_host_set_nstr(&val, addr, len),
	                equal,
	                -EINVAL);

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_nstr4_nok)
{
	cute_expect_assertion(incfgut_host_test_set_nstr4_nok("", 0));
	cute_expect_assertion(incfgut_host_test_set_nstr4_nok("0.0.0.-", 7));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_nstr4_nok);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_host_pack4)
{
	struct dpack_encoder enc;
	char                 buff[INCFG_IP_ADDR_PACKSZ_MAX + 2];
	union incfg_host     addr;
	const uint8_t        ref[] = "\x00\xc4\x04\x7f\x00\x00\x01\xff\xff";

	incfg_host_init(&addr);
	incfg_host_set_saddr4(&addr, INADDR_LOOPBACK);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	cute_check_sint(incfg_host_pack(&addr, &enc), equal, 0);
	cute_check_uint(dpack_encoder_space_used(&enc),
	                equal,
	                INCFG_ADDR_TYPE_PACKSZ + INCFG_IPV4_ADDR_PACKSZ);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - (INCFG_ADDR_TYPE_PACKSZ +
	                                INCFG_IPV4_ADDR_PACKSZ));
	cute_check_mem(buff, equal, ref, sizeof(ref) - 1);

	dpack_encoder_fini(&enc, DPACK_DONE);
	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_pack4_short)
{
	struct dpack_encoder enc;
	char                 buff = '\xff';
	char                 ref = '\x00';
	union incfg_host     addr;

	incfg_host_init(&addr);
	incfg_host_set_saddr4(&addr, INADDR_LOOPBACK);

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_host_pack(&addr, &enc), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 1);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - 1);
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);
	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpack4)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x00\xc4\x04\x7f\x00\x00\x01";
	union incfg_host     addr;
	const struct in_addr ref = { .s_addr = htonl(INADDR_LOOPBACK) };

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpack(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_uint(((const struct incfg_addr *)&addr)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_host_get_inet4(&addr),
	               equal,
	               &ref,
	               sizeof(ref));

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpack4_short)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x00\xc4\x04";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpack(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpack4_unxpct)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x03\xc4\x04\x7f\x00\x00\x01";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpack(&addr, &dec), equal, -EINVAL);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 6);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpackn_check4)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x00\xc4\x04\x7f\x00\x00\x01";
	union incfg_host     addr;
	const struct in_addr ref = { .s_addr = htonl(INADDR_LOOPBACK) };

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_uint(((const struct incfg_addr *)&addr)->type,
	                equal,
	                INCFG_ADDR_IPV4_TYPE);
	cute_check_mem(incfg_host_get_inet4(&addr),
	               equal,
	               &ref,
	               sizeof(ref));

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpackn_check4_short)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x00\xc4\x04";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpackn_check4_unxpct)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x03\xc4\x04\x7f\x00\x00\x01";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, -EINVAL);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 6);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

#else  /* !defined(CONFIG_INCFG_IPV4) */

INCFGUT_NOIPV4_TEST(incfgut_host_set_saddr4_assert);
INCFGUT_NOIPV4_TEST(incfgut_host_set_saddr4);
INCFGUT_NOIPV4_TEST(incfgut_host_set_inet4_assert);
INCFGUT_NOIPV4_TEST(incfgut_host_set_inet4);
INCFGUT_NOIPV4_TEST(incfgut_host_get_str4);
INCFGUT_NOIPV4_TEST(incfgut_host_check_str4_ok);
INCFGUT_NOIPV4_TEST(incfgut_host_check_str4_nok);
INCFGUT_NOIPV4_TEST(incfgut_host_check_nstr4_ok);
INCFGUT_NOIPV4_TEST(incfgut_host_check_nstr4_nok);
INCFGUT_NOIPV4_TEST(incfgut_host_set_str4_ok);
INCFGUT_NOIPV4_TEST(incfgut_host_set_str4_nok);
INCFGUT_NOIPV4_TEST(incfgut_host_set_nstr4_ok);
INCFGUT_NOIPV4_TEST(incfgut_host_set_nstr4_nok);
INCFGUT_NOIPV4_TEST(incfgut_host_pack4);
INCFGUT_NOIPV4_TEST(incfgut_host_pack4_short);
INCFGUT_NOIPV4_TEST(incfgut_host_unpack4);
INCFGUT_NOIPV4_TEST(incfgut_host_unpack4_short);
INCFGUT_NOIPV4_TEST(incfgut_host_unpack4_unxpct);
INCFGUT_NOIPV4_TEST(incfgut_host_unpackn_check4);
INCFGUT_NOIPV4_TEST(incfgut_host_unpackn_check4_short);
INCFGUT_NOIPV4_TEST(incfgut_host_unpackn_check4_unxpct);

#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_set_inet6_assert)
{
	union incfg_host      addr;
	const struct in6_addr inet;

	incfg_host_init(&addr);

	cute_expect_assertion(incfg_host_set_inet6(NULL, &inet));
	cute_expect_assertion(incfg_host_set_inet6(&addr, NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_inet6_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_host_test_set_inet6(const struct in6_addr * addr)
{
	union incfg_host      val;
	const struct in6_addr ref = *addr;

	incfg_host_init(&val);
	incfg_host_set_inet6(&val, &ref);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV6_TYPE);
	cute_check_mem(incfg_host_get_inet6(&val),
	               equal,
	               &ref,
	               sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_inet6)
{
	incfgut_host_test_set_inet6(&in6addr_any);
	incfgut_host_test_set_inet6(&in6addr_loopback);
	incfgut_host_test_set_inet6(&in6addr_linklocal_allnodes);
	incfgut_host_test_set_inet6(&in6addr_linklocal_allrouters);
	incfgut_host_test_set_inet6(&in6addr_sitelocal_allrouters);
}

static void
incfgut_host_test_get_str6(const struct in6_addr * addr)
{
	union incfg_host            val;
	char                        ref[INET6_ADDRSTRLEN];
	const struct stroll_lvstr * str;

	incfg_host_init(&val);
	incfg_host_set_inet6(&val, addr);

	cute_check_ptr(inet_ntop(AF_INET6, addr, ref, sizeof(ref)),
	               equal,
	               ref);

	str = incfg_host_get_str(&val);
	cute_check_str(stroll_lvstr_cstr(str), equal, ref);

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_get_str6)
{
	incfgut_host_test_get_str6(&in6addr_any);
	incfgut_host_test_get_str6(&in6addr_loopback);
	incfgut_host_test_get_str6(&in6addr_linklocal_allnodes);
	incfgut_host_test_get_str6(&in6addr_linklocal_allrouters);
	incfgut_host_test_get_str6(&in6addr_sitelocal_allrouters);
}

CUTE_TEST(incfgut_host_check_str6_ok)
{
	incfgut_host_test_check_str_ok("::");
	incfgut_host_test_check_str_ok("::1");
	incfgut_host_test_check_str_ok("ff02::1");
	incfgut_host_test_check_str_ok("ff05::2");
	incfgut_host_test_check_str_ok("2002:c000:0204::");
	incfgut_host_test_check_str_ok("::ffff:192.0.2.4");
}

CUTE_TEST(incfgut_host_check_str6_nok)
{
	incfgut_host_test_check_str_nok(":");
	incfgut_host_test_check_str_nok(":::");
	incfgut_host_test_check_str_nok("ff02:::");
	incfgut_host_test_check_str_nok("fffff::2");
	incfgut_host_test_check_str_nok("f:f:f:f:f:f:f:f:f");
	incfgut_host_test_check_str_nok("f:");
	incfgut_host_test_check_str_nok(":f");
	incfgut_host_test_check_str_nok("");
}

CUTE_TEST(incfgut_host_check_nstr6_ok)
{
	incfgut_host_test_check_nstr_ok("::", 2);
	incfgut_host_test_check_nstr_ok("::1", 3);
	incfgut_host_test_check_nstr_ok("ff02::1", 7);
	incfgut_host_test_check_nstr_ok("ff05::2", 7);
	incfgut_host_test_check_nstr_ok("2002:c000:0204::", 16);
	incfgut_host_test_check_nstr_ok("::ffff:192.0.2.4", 16);

	incfgut_host_test_check_nstr_ok("::----", 2);
	incfgut_host_test_check_nstr_ok("::1----", 3);
	incfgut_host_test_check_nstr_ok("ff02::1----", 7);
	incfgut_host_test_check_nstr_ok("ff05::2----", 7);
	incfgut_host_test_check_nstr_ok("2002:c000:0204::----", 16);
	incfgut_host_test_check_nstr_ok("::ffff:192.0.2.4----", 16);
}

CUTE_TEST(incfgut_host_check_nstr6_nok)
{
	incfgut_host_test_check_nstr_nok(":", 1);
	incfgut_host_test_check_nstr_nok(":::", 3);
	incfgut_host_test_check_nstr_nok("ff02:::", 7);
	incfgut_host_test_check_nstr_nok("fffff::2", 8);
	incfgut_host_test_check_nstr_nok("f:f:f:f:f:f:f:f:f", 17);
	incfgut_host_test_check_nstr_nok("f:", 2);
	incfgut_host_test_check_nstr_nok(":f", 2);
	incfgut_host_test_check_nstr_nok("", 0);
}

static void
incfgut_host_test_set_str6_ok(const char * addr)
{
	union incfg_host val;
	struct in6_addr  ref;

	incfg_host_init(&val);

	cute_check_sint(inet_pton(AF_INET6, addr, &ref), equal, 1);

	cute_check_sint(incfg_host_set_str(&val, addr), equal, 0);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV6_TYPE);
	cute_check_mem(incfg_host_get_inet6(&val), equal, &ref, sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_str6_ok)
{
	incfgut_host_test_set_str6_ok("::");
	incfgut_host_test_set_str6_ok("::1");
	incfgut_host_test_set_str6_ok("ff02::1");
	incfgut_host_test_set_str6_ok("ff05::2");
	incfgut_host_test_set_str6_ok("2002:c000:0204::");
	incfgut_host_test_set_str6_ok("::ffff:192.0.2.4");
}
#if  defined(CONFIG_INCFG_ASSERT_API)

static void
incfgut_host_test_set_str6_nok(const char * addr)
{
	union incfg_host val;

	incfg_host_init(&val);
	cute_check_sint(incfg_host_set_str(&val, addr), equal, -EINVAL);
	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_str6_nok)
{
	cute_expect_assertion(incfgut_host_test_set_str6_nok(":"));
	cute_expect_assertion(incfgut_host_test_set_str6_nok(":::"));
	cute_expect_assertion(incfgut_host_test_set_str6_nok("ff02:::"));
	cute_expect_assertion(incfgut_host_test_set_str6_nok("fffff::2"));
	cute_expect_assertion(
		incfgut_host_test_set_str6_nok("f:f:f:f:f:f:f:f:f"));
	cute_expect_assertion(incfgut_host_test_set_str6_nok("f:"));
	cute_expect_assertion(incfgut_host_test_set_str6_nok(":f"));
	cute_expect_assertion(incfgut_host_test_set_str6_nok(""));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_str6_nok);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_host_test_set_nstr6_ok(const char * addr, size_t len)
{
	union incfg_host val;
	char             str[INET6_ADDRSTRLEN];
	struct in6_addr  ref;

	incfg_host_init(&val);

	memcpy(str, addr, len);
	str[len] = '\0';
	cute_check_sint(inet_pton(AF_INET6, str, &ref), equal, 1);

	cute_check_sint(incfg_host_set_nstr(&val, addr, len), equal, 0);

	cute_check_uint(((const struct incfg_addr *)&val)->type,
	                equal,
	                INCFG_ADDR_IPV6_TYPE);
	cute_check_mem(incfg_host_get_inet6(&val), equal, &ref, sizeof(ref));

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_nstr6_ok)
{
	incfgut_host_test_set_nstr6_ok("::", 2);
	incfgut_host_test_set_nstr6_ok("::1", 3);
	incfgut_host_test_set_nstr6_ok("ff02::1", 7);
	incfgut_host_test_set_nstr6_ok("ff05::2", 7);
	incfgut_host_test_set_nstr6_ok("2002:c000:0204::", 16);
	incfgut_host_test_set_nstr6_ok("::ffff:192.0.2.4", 16);

	incfgut_host_test_set_nstr6_ok("::----", 2);
	incfgut_host_test_set_nstr6_ok("::1----", 3);
	incfgut_host_test_set_nstr6_ok("ff02::1----", 7);
	incfgut_host_test_set_nstr6_ok("ff05::2----", 7);
	incfgut_host_test_set_nstr6_ok("2002:c000:0204::----", 16);
	incfgut_host_test_set_nstr6_ok("::ffff:192.0.2.4----", 16);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

static void
incfgut_host_test_set_nstr6_nok(const char * addr, size_t len)
{
	union incfg_host val;

	incfg_host_init(&val);

	cute_check_sint(incfg_host_set_nstr(&val, addr, len),
	                equal,
	                -EINVAL);

	incfg_host_fini(&val);
}

CUTE_TEST(incfgut_host_set_nstr6_nok)
{
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok(":", 1));
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok(":::", 3));
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok("ff02:::", 7));
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok("fffff::2", 8));
	cute_expect_assertion(
		incfgut_host_test_set_nstr6_nok("f:f:f:f:f:f:f:f:f", 17));
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok("f:", 2));
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok(":f", 2));
	cute_expect_assertion(incfgut_host_test_set_nstr6_nok("", 0));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_nstr6_nok);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_host_pack6)
{
	struct dpack_encoder enc;
	char                 buff[INCFG_IP_ADDR_PACKSZ_MAX + 2];
	union incfg_host     addr;
	const uint8_t        ref[] = "\x01"
	                             "\xc4\x10"
	                             "\x00\x00\x00\x00\x00\x00\x00\x00"
	                             "\x00\x00\x00\x00\x00\x00\x00\x01";

	incfg_host_init(&addr);
	incfg_host_set_inet6(&addr, &in6addr_loopback);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	cute_check_sint(incfg_host_pack(&addr, &enc), equal, 0);
	cute_check_uint(dpack_encoder_space_used(&enc),
	                equal,
	                INCFG_ADDR_TYPE_PACKSZ + INCFG_IPV6_ADDR_PACKSZ);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - (INCFG_ADDR_TYPE_PACKSZ +
	                                INCFG_IPV6_ADDR_PACKSZ));
	cute_check_mem(buff, equal, ref, sizeof(ref) - 1);

	dpack_encoder_fini(&enc, DPACK_DONE);
	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_pack6_short)
{
	struct dpack_encoder enc;
	char                 buff = '\xff';
	char                 ref = '\x01';
	union incfg_host     addr;

	incfg_host_init(&addr);
	incfg_host_set_inet6(&addr, &in6addr_loopback);

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_host_pack(&addr, &enc), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 1);
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - 1);
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);
	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpack6)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x01"
	                              "\xc4\x10"
	                              "\x00\x00\x00\x00\x00\x00\x00\x00"
	                              "\x00\x00\x00\x00\x00\x00\x00\x01";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpack(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_uint(((const struct incfg_addr *)&addr)->type,
	                equal,
	                INCFG_ADDR_IPV6_TYPE);
	cute_check_mem(incfg_host_get_inet6(&addr),
	               equal,
	               &in6addr_loopback,
	               sizeof(in6addr_loopback));

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpack6_short)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x01\xc4\x10";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpack(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpack6_unxpct)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x03\xc4\x04\x7f\x00\x00\x01";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpack(&addr, &dec), equal, -EINVAL);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 6);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}






CUTE_TEST(incfgut_host_unpackn_check6)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x01"
	                              "\xc4\x10"
	                              "\x00\x00\x00\x00\x00\x00\x00\x00"
	                              "\x00\x00\x00\x00\x00\x00\x00\x01";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, 0);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_uint(((const struct incfg_addr *)&addr)->type,
	                equal,
	                INCFG_ADDR_IPV6_TYPE);
	cute_check_mem(incfg_host_get_inet6(&addr),
	               equal,
	               &in6addr_loopback,
	               sizeof(in6addr_loopback));

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpackn_check6_short)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x01\xc4\x10";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, -EPROTO);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

CUTE_TEST(incfgut_host_unpackn_check6_unxpct)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x03\xc4\x04\x7f\x00\x00\x01";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, -EINVAL);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 6);

	/*
	 * No need to check `addr' content since it may have been modified by
	 * mpack library and is left in an undefined state. See:
	 * mpack_read_bytes -> mpack_read_native -> mpack_read_native_straddle
	 */

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

#else  /* !defined(CONFIG_INCFG_IPV6) */

INCFGUT_NOIPV6_TEST(incfgut_host_set_inet6_assert);
INCFGUT_NOIPV6_TEST(incfgut_host_set_inet6);
INCFGUT_NOIPV6_TEST(incfgut_host_get_str6);
INCFGUT_NOIPV6_TEST(incfgut_host_check_str6_ok);
INCFGUT_NOIPV6_TEST(incfgut_host_check_str6_nok);
INCFGUT_NOIPV6_TEST(incfgut_host_check_nstr6_ok);
INCFGUT_NOIPV6_TEST(incfgut_host_check_nstr6_nok);
INCFGUT_NOIPV6_TEST(incfgut_host_set_str6_ok);
INCFGUT_NOIPV6_TEST(incfgut_host_set_str6_nok);
INCFGUT_NOIPV6_TEST(incfgut_host_set_nstr6_ok);
INCFGUT_NOIPV6_TEST(incfgut_host_set_nstr6_nok);
INCFGUT_NOIPV6_TEST(incfgut_host_pack6);
INCFGUT_NOIPV6_TEST(incfgut_host_pack6_short);
INCFGUT_NOIPV6_TEST(incfgut_host_unpack6);
INCFGUT_NOIPV6_TEST(incfgut_host_unpack6_short);
INCFGUT_NOIPV6_TEST(incfgut_host_unpack6_unxpct);
INCFGUT_NOIPV6_TEST(incfgut_host_unpackn_check6);
INCFGUT_NOIPV6_TEST(incfgut_host_unpackn_check6_short);
INCFGUT_NOIPV6_TEST(incfgut_host_unpackn_check6_unxpct);

#endif /* defined(CONFIG_INCFG_IPV6) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_get_str_assert)
{
	cute_expect_assertion(incfg_host_get_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_get_str_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_check_str_assert)
{
	cute_expect_assertion(incfg_host_check_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_check_str_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_check_nstr_assert)
{
	cute_expect_assertion(incfg_host_check_nstr(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_check_nstr_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_set_str_assert)
{
	union incfg_host addr;
	const char *     str = str;

	incfg_host_init(&addr);
	cute_expect_assertion(incfg_host_set_str(&addr, NULL));
	cute_expect_assertion(incfg_host_set_str(NULL, str));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_str_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_set_nstr_assert)
{
	union incfg_host addr;
	const char *     str = str;

	incfg_host_init(&addr);
	cute_expect_assertion(incfg_host_set_nstr(&addr, NULL, 1));
	cute_expect_assertion(incfg_host_set_nstr(NULL, str, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_set_nstr_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_pack_assert)
{
	struct dpack_encoder enc;
	union incfg_host     addr;

	incfg_host_init(&addr);

	cute_expect_assertion(incfg_host_pack(&addr, NULL));
	cute_expect_assertion(incfg_host_pack(NULL, &enc));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_pack_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_unpack_assert)
{
	struct dpack_decoder dec;
	union incfg_host     addr;

	incfg_host_init(&addr);

	cute_expect_assertion(incfg_host_unpack(&addr, NULL));
	cute_expect_assertion(incfg_host_unpack(NULL, &dec));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_unpack_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if defined(CONFIG_INCFG_DNAME)

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_host_unpack_inval_assert)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x02\xa1\x2d";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_expect_assertion(incfg_host_unpack(&addr, &dec));

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

INCFGUT_NOASSERT_TEST(incfgut_host_unpack_inval_assert);

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_host_unpackn_check_inval)
{
	struct dpack_decoder dec;
	const char           buff[] = "\x02\xa1\x2d";
	union incfg_host     addr;

	incfg_host_init(&addr);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_host_unpackn_check(&addr, &dec), equal, -EINVAL);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_uint(((const struct incfg_addr *)&addr)->type,
	                equal,
	                INCFG_ADDR_TYPE_NR);

	dpack_decoder_fini(&dec);

	incfg_host_fini(&addr);
}

#else  /* !defined(CONFIG_INCFG_DNAME) */

INCFGUT_NODNAME_TEST(incfgut_host_unpack_inval_assert);
INCFGUT_NODNAME_TEST(incfgut_host_unpackn_check_inval);

#endif /* defined(CONFIG_INCFG_DNAME) */

CUTE_GROUP(incfgut_host_group) = {
	CUTE_REF(incfgut_host_set_saddr4_assert),
	CUTE_REF(incfgut_host_set_saddr4),
	CUTE_REF(incfgut_host_set_inet4_assert),
	CUTE_REF(incfgut_host_set_inet4),

	CUTE_REF(incfgut_host_set_inet6_assert),
	CUTE_REF(incfgut_host_set_inet6),

	CUTE_REF(incfgut_host_get_str_assert),
	CUTE_REF(incfgut_host_get_str4),
	CUTE_REF(incfgut_host_get_str6),

	CUTE_REF(incfgut_host_check_str_assert),
	CUTE_REF(incfgut_host_check_str4_ok),
	CUTE_REF(incfgut_host_check_str4_nok),
	CUTE_REF(incfgut_host_check_str6_ok),
	CUTE_REF(incfgut_host_check_str6_nok),

	CUTE_REF(incfgut_host_check_nstr_assert),
	CUTE_REF(incfgut_host_check_nstr4_ok),
	CUTE_REF(incfgut_host_check_nstr4_nok),
	CUTE_REF(incfgut_host_check_nstr6_ok),
	CUTE_REF(incfgut_host_check_nstr6_nok),

	CUTE_REF(incfgut_host_set_str_assert),
	CUTE_REF(incfgut_host_set_str4_ok),
	CUTE_REF(incfgut_host_set_str4_nok),
	CUTE_REF(incfgut_host_set_str6_ok),
	CUTE_REF(incfgut_host_set_str6_nok),

	CUTE_REF(incfgut_host_set_nstr_assert),
	CUTE_REF(incfgut_host_set_nstr4_ok),
	CUTE_REF(incfgut_host_set_nstr4_nok),
	CUTE_REF(incfgut_host_set_nstr6_ok),
	CUTE_REF(incfgut_host_set_nstr6_nok),

	CUTE_REF(incfgut_host_pack_assert),
	CUTE_REF(incfgut_host_pack4),
	CUTE_REF(incfgut_host_pack4_short),
	CUTE_REF(incfgut_host_pack6),
	CUTE_REF(incfgut_host_pack6_short),

	CUTE_REF(incfgut_host_unpack_assert),
	CUTE_REF(incfgut_host_unpack4),
	CUTE_REF(incfgut_host_unpack4_short),
	CUTE_REF(incfgut_host_unpack4_unxpct),
	CUTE_REF(incfgut_host_unpack6),
	CUTE_REF(incfgut_host_unpack6_short),
	CUTE_REF(incfgut_host_unpack6_unxpct),

	CUTE_REF(incfgut_host_unpackn_check4),
	CUTE_REF(incfgut_host_unpackn_check4_short),
	CUTE_REF(incfgut_host_unpackn_check4_unxpct),
	CUTE_REF(incfgut_host_unpackn_check6),
	CUTE_REF(incfgut_host_unpackn_check6_short),
	CUTE_REF(incfgut_host_unpackn_check6_unxpct),

	CUTE_REF(incfgut_host_unpack_inval_assert),
	CUTE_REF(incfgut_host_unpackn_check_inval),
};

CUTE_SUITE_EXTERN(incfgut_host_suite,
                  incfgut_host_group,
                  incfgut_setup,
                  incfgut_teardown,
                  CUTE_DFLT_TMOUT);
