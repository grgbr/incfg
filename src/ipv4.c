/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "incfg/ipv4.h"
#include "addr.h"
#include <dpack/codec.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Use Glibc's inet_pton() primitive here as it is about 15 times as fast as the
 * Perl regular expression used to parse IPv4 that is defined into RFC 6991 :
 *
 * #define INCFG_IPV4_ADDR_PATTERN \
 * 	"(?:(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}" \
 * 	"(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
 *
 * The regex above is a slightly modified version of `ipv4-address' Perl regular
 * expression defined into RFC 6991 (Common YANG Data Types) with capture groups
 * disabled and no support for IPv4 address zone matching...
 */

static int
incfg_ipv4_addr_parse_str(struct in_addr * __restrict addr,
                          const char * __restrict     string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(string);

	int ret;

	ret = inet_pton(AF_INET, string, addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

void
incfg_ipv4_addr_set_saddr(struct incfg_ipv4_addr * __restrict addr,
                          in_addr_t                           saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	if (addr->inet.s_addr != saddr) {
		incfg_addr_clear_str(&addr->base);
		addr->inet.s_addr = htonl(saddr);
	}
}

void
incfg_ipv4_addr_set_inet(struct incfg_ipv4_addr * __restrict addr,
                         const struct in_addr * __restrict   inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	incfg_ipv4_addr_set_saddr(addr, inet->s_addr);
}

const struct stroll_lvstr *
incfg_ipv4_addr_get_str(struct incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	if (!stroll_lvstr_cstr(&addr->base.lvstr)) {
		char *       str;
		const char * ptr __unused;

		str = malloc(INET_ADDRSTRLEN);
		if (!str)
			return NULL;

		ptr = inet_ntop(AF_INET, &addr->inet, str, sizeof(str));
		incfg_assert_intern(ptr == str);

		incfg_addr_set_str(&addr->base, str);
	}

	return &addr->base.lvstr;
}

int
incfg_ipv4_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in_addr addr;

	return incfg_ipv4_addr_parse_str(&addr, string);
}

int
incfg_ipv4_addr_check_nstr(const char * __restrict string,
                           size_t                  length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INET_ADDRSTRLEN) == length);

	return incfg_ipv4_addr_check_str(string);
}

int
incfg_ipv4_addr_set_str(struct incfg_ipv4_addr * __restrict addr,
                        const char * __restrict             string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	struct in_addr tmp;
	int            err;

	err = incfg_ipv4_addr_parse_str(&tmp, string);
	if (err)
		return err;

	incfg_ipv4_addr_set_inet(addr, &tmp);

	return 0;
}

int
incfg_ipv4_addr_set_nstr(struct incfg_ipv4_addr * __restrict addr,
                         const char * __restrict             string,
                         size_t                              length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INET_ADDRSTRLEN) == length);

	return incfg_ipv4_addr_set_str(addr, string);
}

int
incfg_ipv4_addr_pack(const struct incfg_ipv4_addr * __restrict addr,
                     struct dpack_encoder *                    encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(encoder);

	return dpack_encode_bin(encoder,
	                        (const char *)&addr->inet.s_addr,
	                        sizeof(addr->inet.s_addr));
}

int
incfg_ipv4_addr_unpack(struct incfg_ipv4_addr * __restrict addr,
                       struct dpack_decoder *              decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(decoder);

	ssize_t   err;
	in_addr_t saddr;

	err = dpack_decode_bincpy_equ(decoder, sizeof(saddr), (char *)&saddr);
	if (err < 0)
		return (int)err;

	incfg_ipv4_addr_set_saddr(addr, saddr);

	return 0;
}

void
incfg_ipv4_addr_init(struct incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	incfg_addr_init(&addr->base, INCFG_ADDR_IPV4_TYPE);
}

void
incfg_ipv4_addr_fini(struct incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	incfg_addr_fini(&addr->base);
}
