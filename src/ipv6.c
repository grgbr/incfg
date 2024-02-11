/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "incfg/ipv6.h"
#include "common.h"
#include <dpack/codec.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Use Glibc's inet_pton() primitive here as it is much faster than the
 * `ipv6-address' Perl regular expression used to parse IPv6 that is defined
 * into RFC 6991.
 */

static int
incfg_ipv6_addr_parse_str(struct in6_addr * __restrict addr,
                          const char * __restrict      string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(string);

	int ret;

	ret = inet_pton(AF_INET6, string, addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

void
incfg_ipv6_addr_set_inet(struct incfg_ipv6_addr * __restrict addr,
                         const struct in6_addr * __restrict  inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(inet);

	if (memcmp(&addr->inet, inet, sizeof(addr->inet))) {
		stroll_lvstr_drop(&addr->base.lvstr);
		addr->inet = *inet;
	}
}

int
incfg_ipv6_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in6_addr addr;

	return incfg_ipv6_addr_parse_str(&addr, string);
}

int
incfg_ipv6_addr_check_nstr(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	if (!length || (length > INCFG_IPV6_ADDR_STRLEN_MAX))
		return -EINVAL;

	if (string[length] != '\0') {
		char str[INCFG_IPV6_ADDR_STRSZ_MAX];
		
		memcpy(str, string, length);
		str[length] = '\0';

		return incfg_ipv6_addr_check_str(str);
	}
	else
		return incfg_ipv6_addr_check_str(string);
}

const struct stroll_lvstr *
incfg_ipv6_addr_get_str(struct incfg_ipv6_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type == INCFG_ADDR_IPV6_TYPE);

	if (!stroll_lvstr_cstr(&addr->base.lvstr)) {
		char *       str;
		const char * ptr __unused;
		int          err __unused;

		str = malloc(INCFG_IPV6_ADDR_STRSZ_MAX);
		if (!str)
			return NULL;

		ptr = inet_ntop(AF_INET6,
		                &addr->inet,
		                str,
		                INCFG_IPV6_ADDR_STRSZ_MAX);
		incfg_assert_intern(ptr == str);

		err = stroll_lvstr_cede(&addr->base.lvstr, str);
		incfg_assert_intern(!err);
	}
	else
		incfg_assert_intern(
			!incfg_ipv6_addr_check_str(
				stroll_lvstr_cstr(&addr->base.lvstr)));

	return &addr->base.lvstr;
}

int
incfg_ipv6_addr_set_str(struct incfg_ipv6_addr * __restrict addr,
                        const char * __restrict             string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(string);

	struct in6_addr tmp;
	int             err;

	err = incfg_ipv6_addr_parse_str(&tmp, string);
	if (err)
		return err;

	incfg_ipv6_addr_set_inet(addr, &tmp);

	return 0;
}

int
incfg_ipv6_addr_set_nstr(struct incfg_ipv6_addr * __restrict addr,
                         const char * __restrict             string,
                         size_t                              length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(string);

	if (!length || (length > INCFG_IPV6_ADDR_STRLEN_MAX))
		return -EINVAL;

	if (string[length] != '\0') {
		char str[INCFG_IPV6_ADDR_STRSZ_MAX];
		
		memcpy(str, string, length);
		str[length] = '\0';

		return incfg_ipv6_addr_set_str(addr, str);
	}
	else
		return incfg_ipv6_addr_set_str(addr, string);
}

int
incfg_ipv6_addr_pack(const struct incfg_ipv6_addr * __restrict addr,
                     struct dpack_encoder *                    encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type == INCFG_ADDR_IPV6_TYPE);
	incfg_assert_api(encoder);

	return dpack_encode_bin(encoder,
	                        (const char *)&addr->inet.s6_addr,
	                        sizeof(addr->inet.s6_addr));
}

int
incfg_ipv6_addr_unpack(struct incfg_ipv6_addr * __restrict addr,
                       struct dpack_decoder *              decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type == INCFG_ADDR_IPV6_TYPE);
	incfg_assert_api(decoder);

	ssize_t         err;
	struct in6_addr inet;

	err = dpack_decode_bincpy_equ(decoder,
	                              sizeof(inet.s6_addr),
	                              (char *)inet.s6_addr);
	if (err < 0)
		return (int)err;

	incfg_ipv6_addr_set_inet(addr, &inet);

	return 0;
}

void
incfg_ipv6_addr_init(struct incfg_ipv6_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	addr->base.type = INCFG_ADDR_IPV6_TYPE;
	stroll_lvstr_init(&addr->base.lvstr);
	addr->inet = in6addr_any;
}

void
incfg_ipv6_addr_fini(struct incfg_ipv6_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(addr->base.type == INCFG_ADDR_IPV6_TYPE);

	stroll_lvstr_fini(&addr->base.lvstr);
}
