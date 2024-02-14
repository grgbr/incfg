/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "incfg/ip.h"
#include "common.h"
#include <dpack/codec.h>
#include <dpack/scalar.h>

static inline struct incfg_addr *
incfg_ip2addr(const union incfg_ip_addr * __restrict addr)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	return (struct incfg_addr *)addr;
#pragma GCC diagnostic pop
}

#if defined(CONFIG_INCFG_IPV4)

const struct in_addr *
incfg_ip_addr_get_inet4(const union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type == INCFG_ADDR_IPV4_TYPE);

	return incfg_ipv4_addr_get_inet(&addr->ipv4);
}

void
incfg_ip_addr_set_saddr4(union incfg_ip_addr * __restrict addr, in_addr_t saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);

	incfg_ip2addr(addr)->type = INCFG_ADDR_IPV4_TYPE;
	incfg_ipv4_addr_set_saddr(&addr->ipv4, saddr);
}

void
incfg_ip_addr_set_inet4(union incfg_ip_addr * __restrict  addr,
                        const struct in_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);

	incfg_ip2addr(addr)->type = INCFG_ADDR_IPV4_TYPE;
	incfg_ipv4_addr_set_inet(&addr->ipv4, inet);
}

#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)

const struct in6_addr *
incfg_ip_addr_get_inet6(const union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type == INCFG_ADDR_IPV6_TYPE);

	return incfg_ipv6_addr_get_inet(&addr->ipv6);
}

void
incfg_ip_addr_set_inet6(union incfg_ip_addr * __restrict   addr,
                        const struct in6_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);

	incfg_ip2addr(addr)->type = INCFG_ADDR_IPV6_TYPE;
	incfg_ipv6_addr_set_inet(&addr->ipv6, inet);
}

#endif /* defined(CONFIG_INCFG_IPV6) */

int
incfg_ip_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

#if defined(CONFIG_INCFG_IPV4)
	if (!incfg_ipv4_addr_check_str(string))
		return 0;
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	if (!incfg_ipv6_addr_check_str(string))
		return 0;
#endif /* defined(CONFIG_INCFG_IPV6) */

	return -EINVAL;
}

int
incfg_ip_addr_check_nstr(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

#if defined(CONFIG_INCFG_IPV4)
	if (!incfg_ipv4_addr_check_nstr(string, length))
		return 0;
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	if (!incfg_ipv6_addr_check_nstr(string, length))
		return 0;
#endif /* defined(CONFIG_INCFG_IPV6) */

	return -EINVAL;
}

const struct stroll_lvstr *
incfg_ip_addr_get_str(union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	switch (incfg_ip2addr(addr)->type) {
#if defined(CONFIG_INCFG_IPV4)
	case INCFG_ADDR_IPV4_TYPE:
		return incfg_ipv4_addr_get_str(&addr->ipv4);
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ipv6_addr_get_str(&addr->ipv6);
#endif /* defined(CONFIG_INCFG_IPV6) */

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_ip_addr_set_str(union incfg_ip_addr * __restrict  addr,
                      const char * __restrict           string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(string);

#if defined(CONFIG_INCFG_IPV4)
	if (!incfg_ipv4_addr_set_str(&addr->ipv4, string)) {
		incfg_ip2addr(addr)->type = INCFG_ADDR_IPV4_TYPE;
		return 0;
	}
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	if (!incfg_ipv6_addr_set_str(&addr->ipv6, string)) {
		incfg_ip2addr(addr)->type = INCFG_ADDR_IPV6_TYPE;
		return 0;
	}
#endif /* defined(CONFIG_INCFG_IPV6) */

	return -EINVAL;
}

int
incfg_ip_addr_set_nstr(union incfg_ip_addr * __restrict addr,
                       const char * __restrict          string,
                       size_t                           length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(string);

#if defined(CONFIG_INCFG_IPV4)
	if (!incfg_ipv4_addr_set_nstr(&addr->ipv4, string, length)) {
		incfg_ip2addr(addr)->type = INCFG_ADDR_IPV4_TYPE;
		return 0;
	}
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	if (!incfg_ipv6_addr_set_nstr(&addr->ipv6, string, length)) {
		incfg_ip2addr(addr)->type = INCFG_ADDR_IPV6_TYPE;
		return 0;
	}
#endif /* defined(CONFIG_INCFG_IPV6) */

	return -EINVAL;
}

size_t
incfg_ip_addr_packsz(const union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	switch (incfg_ip2addr(addr)->type) {
#if defined(CONFIG_INCFG_IPV4)
	case INCFG_ADDR_IPV4_TYPE:
		return INCFG_ADDR_TYPE_PACKSZ + INCFG_IPV4_ADDR_PACKSZ;
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	case INCFG_ADDR_IPV6_TYPE:
		return INCFG_ADDR_TYPE_PACKSZ + INCFG_IPV6_ADDR_PACKSZ;
#endif /* defined(CONFIG_INCFG_IPV6) */

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_ip_addr_pack(const union incfg_ip_addr * __restrict addr,
                   struct dpack_encoder *                 encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(encoder);

	int err;

	switch (incfg_ip2addr(addr)->type) {
#if defined(CONFIG_INCFG_IPV4)
	case INCFG_ADDR_IPV4_TYPE:
		err = dpack_encode_uint8(encoder,
		                         (uint8_t)INCFG_ADDR_IPV4_TYPE);
		if (err)
			return err;
		return incfg_ipv4_addr_pack(&addr->ipv4, encoder);
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	case INCFG_ADDR_IPV6_TYPE:
		err = dpack_encode_uint8(encoder,
		                         (uint8_t)INCFG_ADDR_IPV6_TYPE);
		if (err)
			return err;
		return incfg_ipv6_addr_pack(&addr->ipv6, encoder);
#endif /* defined(CONFIG_INCFG_IPV4) */

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_ip_addr_unpack(union incfg_ip_addr * __restrict addr,
                     struct dpack_decoder *           decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(decoder);

	int     err;
	uint8_t type;

	err = dpack_decode_uint8(decoder, &type);
	if (err)
		return err;

	switch ((enum incfg_addr_type)type) {
#if defined(CONFIG_INCFG_IPV4)
	case INCFG_ADDR_IPV4_TYPE:
		err = incfg_ipv4_addr_unpack(&addr->ipv4, decoder);
		if (err)
			return err;
		incfg_ip2addr(addr)->type = INCFG_ADDR_IPV4_TYPE;
		return 0;
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
	case INCFG_ADDR_IPV6_TYPE:
		err = incfg_ipv6_addr_unpack(&addr->ipv6, decoder);
		if (err)
			return err;
		incfg_ip2addr(addr)->type = INCFG_ADDR_IPV6_TYPE;
		return 0;
#endif /* defined(CONFIG_INCFG_IPV4) */

	default:
		return -EINVAL;
	}

	unreachable();
}

void
incfg_ip_addr_init(union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	memset(addr, 0, sizeof(*addr));
	incfg_ip2addr(addr)->type = INCFG_ADDR_TYPE_NR;
	stroll_lvstr_init(&incfg_ip2addr(addr)->lvstr);
}

void
incfg_ip_addr_fini(union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_ip2addr(addr)->type <= INCFG_ADDR_TYPE_NR);

	stroll_lvstr_fini(&incfg_ip2addr(addr)->lvstr);
}
