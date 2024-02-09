/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "incfg/ip.h"
#include "addr.h"
#include <dpack/codec.h>

const struct in_addr *
incfg_ip_addr_get_inet4(const union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_addr_get_type((const struct incfg_addr *)addr) ==
	                 INCFG_ADDR_IPV4_TYPE);

	return incfg_ipv4_addr_get_inet(&addr->ipv4);
}

void
incfg_ip_addr_set_saddr4(union incfg_ip_addr * __restrict addr, in_addr_t saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	incfg_addr_set_type(&addr->ipv4.base, INCFG_ADDR_IPV4_TYPE);
	incfg_ipv4_addr_set_saddr(&addr->ipv4, saddr);
}

void
incfg_ip_addr_set_inet4(union incfg_ip_addr * __restrict  addr,
                        const struct in_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	incfg_addr_set_type(&addr->ipv4.base, INCFG_ADDR_IPV4_TYPE);
	incfg_ipv4_addr_set_inet(&addr->ipv4, inet);
}

const struct in6_addr *
incfg_ip_addr_get_inet6(const union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(incfg_addr_get_type((const struct incfg_addr *)addr) ==
	                 INCFG_ADDR_IPV6_TYPE);

	return incfg_ipv6_addr_get_inet(&addr->ipv6);
}

void
incfg_ip_addr_set_inet6(union incfg_ip_addr * __restrict   addr,
                        const struct in6_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	incfg_addr_set_type(&addr->ipv6.base, INCFG_ADDR_IPV6_TYPE);
	incfg_ipv6_addr_set_inet(&addr->ipv6, inet);
}

const struct stroll_lvstr *
incfg_ip_addr_get_str(union incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	switch (incfg_addr_get_type((const struct incfg_addr *)addr)) {
	case INCFG_ADDR_IPV4_TYPE:
		return incfg_ipv4_addr_get_str(&addr->ipv4);

	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ipv6_addr_get_str(&addr->ipv6);

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_ip_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	if (!incfg_ipv4_addr_check_str(string))
		return 0;

	return incfg_ipv6_addr_check_str(string);
}

int
incfg_ip_addr_check_nstr(const char * __restrict string, size_t length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INCFG_ADDR_STRLEN_MAX) == length);

	return incfg_ip_addr_check_str(string);
}

int
incfg_ip_addr_set_str(union incfg_ip_addr * __restrict  addr,
                      const char * __restrict           string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	if (!incfg_ipv4_addr_set_str(&addr->ipv4, string)) {
		incfg_addr_set_type(&addr->ipv4.base, INCFG_ADDR_IPV4_TYPE);
		return 0;
	}

	if (!incfg_ipv6_addr_set_str(&addr->ipv6, string)) {
		incfg_addr_set_type(&addr->ipv6.base, INCFG_ADDR_IPV6_TYPE);
		return 0;
	}

	return -EINVAL;
}

int
incfg_ip_addr_set_nstr(union incfg_ip_addr * __restrict addr,
                       const char * __restrict          string,
                       size_t                           length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INCFG_ADDR_STRLEN_MAX) == length);

	return incfg_ip_addr_set_str(addr, string);
}
