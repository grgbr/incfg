/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "incfg/host.h"
#include "ip.h"

static inline struct incfg_addr *
incfg_host2addr(const union incfg_host * __restrict host)
{
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
	return (struct incfg_addr *)host;
#pragma GCC diagnostic pop
}

#if defined(CONFIG_INCFG_IPV4)

const struct in_addr *
incfg_host_get_inet4(const union incfg_host * __restrict host)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type == INCFG_ADDR_IPV4_TYPE);

	return incfg_ip_addr_get_inet4(&host->ip);
}

void
incfg_host_set_saddr4(union incfg_host * __restrict host, in_addr_t saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type <= INCFG_ADDR_TYPE_NR);

	incfg_ip_addr_set_saddr4(&host->ip, saddr);
}

void
incfg_host_set_inet4(union incfg_host * __restrict     host,
                     const struct in_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type <= INCFG_ADDR_TYPE_NR);

	incfg_ip_addr_set_inet4(&host->ip, inet);
}

#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)

const struct in6_addr *
incfg_host_get_inet6(const union incfg_host * __restrict host)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type == INCFG_ADDR_IPV6_TYPE);

	return incfg_ip_addr_get_inet6(&host->ip);
}

void
incfg_host_set_inet6(union incfg_host * __restrict      host,
                     const struct in6_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type <= INCFG_ADDR_TYPE_NR);

	incfg_ip_addr_set_inet6(&host->ip, inet);
}

#endif /* defined(CONFIG_INCFG_IPV6) */

int
incfg_host_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

#if defined(CONFIG_INCFG_IP)
	if (!incfg_ip_addr_check_str(string))
		return 0;
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	if (!incfg_dname_check(string))
		return 0;
#endif /* defined(CONFIG_INCFG_DNAME) */

	return -EINVAL;
}

int
incfg_host_check_nstr(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

#if defined(CONFIG_INCFG_IP)
	if (!incfg_ip_addr_check_nstr(string, length))
		return 0;
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	if (!incfg_dname_ncheck(string, length))
		return 0;
#endif /* defined(CONFIG_INCFG_DNAME) */

	return -EINVAL;
}

const struct stroll_lvstr *
incfg_host_get_str(union incfg_host * __restrict host)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);

	switch (incfg_host2addr(host)->type) {
#if defined(CONFIG_INCFG_IP)
	case INCFG_ADDR_IPV4_TYPE:
	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ip_addr_get_str(&host->ip);
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	case INCFG_ADDR_DNAME_TYPE:
		return incfg_dname_get(&host->dname);
#endif /* defined(CONFIG_INCFG_DNAME) */

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_host_set_str(union incfg_host * __restrict host,
                   const char * __restrict       string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(string);
	incfg_assert_api(!incfg_host_check_str(string));

	int ret = -EINVAL;

#if defined(CONFIG_INCFG_IP)
	if (!incfg_ip_addr_set_str(&host->ip, string))
		return 0;
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	ret = incfg_dname_set(&host->dname, string);
	if (ret)
		return ret;

	incfg_host2addr(host)->type = INCFG_ADDR_DNAME_TYPE;
#endif /* defined(CONFIG_INCFG_DNAME) */

	incfg_assert_api(ret != -EINVAL);

	return ret;
}

int
incfg_host_set_nstr(union incfg_host * __restrict host,
                    const char * __restrict       string,
                    size_t                        length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_api(string);
	incfg_assert_api(!incfg_host_check_nstr(string, length));

	int ret = -EINVAL;

#if defined(CONFIG_INCFG_IP)
	if (!incfg_ip_addr_set_nstr(&host->ip, string, length))
		return 0;
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	ret = incfg_dname_nset(&host->dname, string, length);
	if (ret)
		return ret;

	incfg_host2addr(host)->type = INCFG_ADDR_DNAME_TYPE;
#endif /* defined(CONFIG_INCFG_DNAME) */

	incfg_assert_api(ret != -EINVAL);

	return ret;
}

size_t
incfg_host_packsz(const union incfg_host * __restrict host)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);

	switch (incfg_host2addr(host)->type) {
#if defined(CONFIG_INCFG_IP)
	case INCFG_ADDR_IPV4_TYPE:
	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ip_addr_packsz(&host->ip);
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	case INCFG_ADDR_DNAME_TYPE:
		return incfg_dname_packsz(&host->dname);
#endif /* defined(CONFIG_INCFG_DNAME) */

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_host_pack(const union incfg_host * __restrict host,
                struct dpack_encoder *              encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(encoder);

	switch (incfg_host2addr(host)->type) {
#if defined(CONFIG_INCFG_IP)
	case INCFG_ADDR_IPV4_TYPE:
	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ip_addr_pack(&host->ip, encoder);
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	case INCFG_ADDR_DNAME_TYPE:
		return incfg_dname_pack(&host->dname, encoder);
#endif /* defined(CONFIG_INCFG_DNAME) */

	default:
		incfg_assert_api(0);
	}

	unreachable();
}

int
incfg_host_unpack(union incfg_host * __restrict host,
                  struct dpack_decoder *        decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(decoder);

	int     err;
	uint8_t type;

	err = dpack_decode_uint8(decoder, &type);
	if (err)
		return err;

	switch ((enum incfg_addr_type)type) {
#if defined(CONFIG_INCFG_IP)
	case INCFG_ADDR_IPV4_TYPE:
	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ip_addr_decode(&host->ip,
		                            (enum incfg_addr_type)type,
		                            decoder);
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	case INCFG_ADDR_DNAME_TYPE:
		err = incfg_dname_unpack(&host->dname, decoder);
		if (err)
			return err;
		incfg_host2addr(host)->type = INCFG_ADDR_DNAME_TYPE;
		return 0;
#endif /* defined(CONFIG_INCFG_DNAME) */

	default:
		return -EINVAL;
	}

	unreachable();
}

int
incfg_host_unpackn_check(union incfg_host * __restrict host,
                         struct dpack_decoder *        decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(decoder);

	int     err;
	uint8_t type;

	err = dpack_decode_uint8(decoder, &type);
	if (err)
		return err;

	switch ((enum incfg_addr_type)type) {
#if defined(CONFIG_INCFG_IP)
	case INCFG_ADDR_IPV4_TYPE:
	case INCFG_ADDR_IPV6_TYPE:
		/*
		 * Check and no check versions of IP address unpacking are
		 * identical...
		 */
		return incfg_ip_addr_decode(&host->ip,
		                            (enum incfg_addr_type)type,
		                            decoder);
#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
	case INCFG_ADDR_DNAME_TYPE:
		err = incfg_dname_unpackn_check(&host->dname, decoder);
		if (err)
			return err;
		incfg_host2addr(host)->type = INCFG_ADDR_DNAME_TYPE;
		return 0;
#endif /* defined(CONFIG_INCFG_DNAME) */

	default:
		return -EINVAL;
	}

	unreachable();
}

void
incfg_host_init(union incfg_host * __restrict host)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);

	memset(host, 0, sizeof(*host));
	incfg_host2addr(host)->type = INCFG_ADDR_TYPE_NR;
	stroll_lvstr_init(&incfg_host2addr(host)->lvstr);
}

void
incfg_host_fini(union incfg_host * __restrict host)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(host);
	incfg_assert_api(incfg_host2addr(host)->type <= INCFG_ADDR_TYPE_NR);

	stroll_lvstr_fini(&incfg_host2addr(host)->lvstr);
}
