/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * IP interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      31 Jan 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 *
 * Interface to work with IP v4 or v6 addresses inspired by the
 * `ipv-address-no-zone' typedef defined into section 4 of RFC 6991.
 *
 * For more informations, refer to :
 * - RFC 6991: Common YANG Data Types
 */

#ifndef _INCFG_IP_H
#define _INCFG_IP_H

#include <incfg/priv/cdefs.h>

#if defined(CONFIG_INCFG_IPV4)
#include <incfg/ipv4.h>
#endif /* defined(CONFIG_INCFG_IPV4) */
#if defined(CONFIG_INCFG_IPV6)
#include <incfg/ipv6.h>
#endif /* defined(CONFIG_INCFG_IPV6) */

union incfg_ip_addr {
#if defined(CONFIG_INCFG_IPV4)
	struct incfg_ipv4_addr ipv4;
#endif /* defined(CONFIG_INCFG_IPV4) */
#if defined(CONFIG_INCFG_IPV6)
	struct incfg_ipv6_addr ipv6;
#endif /* defined(CONFIG_INCFG_IPV6) */
};

#if defined(CONFIG_INCFG_IPV4)
#define INCFG_ADDR_STRSZ_MAX   INCFG_IPV4_ADDR_STRSZ_MAX 
#define _INCFG_ADDR_PACKSZ_MIN INCFG_IPV4_ADDR_PACKSZ
#define _INCFG_ADDR_PACKSZ_MAX INCFG_IPV4_ADDR_PACKSZ
#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)
#undef INCFG_ADDR_STRSZ_MAX
#define INCFG_ADDR_STRSZ_MAX   INCFG_IPV6_ADDR_STRSZ_MAX 
#undef _INCFG_ADDR_PACKSZ_MIN
#define _INCFG_ADDR_PACKSZ_MIN INCFG_IPV6_ADDR_PACKSZ
#undef _INCFG_ADDR_PACKSZ_MAX
#define _INCFG_ADDR_PACKSZ_MAX INCFG_IPV6_ADDR_PACKSZ
#endif /* defined(CONFIG_INCFG_IPV6) */

#define INCFG_ADDR_STRLEN_MAX \
	(INCFG_ADDR_STRSZ_MAX - 1)

#define INCFG_IP_ADDR_PACKSZ_MIN \
	(INCFG_ADDR_TYPE_PACKSZ + _INCFG_ADDR_PACKSZ_MIN)

#define INCFG_IP_ADDR_PACKSZ_MAX \
	(INCFG_ADDR_TYPE_PACKSZ + _INCFG_ADDR_PACKSZ_MAX)

#if defined(CONFIG_INCFG_IPV4)

extern const struct in_addr *
incfg_ip_addr_get_inet4(const union incfg_ip_addr * __restrict addr)
	__incfg_export;

extern void
incfg_ip_addr_set_saddr4(union incfg_ip_addr * __restrict addr,
                         in_addr_t                        saddr)
	__incfg_export;

extern void
incfg_ip_addr_set_inet4(union incfg_ip_addr * __restrict  addr,
                        const struct in_addr * __restrict inet)
	__incfg_export;

#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)

extern const struct in6_addr *
incfg_ip_addr_get_inet6(const union incfg_ip_addr * __restrict addr)
	__incfg_export;

extern void
incfg_ip_addr_set_inet6(union incfg_ip_addr * __restrict   addr,
                        const struct in6_addr * __restrict inet)
	__incfg_export;

#endif /* defined(CONFIG_INCFG_IPV6) */

extern int
incfg_ip_addr_check_str(const char * __restrict string)
	__incfg_export;

extern int
incfg_ip_addr_check_nstr(const char * __restrict string, size_t length)
	__incfg_export;

extern const struct stroll_lvstr *
incfg_ip_addr_get_str(union incfg_ip_addr * __restrict addr)
	__incfg_export;

extern int
incfg_ip_addr_set_str(union incfg_ip_addr * __restrict  addr,
                      const char * __restrict           string)
	__incfg_export;

extern int
incfg_ip_addr_set_nstr(union incfg_ip_addr * __restrict addr,
                       const char * __restrict          string,
                       size_t                           length)
	__incfg_export;

extern size_t
incfg_ip_addr_packsz(const union incfg_ip_addr * __restrict addr)
	__incfg_export;

extern int
incfg_ip_addr_pack(const union incfg_ip_addr * __restrict addr,
                   struct dpack_encoder *                 encoder)
	__incfg_export;

extern int
incfg_ip_addr_unpack(union incfg_ip_addr * __restrict addr,
                     struct dpack_decoder *           decoder)
	__incfg_export;

static inline int
incfg_ip_addr_unpackn_check(union incfg_ip_addr * __restrict addr,
                            struct dpack_decoder *           decoder)
{
	/* No particular data consistency check to do... */
	return incfg_ip_addr_unpack(addr, decoder);
}

extern void
incfg_ip_addr_init(union incfg_ip_addr * __restrict addr)
	__incfg_export;

extern void
incfg_ip_addr_fini(union incfg_ip_addr * __restrict addr)
	__incfg_export;

#endif /* _INCFG_IP_H */
