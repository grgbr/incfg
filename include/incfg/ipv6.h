/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * IPv6 interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      06 Feb 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 *
 * Interface to work with IPv6 addresses inspired by the `ipv6-address-no-zone'
 * typedef defined into section 4 of RFC 6991.
 * When encoded as a string, this interface supports IPv6 addresses represented
 * in dotted-quad notation with no additional zone index.
 *
 * For more informations, refer to :
 * - RFC 6991: Common YANG Data Types
 */

#ifndef _INCFG_IPV6_H
#define _INCFG_IPV6_H

#include <incfg/cdefs.h>
#include <netinet/in.h>
#include <dpack/bin.h>
#include <stdlib.h>

#define INCFG_IPV6_ADDR_STRSZ_MAX \
	INET6_ADDRSTRLEN

#define INCFG_IPV6_ADDR_STRLEN_MAX \
	(INCFG_IPV6_ADDR_STRSZ_MAX - 1)

#define INCFG_IPV6_ADDR_PACKSZ \
	DPACK_BIN_SIZE(sizeof_member(struct in6_addr, s6_addr))

extern void
incfg_ipv6_addr_set_inet(struct in6_addr * __restrict       addr,
                         const struct in6_addr * __restrict inet)
	__incfg_export;

extern const char *
incfg_ipv6_addr_get_str(const struct in6_addr * __restrict addr,
                        char * __restrict                  string)
	__incfg_export;

extern int
incfg_ipv6_addr_check_str(const char * __restrict string)
	__incfg_export;

extern int
incfg_ipv6_addr_check_nstr(const char * __restrict string, size_t length)
	__incfg_export;

extern int
incfg_ipv6_addr_set_str(struct in6_addr * __restrict addr,
                        const char * __restrict      string)
	__incfg_export;

extern int
incfg_ipv6_addr_set_nstr(struct in6_addr * __restrict addr,
                         const char * __restrict      string,
                         size_t                       length)
	__incfg_export;

extern int
incfg_ipv6_addr_pack(const struct in6_addr * __restrict addr,
                     struct dpack_encoder *             encoder)
	__incfg_export;

extern ssize_t
incfg_ipv6_addr_unpack(struct in6_addr * __restrict addr,
                       struct dpack_decoder *       decoder)
	__incfg_export;

static inline ssize_t
incfg_ipv6_addr_unpackn_check(struct in6_addr * __restrict addr,
                              struct dpack_decoder *       decoder)
{
	/* No particular data consistency check to do... */
	return incfg_ipv6_addr_unpack(addr, decoder);
}

#if defined(CONFIG_INCFG_ASSERT_API)

extern size_t
incfg_ipv6_addr_packsz(const struct in6_addr * __restrict addr)
	__incfg_nonull(1)
	__incfg_const
	__incfg_nothrow
	__leaf
	__warn_result
	__incfg_export;

extern void
incfg_ipv6_addr_init(struct in6_addr * __restrict addr)
	__incfg_export;

extern void
incfg_ipv6_addr_fini(struct in6_addr * __restrict addr)
	__incfg_export;

#else  /* defined(CONFIG_INCFG_ASSERT_API) */

static inline
size_t __incfg_nonull(1) __incfg_const __incfg_nothrow __warn_result
incfg_ipv6_addr_packsz(const struct in6_addr * __restrict addr __unused)
{
	return INCFG_IPV6_ADDR_PACKSZ;
}

static inline void
incfg_ipv6_addr_init(struct in6_addr * __restrict addr __unused)
{
}

static inline void
incfg_ipv6_addr_fini(struct in6_addr * __restrict addr __unused)
{
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#endif /* _INCFG_IPV6_H */
