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

#include <incfg/common.h>
#include <netinet/in.h>
#include <dpack/bin.h>
#include <stdlib.h>

#define INCFG_ADDR_STRSZ_MAX \
	STROLL_CONST_MAX(INCFG_IPV4_ADDR_STRSZ_MAX, INCFG_IPV6_ADDR_STRSZ_MAX)

#define INCFG_ADDR_STRLEN_MAX \
	(INCFG_ADDR_STRSZ_MAX - 1)

union incfg_ip_addr {
	struct incfg_ipv4_addr ipv4;
	struct incfg_ipv6_addr ipv6;
};

extern void
incfg_addr_set_saddr4(struct incfg_addr * __restrict addr,
                         in_addr_t                         saddr)

extern void
incfg_addr_set_inet4(struct incfg_addr * __restrict addr,
                        const struct in_addr * __restrict inet)
	__incfg_export;

extern void
incfg_addr_set_inet6(struct incfg_addr * __restrict  addr,
                        const struct in6_addr * __restrict inet)
	__incfg_export;

extern const char *
incfg_addr_get_str(const struct incfg_addr * __restrict addr)
	__incfg_export;

extern size_t
incfg_addr_get_len(const struct incfg_addr * __restrict addr)
	__incfg_export;

extern int
incfg_addr_check_str(const char * __restrict string)
	__incfg_export;

extern int
incfg_addr_check_nstr(const char * __restrict string, size_t length)
	__incfg_export;

extern int
incfg_addr_set_str(struct incfg_addr * __restrict addr,
                      const char * __restrict           string)
	__incfg_export;

extern int
incfg_addr_set_nstr(struct incfg_addr * __restrict addr,
                       const char * __restrict           string,
                       size_t                            length)
	__incfg_export;

extern size_t
incfg_addr_packsz(const struct incfg_addr * __restrict addr)
	__incfg_nonull(1)
	__incfg_const
	__incfg_nothrow
	__leaf
	__warn_result
	__incfg_export;

extern int
incfg_addr_pack(const struct incfg_addr * __restrict addr,
                   struct dpack_encoder *                  encoder)
	__incfg_export;

extern int
incfg_addr_unpack(struct incfg_addr * __restrict addr,
                     struct dpack_decoder *            decoder)
	__incfg_export;

static inline int
incfg_addr_unpackn_check(struct incfg_addr * __restrict addr,
                            struct dpack_decoder *            decoder)
{
	/* No particular data consistency check to do... */
	return incfg_addr_unpack(addr, decoder);
}

#if defined(CONFIG_INCFG_ASSERT_API)

extern void
incfg_addr_init(struct incfg_addr * __restrict addr)
	__incfg_export;

extern void
incfg_addr_fini(struct incfg_addr * __restrict addr)
	__incfg_export;

#else  /* defined(CONFIG_INCFG_ASSERT_API) */

static inline void
incfg_addr_init(struct incfg_addr * __restrict addr)
{
	addr->type = INCFG_ADDR_TYPE_NR;
}

static inline void
incfg_addr_fini(struct incfg_addr * __restrict addr __unused)
{
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#endif /* _INCFG_IP_H */
