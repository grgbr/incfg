/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * IPv4 interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      31 Jan 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _INCFG_IPV4_H
#define _INCFG_IPV4_H

#include <incfg/cdefs.h>
#include <netinet/in.h>
#include <dpack/bin.h>
#include <stdlib.h>

#define INCFG_IPV4_ADDR_STRSZ_MAX \
	INET_ADDRSTRLEN

#define INCFG_IPV4_ADDR_STRLEN_MAX \
	(INCFG_IPV4_ADDR_STRSZ_MAX - 1)

#define INCFG_IPV4_ADDR_PACKSZ \
	DPACK_BIN_SIZE(sizeof_member(struct in_addr, s_addr))

extern int
incfg_ipv4_addr_check_str(const char * __restrict string)
	__incfg_export;

extern int
incfg_ipv4_addr_check_nstr(const char * __restrict string, size_t length)
	__incfg_export;

extern void
incfg_ipv4_addr_set_saddr(struct in_addr * __restrict addr, in_addr_t saddr)
	__incfg_export;

extern void
incfg_ipv4_addr_set_inet(struct in_addr * __restrict       addr,
                         const struct in_addr * __restrict inet)
	__incfg_export;

extern const char *
incfg_ipv4_addr_get_str(const struct in_addr * __restrict addr,
                        char * __restrict                 string)
	__incfg_export;

extern int
incfg_ipv4_addr_set_str(struct in_addr * __restrict addr,
                        const char * __restrict     string)
	__incfg_export;

extern int
incfg_ipv4_addr_set_nstr(struct in_addr * __restrict addr,
                         const char * __restrict     string,
                         size_t                      length)
	__incfg_export;

static inline
size_t __incfg_nonull(1) __incfg_const __incfg_nothrow __warn_result
incfg_ipv4_addr_packsz(const struct in_addr * __restrict addr __unused)
{
	return INCFG_IPV4_ADDR_PACKSZ;
}

extern int
incfg_ipv4_addr_pack(const struct in_addr * __restrict addr,
                     struct dpack_encoder *            encoder)
	__incfg_export;

extern ssize_t
incfg_ipv4_addr_unpack(struct in_addr * __restrict addr,
                       struct dpack_decoder *      decoder)
	__incfg_export;

static inline ssize_t
incfg_ipv4_addr_unpackn_check(struct in_addr * __restrict addr,
                              struct dpack_decoder *      decoder)
{
	return incfg_ipv4_addr_unpack(addr, decoder);
}

static inline void
incfg_ipv4_addr_init(struct in_addr * __restrict addr __unused)
{
}

static inline void
incfg_ipv4_addr_fini(struct in_addr * __restrict addr __unused)
{
}

#endif /* _INCFG_IPV4_H */
