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

union incfg_ipv4_addr {
	struct in_addr inet;
	uint8_t        bytes[sizeof(in_addr_t)];
};

#define INCFG_IPV4_ADDR_INIT_SADDR(_saddr) \
	{ .inet.s_addr = htonl(_saddr) }

#define INCFG_IPV4_ADDR_INIT_INET(_inet) \
	{ .inet = _inet }

#define INCFG_IPV4_ADDR_STRSZ \
	INET_ADDRSTRLEN

#define INCFG_IPV4_ADDR_STRLEN \
	(INCFG_IPV4_ADDR_STRSZ - 1)

#define INCFG_IPV4_ADDR_PACKSZ \
	DPACK_BIN_SIZE(sizeof_member(union incfg_ipv4_addr, bytes))

extern int
incfg_ipv4_addr_check_str(const char * __restrict string) __incfg_export;

extern const char *
incfg_ipv4_addr_str(const union incfg_ipv4_addr * __restrict addr,
                    char * __restrict                        string)
	__incfg_export;

extern void
incfg_ipv4_addr_setup_saddr(union incfg_ipv4_addr * __restrict addr,
                            in_addr_t                          saddr)
	__incfg_export;

extern void
incfg_ipv4_addr_setup_inet(union incfg_ipv4_addr * __restrict addr,
                           const struct in_addr * __restrict  inet)
	__incfg_export;

extern int
incfg_ipv4_addr_setup_str(union incfg_ipv4_addr * __restrict addr,
                          const char * __restrict            string)
	__incfg_export;

extern int
incfg_ipv4_addr_pack(struct dpack_encoder *                   encoder,
                     const union incfg_ipv4_addr * __restrict addr)
	__incfg_export;

extern ssize_t
incfg_ipv4_addr_unpack(struct dpack_decoder *             decoder,
                       union incfg_ipv4_addr * __restrict addr)
	__incfg_export;

static inline union incfg_ipv4_addr *
incfg_ipv4_addr_alloc(void)
{
	return malloc(sizeof(union incfg_ipv4_addr));
}

static inline void
incfg_ipv4_addr_free(union incfg_ipv4_addr * addr)
{
	free(addr);
}

static inline void
incfg_ipv4_addr_destroy(union incfg_ipv4_addr * addr)
{
	incfg_ipv4_addr_free(addr);
}

extern union incfg_ipv4_addr *
incfg_ipv4_addr_create_saddr(in_addr_t saddr)
	__incfg_export;

extern union incfg_ipv4_addr *
incfg_ipv4_addr_create_inet(const struct in_addr * __restrict inet)
	__incfg_export;

extern union incfg_ipv4_addr *
incfg_ipv4_addr_create_str(const char * __restrict string)
	__incfg_export;

#endif /* _INCFG_IPV4_H */
