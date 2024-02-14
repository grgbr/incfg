/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Host interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      14 Feb 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 *
 * Interface to work with network host inspired by the `host' typedef defined
 * into section 4 of RFC 6991.
 *
 * For more informations, refer to :
 * - RFC 6991: Common YANG Data Types
 */

#ifndef _INCFG_HOST_H
#define _INCFG_HOST_H

#include <incfg/priv/cdefs.h>

#if !defined(CONFIG_INCFG_DNAME) && !defined(CONFIG_INCFG_IP)
#error Invalid build configuration: host support requires either domain name \
       or IP address build configuration options !
#endif /* !defined(CONFIG_INCFG_DNAME) && !defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)
#include <incfg/dname.h>
#endif /* defined(CONFIG_INCFG_DNAME) */
#if defined(CONFIG_INCFG_IP)
#include <incfg/ip.h>
#endif /* defined(CONFIG_INCFG_IP) */

union incfg_host {
#if defined(CONFIG_INCFG_DNAME)
	struct incfg_addr   dname;
#endif /* defined(CONFIG_INCFG_DNAME) */
#if defined(CONFIG_INCFG_IP)
	union incfg_ip_addr ip;
#endif /* defined(CONFIG_INCFG_IP) */
};

#if defined(CONFIG_INCFG_IP)

#define _INCFG_HOST_IP_STRSZ_MAX  INCFG_IP_ADDR_STRSZ_MAX
#define _INCFG_HOST_IP_PACKSZ_MIN INCFG_IP_ADDR_PACKSZ_MIN
#define _INCFG_HOST_IP_PACKSZ_MAX INCFG_IP_ADDR_PACKSZ_MAX

#else  /* !defined(CONFIG_INCFG_IP) */

#define _INCFG_HOST_IP_STRSZ_MAX  (0U)
#define _INCFG_HOST_IP_PACKSZ_MIN (UINT_MAX)
#define _INCFG_HOST_IP_PACKSZ_MAX (0U)

#endif /* defined(CONFIG_INCFG_IP) */

#if defined(CONFIG_INCFG_DNAME)

#define _INCFG_HOST_DNAME_STRSZ_MAX  \
	(INCFG_ADDR_TYPE_PACKSZ + INCFG_DNAME_ADDR_STRSZ_MAX)
#define _INCFG_HOST_DNAME_PACKSZ_MIN \
	(INCFG_ADDR_TYPE_PACKSZ + INCFG_DNAME_ADDR_PACKSZ_MIN)
#define _INCFG_HOST_DNAME_PACKSZ_MAX \
	(INCFG_ADDR_TYPE_PACKSZ + INCFG_DNAME_ADDR_PACKSZ_MAX)

#else  /* !defined(CONFIG_INCFG_DNAME) */

#define _INCFG_HOST_DNAME_STRSZ_MAX  (0U)
#define _INCFG_HOST_DNAME_PACKSZ_MIN (UINT_MAX)
#define _INCFG_HOST_DNAME_PACKSZ_MAX (0U)

#endif /* defined(CONFIG_INCFG_DNAME) */

#define INCFG_HOST_STRSZ_MAX \
	STROLL_CONST_MAX(_INCFG_HOST_IP_STRSZ_MAX, _INCFG_HOST_DNAME_STRSZ_MAX)

#define INCFG_HOST_STRLEN_MAX \
	(INCFG_HOST_STRSZ_MAX - 1)

#define INCFG_HOST_PACKSZ_MIN \
	STROLL_CONST_MIN(_INCFG_HOST_IP_PACKSZ_MIN, \
	                 _INCFG_HOST_DNAME_PACKSZ_MIN)

#define INCFG_HOST_PACKSZ_MAX \
	STROLL_CONST_MAX(_INCFG_HOST_IP_PACKSZ_MAX, \
	                 _INCFG_HOST_DNAME_PACKSZ_MAX)

#if defined(CONFIG_INCFG_IPV4)

extern const struct in_addr *
incfg_host_get_inet4(const union incfg_host * __restrict host)
	__incfg_export;

extern void
incfg_host_set_saddr4(union incfg_host * __restrict host,
                      in_addr_t                     saddr)
	__incfg_export;

extern void
incfg_host_set_inet4(union incfg_host * __restrict     host,
                     const struct in_addr * __restrict inet)
	__incfg_export;

#endif /* defined(CONFIG_INCFG_IPV4) */

#if defined(CONFIG_INCFG_IPV6)

extern const struct in6_addr *
incfg_host_get_inet6(const union incfg_host * __restrict host)
	__incfg_export;

extern void
incfg_host_set_inet6(union incfg_host * __restrict      host,
                     const struct in6_addr * __restrict inet)
	__incfg_export;

#endif /* defined(CONFIG_INCFG_IPV6) */

extern int
incfg_host_check_str(const char * __restrict string)
	__incfg_export;

extern int
incfg_host_check_nstr(const char * __restrict string, size_t length)
	__incfg_export;

extern const struct stroll_lvstr *
incfg_host_get_str(union incfg_host * __restrict host)
	__incfg_export;

extern int
incfg_host_set_str(union incfg_host * __restrict  host,
                   const char * __restrict        string)
	__incfg_export;

extern int
incfg_host_set_nstr(union incfg_host * __restrict host,
                    const char * __restrict       string,
                    size_t                        length)
	__incfg_export;

extern size_t
incfg_host_packsz(const union incfg_host * __restrict host)
	__incfg_export;

extern int
incfg_host_pack(const union incfg_host * __restrict host,
                struct dpack_encoder *              encoder)
	__incfg_export;

extern int
incfg_host_unpack(union incfg_host * __restrict host,
                  struct dpack_decoder *        decoder)
	__incfg_export;

extern int
incfg_host_unpackn_check(union incfg_host * __restrict host,
                         struct dpack_decoder *        decoder)
	__incfg_export;

extern void
incfg_host_init(union incfg_host * __restrict host)
	__incfg_export;

extern void
incfg_host_fini(union incfg_host * __restrict host)
	__incfg_export;

#endif /* _INCFG_IP_H */
