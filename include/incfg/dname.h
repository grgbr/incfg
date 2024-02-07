/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Domain name interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      03 Feb 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 *
 * Interface to work with DNS domain names deeply inspired by the `domain-name'
 * typedef defined into section 4 of RFC 6991.
 * It is designed to allow for current practice in domain name use, and some
 * possible future expansion.
 *
 * Basically, domain names encoding :
 * - uses US-ASCII,
 * - is restricted to ``NI_MAXHOST - 1`` characters (1024 on modern Linux
 *   platforms),
 * - with DNS labels shorter or equal to ``NS_MAXLABEL`` (63 characters).
 *
 * For more informations, refer to :
 * - RFC 6991: Common YANG Data Types
 * - RFC 952:  DoD Internet Host Table Specification
 * - RFC 1034: Domain Names - Concepts and Facilities
 * - RFC 1123: Requirements for Internet Hosts -- Application and Support
 * - RFC 2782: A DNS RR for specifying the location of services (DNS SRV)
 * - RFC 5890: Internationalized Domain Names in Applications (IDNA):
 *   Definitions and Document Framework.
 */

#ifndef _INCFG_DNAME_H
#define _INCFG_DNAME_H

#include <incfg/cdefs.h>
#include <netdb.h>
#include <dpack/lvstr.h>
#include <stdlib.h>

#define INCFG_DNAME_STRSZ_MAX \
	(NI_MAXHOST)

#define INCFG_DNAME_STRLEN_MAX \
	(INCFG_DNAME_STRSZ_MAX - 1)

#if INCFG_DNAME_STRLEN_MAX > DPACK_LVSTRLEN_MAX
#error Underlying lvstr cannot hold a complete domain name string ! \
       Increase DPack maximum string length and rebuild !
#endif /* INCFG_DNAME_STRLEN_MAX > DPACK_LVSTRLEN_MAX */

#define INCFG_DNAME_PACKSZ(_len) \
	DPACK_STR_SIZE(_len)

#define INCFG_DNAME_PACKSZ_MIN \
	DPACK_STR_SIZE(1)

#define INCFG_DNAME_PACKSZ_MAX \
	DPACK_STR_SIZE(INCFG_DNAME_STRLEN_MAX)

extern int
incfg_dname_check(const char * __restrict string)
	__incfg_export;

extern int
incfg_dname_ncheck(const char * __restrict string,
                   size_t                  length)
	__incfg_export;

extern const char *
incfg_dname_get_str(const struct stroll_lvstr * __restrict dname)
	__incfg_export;

extern size_t
incfg_dname_get_len(const struct stroll_lvstr * __restrict dname)
	__incfg_export;

extern void
incfg_dname_lend(struct stroll_lvstr * __restrict dname, const char * name)
	__incfg_export;

extern void
incfg_dname_nlend(struct stroll_lvstr * __restrict dname,
                  const char *                     name,
                  size_t                           length)
	__incfg_export;

extern void
incfg_dname_cede(struct stroll_lvstr * __restrict dname, char * name)
	__incfg_export;

extern void
incfg_dname_ncede(struct stroll_lvstr * __restrict dname,
                  char *                           name,
                  size_t                           length)
	__incfg_export;

extern int
incfg_dname_dup(struct stroll_lvstr * __restrict dname, const char * name)
	__incfg_export;

extern int
incfg_dname_ndup(struct stroll_lvstr * __restrict dname,
                 const char *                     name,
                 size_t                           length)
	__incfg_export;

extern size_t
incfg_dname_packsz(const struct stroll_lvstr * __restrict dname)
	__incfg_nonull(1)
	__incfg_pure
	__incfg_nothrow
	__leaf
	__warn_result
	__incfg_export;

extern int
incfg_dname_pack(const struct stroll_lvstr * __restrict dname,
                 struct dpack_encoder *                 encoder)
	__incfg_export;

extern int
incfg_dname_unpack(struct stroll_lvstr *  __restrict dname,
                   struct dpack_decoder *            decoder)
	__incfg_export;

extern int
incfg_dname_unpackn_check(struct stroll_lvstr *  __restrict dname,
                          struct dpack_decoder *            decoder)
	__incfg_export;

extern void
incfg_dname_init(struct stroll_lvstr * __restrict dname)
	__incfg_export;

extern void
incfg_dname_fini(struct stroll_lvstr * __restrict dname)
	__incfg_export;

#endif /* _INCFG_DNAME_H */
