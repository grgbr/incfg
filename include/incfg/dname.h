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

extern void
incfg_dname_dup(struct stroll_lvstr * __restrict dname, const char * name)
	__incfg_export;

extern void
incfg_dname_ndup(struct stroll_lvstr * __restrict dname,
                 const char *                     name,
                 size_t                           length)
	__incfg_export;

extern size_t
incfg_dname_packsz(size_t len) __incfg_const
                               __incfg_nothrow
                               __leaf
                               __warn_result
                               __incfg_export;

extern int
incfg_dname_pack(const struct stroll_lvstr * __restrict dname,
                 struct dpack_encoder *                 encoder)
	__incfg_export;

extern ssize_t
incfg_dname_unpack(struct stroll_lvstr *  __restrict dname,
                   struct dpack_decoder *            decoder)
	__incfg_export;

extern ssize_t
incfg_dname_checkn_unpack(struct stroll_lvstr *  __restrict dname,
                          struct dpack_decoder *            decoder)
	__incfg_export;

extern void
incfg_dname_init(struct stroll_lvstr * __restrict dname)
	__incfg_export;

extern void
incfg_dname_fini(struct stroll_lvstr * __restrict dname)
	__incfg_export;

#endif /* _INCFG_DNAME_H */
