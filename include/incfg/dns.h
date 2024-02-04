
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

#ifndef _INCFG_DNS_H
#define _INCFG_DNS_H

#include <incfg/cdefs.h>
#include <netdb.h>
#include <dpack/lvstr.h>
#include <stdlib.h>

struct incfg_dns {
	struct stroll_lvstr name;
};

#define INCFG_DNS_STRSZ_MAX \
	(NI_MAXHOST)

#define INCFG_DNS_STRLEN_MAX \
	(INCFG_DNS_STRSZ_MAX - 1)

#define INCFG_DNS_PACKSZ(_len) \
	DPACK_STR_SIZE(_len)

#define INCFG_DNS_PACKSZ_MIN \
	DPACK_STR_SIZE(1)

#define INCFG_DNS_PACKSZ_MAX \
	DPACK_STR_SIZE(INCFG_DNS_STRLEN_MAX)

extern int
incfg_dns_check_nstr(const char * __restrict string,
                     size_t                  length) __incfg_export;

extern int
incfg_dns_check_str(const char * __restrict string) __incfg_export;

#endif /* _INCFG_DNS_H */
