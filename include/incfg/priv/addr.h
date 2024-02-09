/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Network address interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      03 Feb 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _INCFG_ADDR_H
#define _INCFG_ADDR_H

#include <incfg/cdefs.h>
#include <dpack/lvstr.h>

enum incfg_addr_type {
	INCFG_ADDR_IPV4_TYPE  = 0,
	INCFG_ADDR_IPV6_TYPE  = 1,
	INCFG_ADDR_DNAME_TYPE = 2,
	INCFG_ADDR_TYPE_NR
};

struct incfg_addr {
	enum incfg_addr_type type;
	struct stroll_lvstr  lvstr;
};

#endif /* _INCFG_ADDR_H */
