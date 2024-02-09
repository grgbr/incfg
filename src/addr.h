/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Internal network address helpers
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      08 Feb 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _INCFG_INTERN_ADDR_H
#define _INCFG_INTERN_ADDR_H

#include <incfg/priv/addr.h>
#include "common.h"

static inline enum incfg_addr_type
incfg_addr_get_type(const struct incfg_addr * __restrict addr)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(addr->type <= INCFG_ADDR_TYPE_NR);

	return addr->type;
}

static inline void
incfg_addr_set_type(struct incfg_addr * __restrict addr,
                    enum incfg_addr_type           type)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(addr->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_intern(type <= INCFG_ADDR_TYPE_NR);

	addr->type = type;
}

static inline void
incfg_addr_set_str(struct incfg_addr * __restrict addr,
                   char *                         string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(addr->type <= INCFG_ADDR_TYPE_NR);
	incfg_assert_intern(string);
	incfg_assert_intern(*string);

	int err __unused;

	err = stroll_lvstr_cede(&addr->lvstr, string);
	incfg_assert_intern(!err);
}

static inline void
incfg_addr_clear_str(struct incfg_addr * __restrict addr)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(addr->type <= INCFG_ADDR_TYPE_NR);

	return stroll_lvstr_drop(&addr->lvstr);
}

static inline void
incfg_addr_init(struct incfg_addr * __restrict addr, enum incfg_addr_type type)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(type <= INCFG_ADDR_TYPE_NR);

	addr->type = type;
	stroll_lvstr_init(&addr->lvstr);
}

static inline void
incfg_addr_fini(struct incfg_addr * __restrict addr)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(addr->type <= INCFG_ADDR_TYPE_NR);

	stroll_lvstr_fini(&addr->lvstr);
}

#endif /* _INCFG_INTERN_ADDR_H */
