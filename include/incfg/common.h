/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Base interface
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      03 Feb 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _INCFG_COMMON_H
#define _INCFG_COMMON_H

#include <incfg/cdefs.h>

struct elog;

extern int
incfg_init(struct elog * logger) __incfg_export;

extern void
incfg_fini(void) __incfg_export;

#endif /* _INCFG_COMMON_H */
