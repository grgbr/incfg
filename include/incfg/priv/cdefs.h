/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

/**
 * @file
 * Common definitions
 *
 * @author    Grégor Boirie <gregor.boirie@free.fr>
 * @date      31 Jan 2024
 * @copyright Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 * @license   [GNU Lesser General Public License (LGPL) v3]
 *            (https://www.gnu.org/licenses/lgpl+gpl-3.0.txt)
 */

#ifndef _INCFG_CDEFS_H
#define _INCFG_CDEFS_H

#include <incfg/config.h>
#include <stroll/cdefs.h>

#define __incfg_export  __export_public

#if defined(CONFIG_INCFG_ASSERT_API) || defined(CONFIG_INCFG_ASSERT_INTERN)

#define __incfg_nonull(_arg_index, ...)
#define __incfg_const
#define __incfg_pure
#define __incfg_nothrow

#else   /* !(defined(CONFIG_INCFG_ASSERT_API) || \
             defined(CONFIG_INCFG_ASSERT_INTERN)) */

#define __incfg_nonull(_arg_index, ...) \
	__nonull(_arg_index, ## __VA_ARGS__)

#define __incfg_const   __const
#define __incfg_pure    __pure
#define __incfg_nothrow __nothrow

#endif /* defined(CONFIG_INCFG_ASSERT_API) || \
          defined(CONFIG_INCFG_ASSERT_INTERN) */

#endif /* _INCFG_CDEFS_H */
