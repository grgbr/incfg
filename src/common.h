/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_COMMON_H
#define _INCFG_COMMON_H

#include "incfg/cdefs.h"

#if defined(CONFIG_INCFG_ASSERT_API)

#include <stroll/assert.h>

#define incfg_assert_api(_cond) \
	stroll_assert("incfg", _cond)

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

#define incfg_assert_api(_cond)

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

#if defined(CONFIG_INCFG_ASSERT_INTERN)

#define incfg_assert_intern(_cond) \
	stroll_assert("incfg", _cond)

#else  /* !defined(CONFIG_INCFG_ASSERT_INTERN) */

#define incfg_assert_intern(_cond)

#endif /* defined(CONFIG_INCFG_ASSERT_INTERN) */

#endif /* _INCFG_COMMON_H */
