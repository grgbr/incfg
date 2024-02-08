/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_INTERN_DNAME_H
#define _INCFG_INTERN_DNAME_H

#include <incfg/config.h>

#if defined(CONFIG_INCFG_DNAME)

extern int
incfg_dname_init_lib(void);

extern void
incfg_dname_fini_lib(void);

#else  /* !defined(CONFIG_INCFG_DNAME) */

static inline int incfg_dname_init_lib(void) { return 0; }

static inline void incfg_dname_fini_lib(void) {}

#endif /* defined(CONFIG_INCFG_DNAME) */

#endif /* _INCFG_INTERN_DNAME */
