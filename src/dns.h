/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_INTERN_DNS_H
#define _INCFG_INTERN_DNS_H

#include <incfg/config.h>

#if defined(CONFIG_INCFG_DNS)

extern int
incfg_dns_init(void);

extern void
incfg_dns_fini(void);

#else  /* !defined(CONFIG_INCFG_DNS) */

static inline int incfg_dns_init(void) {}

static inline void incfg_dns_fini(void) {}

#endif /* defined(CONFIG_INCFG_DNS) */

#endif /* _INCFG_INTERN_DNS_H */
