/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_UTEST_H
#define _INCFG_UTEST_H

#include "incfg/config.h"
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <netinet/in.h>

#if defined(CONFIG_INCFG_IPV6)

extern const struct in6_addr in6addr_linklocal_allnodes;
extern const struct in6_addr in6addr_linklocal_allrouters;
extern const struct in6_addr in6addr_sitelocal_allrouters;

#endif /* defined(CONFIG_INCFG_IPV6) */

extern void free(void * ptr);
extern void incfgut_expect_free(const void * data, size_t size);

extern void * malloc(size_t size);
extern int    incfgut_expect_malloc(void);

extern void
incfgut_setup(void);

extern void
incfgut_teardown(void);

#endif /* _INCFG_UTEST_H */
