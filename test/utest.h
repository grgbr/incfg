/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_UTEST_H
#define _INCFG_UTEST_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>

extern void free(void * ptr);
extern void incfgut_expect_free(const void * data, size_t size);

extern void * malloc(size_t size);
extern int    incfgut_expect_malloc(void);

#endif /* _INCFG_UTEST_H */
