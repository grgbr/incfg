/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_INTERN_COMMON_H
#define _INCFG_INTERN_COMMON_H

#include "incfg/common.h"
#include <elog/elog.h>

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

extern struct elog * incfg_logger;

#define incfg_err(_format, ...) \
	elog_err(incfg_logger, "incfg: " _format ".", ## __VA_ARGS__)

#if defined(CONFIG_INCFG_DEBUG)

#define incfg_debug(_format, ...) \
	elog_debug(incfg_logger, "incfg: " _format ".", ## __VA_ARGS__)

#else  /* !defined(CONFIG_INCFG_DEBUG) */

#define incfg_debug(_format, ...)

#endif /* defined(CONFIG_INCFG_DEBUG) */

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

struct incfg_regex {
	pcre2_code *       code;
	pcre2_match_data * data;
	const char *       name;
};

extern int
incfg_regex_nmatch(const struct incfg_regex * __restrict regex,
                   const char *                          string,
                   size_t                                length);

static inline int
incfg_regex_match(const struct incfg_regex * __restrict regex,
                  const char *                          string)
{
	return incfg_regex_nmatch(regex, string, PCRE2_ZERO_TERMINATED);
}

extern int
incfg_regex_ninit(struct incfg_regex * __restrict regex,
                  const char *         __restrict name,
                  const char *                    pattern,
                  size_t                          length);

static inline int
_incfg_regex_init(struct incfg_regex * __restrict regex,
                  const char *         __restrict name,
                  const char *                    pattern)
{
	return incfg_regex_ninit(regex, name, pattern, PCRE2_ZERO_TERMINATED);
}

#define _incfg_regex_init_const(_regex, _name, _pattern) \
	compile_eval(__builtin_constant_p(_pattern), \
	             incfg_regex_ninit(_regex, \
	                               _name, \
	                               _pattern, \
	                               sizeof(_pattern) - 1), \
	             "constant pattern string expected")

#define incfg_regex_init(_regex, _name, _pattern) \
	compile_choose(__builtin_constant_p(_pattern), \
	               _incfg_regex_init_const(_regex, _name, _pattern), \
	               _incfg_regex_init(_regex, _name, _pattern))

extern void
incfg_regex_fini(struct incfg_regex * __restrict regex);

#endif /* _INCFG_INTERN_COMMON_H */
