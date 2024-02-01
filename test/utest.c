/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ipv4.h"
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <stroll/assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#if defined(CONFIG_INCFG_VALGRIND)
#include <valgrind/valgrind.h>
#endif

static char incfgut_assert_msg[LINE_MAX];

/*
 * Override libstroll's stroll_assert_fail() and use cute_mock_assert() to
 * validate assertions.
 */
void
stroll_assert_fail(const char * __restrict prefix,
                   const char * __restrict expr,
                   const char * __restrict file,
                   unsigned int            line,
                   const char * __restrict func)
{
	int    ret;
	size_t sz = sizeof(incfgut_assert_msg) - 1;

	/*
	 * cute_mock_assert() does not really "return". It uses a nonlocal goto
	 * logic to restore program / stack state that existed before the code
	 * under test called us. This is the way CUTe allows checking for
	 * assertions.
	 * This means that the code below will never reach the abort() call
	 * below (which is just there to prevent GCC from warning us since
	 * stroll_assert_fail() is declared as a function that cannot return).
	 *
	 * Since cute_mock_assert() does not give control back to us, we MUST
	 * use a statically allocated buffer to store assertion messages. We
	 * would not have the opportunity to free(3) a previously allocated
	 * buffer otherwise.
	 * In other words, Valgrind memory leak checker should be happy with
	 * this...
	 */
	ret = snprintf(incfgut_assert_msg,
	               sz,
	               "{utest assert} %s:%s:%u:%s:\'%s\'",
	               prefix,
	               file,
	               line,
	               func,
	               expr);
	if (ret > 0) {
		if ((size_t)ret >= sz)
			incfgut_assert_msg[sz - 1] = '\0';

		cute_mock_assert(incfgut_assert_msg, file, line, func);
	}
	else
		cute_mock_assert("{utest assert} ??", file, line, func);

	/* Not reached (see comment above)... */
	abort();
}

/*
 * Override libstroll's stroll_assert_fail_msg() and use cute_mock_assert() to
 * validate assertions.
 */
void
stroll_assert_fail_msg(const char * __restrict prefix,
                       const char * __restrict message)
{
	int    ret;
	size_t sz = sizeof(incfgut_assert_msg) - 1;

	/*
	 * cute_mock_assert() does not really "return". It uses a nonlocal goto
	 * logic to restore program / stack state that existed before the code
	 * under test called us. This is the way CUTe allows checking for
	 * assertions.
	 * This means that the code below will never reach the abort() call
	 * below (which is just there to prevent GCC from warning us since
	 * stroll_assert_fail_msg() is declared as a function that cannot
	 * return).
	 *
	 * Since cute_mock_assert() does not give control back to us, we MUST
	 * use a statically allocated buffer to store assertion messages. We
	 * would not have the opportunity to free(3) a previously allocated
	 * buffer otherwise.
	 * In other words, Valgrind memory leak checker should be happy with
	 * this...
	 */
	ret = snprintf(incfgut_assert_msg,
	               sz,
	               "{utest assert} %s:%s",
	               prefix,
	               message);
	if (ret > 0) {
		if ((size_t)ret >= sz)
			incfgut_assert_msg[sz - 1] = '\0';

		cute_mock_assert(incfgut_assert_msg,
		                 __FILE__,
		                 __LINE__,
		                 __func__);
	}
	else
		cute_mock_assert("{utest assert} ??",
		                 __FILE__,
		                 __LINE__,
		                 __func__);

	abort();
}

static bool incfgut_free_wrapped;

/*
 * Mock Glibc's free(3) for verification purposes.
 *
 * Set incfgut_free_wrapped to true from client testing code to enable
 * free(3) argument checking logic.
 */
void
free(void * ptr)
{
	if (incfgut_free_wrapped) {
		/*
		 * Disable checking logic implicitly. Client testing code will
		 * have to re-enable it by setting incfgut_free_wrapped to
		 * true to perform subsequent validation.
		 *
		 * Watch out ! This MUST be done before calling any
		 * cute_mock_...() function is called since they all rely upon a
		 * working free(3). We would otherwise wrap CUTe's internal
		 * calls to free(3) !
		 */
		incfgut_free_wrapped = false;
		/*
		 * free(3) argument checking logic is enabled: do the check
		 * using standard CUTe's cute_mock_ptr_parm() /
		 * cute_mock_mem_parm().
		 * First check pointer value, then content of memory pointed to.
		 */
		cute_mock_ptr_parm(ptr);
		cute_mock_mem_parm(ptr);
	}

	/* Now call the original GLibc core free(3) function. */
#if defined __GLIBC__
	extern void __libc_free(void *);
	__libc_free(ptr);
#else
#error Glibc is the only C library supported for now !
#endif
}

void
incfgut_expect_free(const void * parm, size_t size)
{
#if defined(CONFIG_INCFG_VALGRIND)
	/*
	 * As Valgrind overrides C library's malloc(3) / realloc(3) / free(3)
	 * functions, it bypasses our own free(3) wrapper implemented above.
	 * This breaks our mocked free(3) testing mechanism and leads to test
	 * failures.
	 * Inhibit our mocked free(3) based tests when running testsuite under
	 * Valgrind. We may still run the entire testsuite without Valgrind
	 * anyway.
	 */
	if (RUNNING_ON_VALGRIND)
		return;
#endif
	/* Request checking of pointer value. */
	cute_expect_ptr_parm(free, ptr, equal, parm);
	/* Request checking of pointed to memory content. */
	cute_expect_mem_parm(free, ptr, equal, parm, size);

	/* Instruct free() function above to perform checking of arguments. */
	incfgut_free_wrapped = true;
}

static bool incfgut_malloc_wrapped;

/*
 * Mock Glibc's malloc(3) for verification purposes.
 *
 * Set incfgut_malloc_wrapped to true from client testing code to enable
 * malloc(3) argument checking logic and simulate allocation failure.
 */
void *
malloc(size_t size)
{
	if (incfgut_malloc_wrapped) {
		/*
		 * Disable checking logic implicitly. Client testing code will
		 * have to re-enable it by setting incfgut_malloc_wrapped to
		 * true to perform subsequent validation.
		 *
		 * Watch out ! This MUST be done before calling any
		 * cute_mock_...() function is called since they all rely
		 * upon a working malloc(3). We would otherwise wrap CUTe's
		 * internal calls to malloc(3) !
		 */
		incfgut_malloc_wrapped = false;
		/*
		 * malloc(3) argument checking logic is enabled: do the check
		 * using standard CUTe cute_mock_uint_parm().
		 */
		cute_mock_uint_parm(size);

		/* Now simulate a malloc() failure */
		return NULL;
	}

	/* Now call the GLibc core malloc(3) function. */
#if defined __GLIBC__
	extern void * __libc_malloc(size_t);
	return __libc_malloc(size);
#else
#error Glibc is the only C library supported for now !
#endif
}

int
incfgut_expect_malloc(void)
{
#if defined(CONFIG_INCFG_VALGRIND)
	/*
	 * As Valgrind overrides C library's malloc(3) / realloc(3) / free(3)
	 * functions, it bypasses our own malloc(3) wrapper implemented above.
	 * This breaks our mocked malloc(3) testing mechanism and leads to test
	 * failures.
	 * Inhibit our mocked malloc(3) based tests when running testsuite under
	 * Valgrind. We may still run the entire testsuite without Valgrind
	 * anyway.
	 */
	if (RUNNING_ON_VALGRIND)
		/*
		 * Tell the caller we cannot intercept malloc() calls since
		 * Valgrind has already overridden malloc().
		 */
		return -ECANCELED;
#endif

	/* Request checking of malloc(3) argument value to ensure it is != 0. */
	cute_expect_uint_parm(malloc, size, unequal, 0);
	/*
	 * Instruct malloc() function above to check argument and simulate a
	 * failure.
	 */
	incfgut_malloc_wrapped = true;

	return 0;
}

#if defined(CONFIG_INCFG_IPV4)
extern CUTE_SUITE_DECL(incfgut_ipv4_suite);
#endif

CUTE_GROUP(incfgut_group) = {
#if defined(CONFIG_DPACK_ARRAY)
	CUTE_REF(incfgut_ipv4_suite),
#endif
};

CUTE_SUITE(incfgut_suite, incfgut_group);

CUTE_MAIN(incfgut_suite, "InCfg", INCFG_VERSION_STRING)
