/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/dns.h"
#include <arpa/nameser.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <errno.h>

static const char * const incfgut_dns_compliant_names[] = {
	".",
	"domain.",
	"host",
	"host.domain.",
	"host.domain",
	"host2.domain0.",
	"host2.domain0",
	"2host.0domain.",
	"2host.0domain",
	"host.sub-domain.",
	"host.sub-domain",
	"h-ost.sub-domain.",
	"h-ost.sub-domain",
	"2h-ost.0sub-domain.",
	"2h-ost.0sub-domain",
	"_host",
	"_host._sub-domain",
	"host.xn--sub_domain.domain.fr"
};

static const char * const incfgut_dns_invalid_names[] = {
	"",
	" .",
	"-",
	"-.",
	"-domain.",
	"-host",
	"-host.domain.",
	"-host.domain",
	"-host2.domain0.",
	"-host2.domain0",
	"-2host.0domain.",
	"-2host.0domain",
	"-host.sub-domain.",
	"-host.sub-domain",
	"-h-ost.sub-domain.",
	"-h-ost.sub-domain",
	"-2h-ost.0sub-domain.",
	"-2h-ost.0sub-domain",

	".-",
	"domain-.",
	"host-",
	"host-.domain.",
	"host-.domain",
	"host2-.domain0.",
	"host2-.domain0",
	"2host-.0domain.",
	"2host-.0domain",
	"host-.sub-domain.",
	"host-.sub-domain",
	"h-ost-.sub-domain.",
	"h-ost-.sub-domain",
	"2h-ost-.0sub-domain.",
	"2h-ost-.0sub-domain",

	"host.-domain.",
	"host.-domain",
	"host2.-domain0.",
	"host2.-domain0",
	"2host.-0domain.",
	"2host.-0domain",
	"host.-sub-domain.",
	"host.-sub-domain",
	"h-ost.-sub-domain.",
	"h-ost.-sub-domain",
	"2h-ost.-0sub-domain.",
	"2h-ost.-0sub-domain",

	"host.domain-.",
	"host.domain-",
	"host2.domain0-.",
	"host2.domain0-",
	"2host.0domain-.",
	"2host.0domain-",
	"host.sub-domain-.",
	"host.sub-domain-",
	"h-ost.sub-domain-.",
	"h-ost.sub-domain-",
	"2h-ost.0sub-domain-.",
	"2h-ost.0sub-domain-",

	"2h-ost.-0sub-domain.domain.",
	"2h-ost.0sub-domain-.domain.",
	"2h-ost.0sub-domain-.domain",

	"_",
	"host_",
	"host.domain_",
	"host.sub-domain_.domain.",
	"host.sub-domain_.domain",
};

static void * incfgut_dns_tofree = NULL;

static void
incfgut_dns_teardown(void)
{
	free(incfgut_dns_tofree);
	incfgut_dns_tofree = NULL;
	incfgut_teardown();
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dns_check_str_assert)
{
	cute_expect_assertion(incfg_dns_check_str(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dns_check_str_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_dns_check_names(const char * const names[],
                        unsigned int       count,
                        int                result)
{
	unsigned int n;

	for (n = 0; n < count; n++)
		cute_check_sint(incfg_dns_check_str(names[n]), equal, result);
}

static void
incfgut_dns_check_label(size_t length, int error)
{
	char * str;

	incfgut_dns_tofree = malloc(length + 1);
	str = incfgut_dns_tofree;

	cute_check_ptr(str, unequal, NULL);

	memset(str, 'a', length);
	str[length] = '\0';

	cute_check_sint(incfg_dns_check_str(str), equal, error);

	free(str);
	incfgut_dns_tofree = NULL;
}

CUTE_TEST(incfgut_dns_check_str_ok)
{
	incfgut_dns_check_names(incfgut_dns_compliant_names,
	                        array_nr(incfgut_dns_compliant_names),
	                        0);

	incfgut_dns_check_label(NS_MAXLABEL, 0);
}

CUTE_TEST(incfgut_dns_check_str_nok)
{
	incfgut_dns_check_names(incfgut_dns_invalid_names,
	                        array_nr(incfgut_dns_invalid_names),
	                        -EINVAL);

	incfgut_dns_check_label(NS_MAXLABEL + 1, -EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dns_check_nstr_assert)
{
	cute_expect_assertion(incfg_dns_check_nstr(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dns_check_nstr_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_dns_check_nnames(const char * const names[],
                         unsigned int       count,
                         int                result)
{
	unsigned int n;

	for (n = 0; n < count; n++)
		cute_check_sint(incfg_dns_check_nstr(names[n],
		                                     strlen(names[n])),
		                equal,
		                result);
}

static void
incfgut_dns_check_nlabel(size_t length, int error)
{
	char * str;

	incfgut_dns_tofree = malloc(length + 1);
	str = incfgut_dns_tofree;

	cute_check_ptr(str, unequal, NULL);

	memset(str, 'a', length + 1);

	cute_check_sint(incfg_dns_check_nstr(str, length), equal, error);

	free(str);
	incfgut_dns_tofree = NULL;
}

CUTE_TEST(incfgut_dns_check_nstr_ok)
{
	incfgut_dns_check_nnames(incfgut_dns_compliant_names,
	                         array_nr(incfgut_dns_compliant_names),
	                         0);

	incfgut_dns_check_nlabel(NS_MAXLABEL, 0);
}

CUTE_TEST(incfgut_dns_check_nstr_nok)
{
	incfgut_dns_check_nnames(incfgut_dns_invalid_names,
	                         array_nr(incfgut_dns_invalid_names),
	                         -EINVAL);

	incfgut_dns_check_nlabel(NS_MAXLABEL + 1, -EINVAL);
}

CUTE_GROUP(incfgut_dns_group) = {
	CUTE_REF(incfgut_dns_check_str_assert),
	CUTE_REF(incfgut_dns_check_str_ok),
	CUTE_REF(incfgut_dns_check_str_nok),
	CUTE_REF(incfgut_dns_check_nstr_assert),
	CUTE_REF(incfgut_dns_check_nstr_ok),
	CUTE_REF(incfgut_dns_check_nstr_nok),
};

CUTE_SUITE_EXTERN(incfgut_dns_suite,
                  incfgut_dns_group,
                  incfgut_setup,
                  incfgut_dns_teardown,
                  CUTE_DFLT_TMOUT);
