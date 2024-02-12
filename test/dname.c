/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/dname.h"
#include <dpack/codec.h>
#include <arpa/nameser.h>
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <errno.h>

static const char * const incfgut_dname_compliant_names[] = {
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

static const char * const incfgut_dname_invalid_names[] = {
	"",
	" .",
	".domain",
	".domain.",

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

static void * incfgut_dname_tofree = NULL;

static void
incfgut_dname_teardown(void)
{
	free(incfgut_dname_tofree);
	incfgut_dname_tofree = NULL;
	incfgut_teardown();
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_check_assert)
{
	cute_expect_assertion(incfg_dname_check(NULL));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_check_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_dname_check_names(const char * const names[],
                          unsigned int       count,
                          int                result)
{
	unsigned int n;

	for (n = 0; n < count; n++)
		cute_check_sint(incfg_dname_check(names[n]), equal, result);
}

static void
incfgut_dname_check_label(size_t length, int error)
{
	char * str;

	incfgut_dname_tofree = malloc(length + 1);
	str = incfgut_dname_tofree;

	cute_check_ptr(str, unequal, NULL);

	memset(str, 'a', length);
	str[length] = '\0';

	cute_check_sint(incfg_dname_check(str), equal, error);

	free(str);
	incfgut_dname_tofree = NULL;
}

CUTE_TEST(incfgut_dname_check_ok)
{
	incfgut_dname_check_names(incfgut_dname_compliant_names,
	                          array_nr(incfgut_dname_compliant_names),
	                          0);

	incfgut_dname_check_label(NS_MAXLABEL, 0);
}

CUTE_TEST(incfgut_dname_check_nok)
{
	incfgut_dname_check_names(incfgut_dname_invalid_names,
	                          array_nr(incfgut_dname_invalid_names),
	                          -EINVAL);

	incfgut_dname_check_label(NS_MAXLABEL + 1, -EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_ncheck_assert)
{
	cute_expect_assertion(incfg_dname_ncheck(NULL, 1));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_ncheck_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

static void
incfgut_dname_check_nnames(const char * const names[],
                           unsigned int       count,
                           int                result)
{
	unsigned int n;

	for (n = 0; n < count; n++)
		cute_check_sint(incfg_dname_ncheck(names[n], strlen(names[n])),
		                equal,
		                result);
}

static void
incfgut_dname_check_nlabel(size_t length, int error)
{
	char * str;

	incfgut_dname_tofree = malloc(length + 1);
	str = incfgut_dname_tofree;

	cute_check_ptr(str, unequal, NULL);

	memset(str, 'a', length + 1);

	cute_check_sint(incfg_dname_ncheck(str, length), equal, error);

	free(str);
	incfgut_dname_tofree = NULL;
}

CUTE_TEST(incfgut_dname_ncheck_ok)
{
	incfgut_dname_check_nnames(incfgut_dname_compliant_names,
	                           array_nr(incfgut_dname_compliant_names),
	                           0);

	incfgut_dname_check_nlabel(NS_MAXLABEL, 0);
}

CUTE_TEST(incfgut_dname_ncheck_nok)
{
	incfgut_dname_check_nnames(incfgut_dname_invalid_names,
	                           array_nr(incfgut_dname_invalid_names),
	                           -EINVAL);

	incfgut_dname_check_nlabel(NS_MAXLABEL + 1, -EINVAL);
}

CUTE_TEST(incfgut_dname_ncheck_short)
{
	cute_check_sint(incfg_dname_ncheck("host.domain", 4), equal, 0);
	cute_check_sint(incfg_dname_ncheck("host.domain ", 12), equal, -EINVAL);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_get_assert)
{
	struct incfg_addr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_get(NULL));
	cute_expect_assertion(incfg_dname_get(&dname));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_get_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_get)
{
	struct incfg_addr           dname;
	const struct stroll_lvstr * str;

	incfg_dname_init(&dname);
	incfg_dname_set(&dname, "host.domain.");

	str = incfg_dname_get(&dname);
	cute_check_ptr(str, unequal, NULL);

	cute_check_str(stroll_lvstr_cstr(str), equal, "host.domain.");

	incfg_dname_fini(&dname);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_set_assert)
{
	struct incfg_addr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_set(NULL, "host.domain."));
	cute_expect_assertion(incfg_dname_set(&dname, NULL));
	cute_expect_assertion(incfg_dname_set(&dname, "-domain."));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_set_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_set)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct incfg_addr           dname;
		const struct stroll_lvstr * str;
		int                         ret;

		incfg_dname_init(&dname);

		if (!incfgut_expect_malloc())
			cute_check_sint(
				incfg_dname_set(
					&dname,
					incfgut_dname_compliant_names[n]),
				equal,
				-ENOMEM);

		ret = incfg_dname_set(&dname, incfgut_dname_compliant_names[n]);
		incfgut_dname_tofree = dname.lvstr.rwstr;
		cute_check_sint(ret, equal, 0);

		str = incfg_dname_get(&dname);
		cute_check_ptr(str, unequal, NULL);
		cute_check_str(stroll_lvstr_cstr(str),
		               equal,
		               incfgut_dname_compliant_names[n]);

		incfg_dname_fini(&dname);

		incfgut_dname_tofree = NULL;
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_nset_assert)
{
	struct incfg_addr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_nset(NULL,
	                                       "host.domain.",
	                                       strlen("host.domain.")));
	cute_expect_assertion(incfg_dname_nset(&dname, NULL, 1));
	cute_expect_assertion(incfg_dname_nset(&dname,
	                                       "host.domain.",
	                                       0));
	cute_expect_assertion(incfg_dname_nset(&dname,
	                                       "host.domain.",
	                                       strlen("host.domain.") + 1));
	cute_expect_assertion(incfg_dname_nset(&dname,
	                                       "-domain.",
	                                       strlen("-domain.")));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_nset_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_nset)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct incfg_addr           dname;
		const char *                str;
		const struct stroll_lvstr * lvstr;
		size_t                      len;
		int                         ret;

		str = incfgut_dname_compliant_names[n];
		len = strlen(str);

		incfg_dname_init(&dname);

		if (!incfgut_expect_malloc())
			cute_check_sint(
				incfg_dname_nset(&dname, str, len),
				equal,
				-ENOMEM);

		ret = incfg_dname_nset(&dname, str, len);
		incfgut_dname_tofree = dname.lvstr.rwstr;
		cute_check_sint(ret, equal, 0);

		lvstr = incfg_dname_get(&dname);
		cute_check_ptr(lvstr, unequal, NULL);
		cute_check_str(stroll_lvstr_cstr(lvstr), equal, str);

		incfg_dname_fini(&dname);

		incfgut_dname_tofree = NULL;
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_pack_assert)
{
	struct dpack_encoder enc;
	struct incfg_addr    dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_pack(&dname, NULL));
	cute_expect_assertion(incfg_dname_pack(NULL, &enc));

	cute_expect_assertion(incfg_dname_pack(&dname, &enc));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_pack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_pack)
{
	struct dpack_encoder enc;
	char                 buff[INCFG_DNAME_PACKSZ(12) + 2];
	struct incfg_addr    dname;
	const uint8_t        ref[] = "\xac"
	                             "\x68\x6f\x73\x74"
	                             "\x2e"
	                             "\x64\x6f\x6d\x61\x69\x6e"
	                             "\x2e";

	cute_check_uint(INCFG_DNAME_PACKSZ(12), equal, sizeof(ref) - 1);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	incfg_dname_init(&dname);
	cute_check_sint(incfg_dname_set(&dname, "host.domain."), equal, 0);

	cute_check_sint(incfg_dname_pack(&dname, &enc), equal, 0);
	cute_check_uint(dpack_encoder_space_used(&enc),
	                equal,
	                INCFG_DNAME_PACKSZ(12));
	cute_check_uint(dpack_encoder_space_left(&enc),
	                equal,
	                sizeof(buff) - INCFG_DNAME_PACKSZ(12));
	cute_check_mem(buff, equal, ref, sizeof(ref) - 1);

	incfg_dname_fini(&dname);

	dpack_encoder_fini(&enc, DPACK_DONE);
}

CUTE_TEST(incfgut_dname_pack_short)
{
	struct dpack_encoder enc;
	char                 buff = '\xff';
	char                 ref = '\xff';
	struct incfg_addr    dname;

	incfg_dname_init(&dname);
	cute_check_sint(incfg_dname_set(&dname, "host.domain."), equal, 0);

	dpack_encoder_init_buffer(&enc, &buff, sizeof(buff));

	cute_check_sint(incfg_dname_pack(&dname, &enc), equal, -EMSGSIZE);
	cute_check_uint(dpack_encoder_space_used(&enc), equal, 0);
	cute_check_uint(dpack_encoder_space_left(&enc), equal, sizeof(buff));
	cute_check_mem((void *)&buff, equal, (void *)&ref, sizeof(ref));

	dpack_encoder_fini(&enc, DPACK_ABORT);

	incfg_dname_fini(&dname);
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_unpack_assert)
{
	struct dpack_decoder dec;
	struct incfg_addr    dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_unpack(&dname, NULL));
	cute_expect_assertion(incfg_dname_unpack(NULL, &dec));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_unpack_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_unpack)
{
	struct dpack_decoder        dec;
	const char                  buff[] = "\xac"
	                                     "\x68\x6f\x73\x74"
	                                     "\x2e"
	                                     "\x64\x6f\x6d\x61\x69\x6e"
	                                     "\x2e";
	const struct stroll_lvstr * str;
	struct incfg_addr           dname;

	incfg_dname_init(&dname);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_dname_unpack(&dname, &dec), equal, 0);
	incfgut_dname_tofree = dname.lvstr.rwstr;
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	str = incfg_dname_get(&dname);
	cute_check_ptr(str, unequal, NULL);
	cute_check_str(stroll_lvstr_cstr(str), equal, "host.domain.");

	dpack_decoder_fini(&dec);

	incfg_dname_fini(&dname);
	incfgut_dname_tofree = NULL;
}

static void
incfgut_dname_test_unpack_fail(const char * buff, size_t size, int error)
{
	struct dpack_decoder dec;
	struct incfg_addr    dname;

	incfg_dname_init(&dname);

	dpack_decoder_init_buffer(&dec, buff, size);

	cute_check_sint(incfg_dname_unpack(&dname, &dec), equal, error);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	dpack_decoder_fini(&dec);

	incfg_dname_fini(&dname);
}

CUTE_TEST(incfgut_dname_unpack_fail)
{
	/* Expecting a string and received a bin. */
	incfgut_dname_test_unpack_fail("\xc4\x04", 2, -ENOMSG);
	/* Advertised string length is not consistent with data buffer size. */
	incfgut_dname_test_unpack_fail("\xac\xff", 1, -EPROTO);
	/* Empty strings not allowed. */
	incfgut_dname_test_unpack_fail("\xa0", 1, -EMSGSIZE);
	/* NULL terminated string rejected. */
	incfgut_dname_test_unpack_fail("\xa2\x61\x00", 3, -EBADMSG);
}

CUTE_TEST(incfgut_dname_unpackn_check)
{
	struct dpack_decoder        dec;
	const char                  buff[] = "\xac"
	                                     "\x68\x6f\x73\x74"
	                                     "\x2e"
	                                     "\x64\x6f\x6d\x61\x69\x6e"
	                                     "\x2e";
	struct incfg_addr           dname;
	const struct stroll_lvstr * str;

	incfg_dname_init(&dname);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_dname_unpackn_check(&dname, &dec), equal, 0);
	incfgut_dname_tofree = dname.lvstr.rwstr;
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	str = incfg_dname_get(&dname);
	cute_check_ptr(str, unequal, NULL);
	cute_check_str(stroll_lvstr_cstr(str), equal, "host.domain.");

	dpack_decoder_fini(&dec);

	incfg_dname_fini(&dname);
	incfgut_dname_tofree = NULL;
}

static void
incfgut_dname_test_unpackn_check_fail(const char * buff, size_t size, int error)
{
	struct dpack_decoder dec;
	struct incfg_addr  dname;

	incfg_dname_init(&dname);

	dpack_decoder_init_buffer(&dec, buff, size);

	cute_check_sint(incfg_dname_unpackn_check(&dname, &dec), equal, error);
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);

	dpack_decoder_fini(&dec);

	incfg_dname_fini(&dname);
}

CUTE_TEST(incfgut_dname_unpackn_check_fail)
{
	/* Expecting a string and received a bin. */
	incfgut_dname_test_unpackn_check_fail("\xc4\x04", 2, -ENOMSG);
	/* Advertised string length is not consistent with data buffer size. */
	incfgut_dname_test_unpackn_check_fail("\xac\xff", 1, -EPROTO);
	/* Empty strings not allowed. */
	incfgut_dname_test_unpackn_check_fail("\xa0", 1, -EMSGSIZE);
	/* NULL terminated string rejected. */
	incfgut_dname_test_unpackn_check_fail("\xa2\x61\x00", 3, -EBADMSG);
	/* leading '-' character rejected within domain names... */
	incfgut_dname_test_unpackn_check_fail("\xa1\x2d", 2, -EINVAL);
}

CUTE_GROUP(incfgut_dname_group) = {
	CUTE_REF(incfgut_dname_check_assert),
	CUTE_REF(incfgut_dname_check_ok),
	CUTE_REF(incfgut_dname_check_nok),
	CUTE_REF(incfgut_dname_ncheck_assert),
	CUTE_REF(incfgut_dname_ncheck_ok),
	CUTE_REF(incfgut_dname_ncheck_nok),
	CUTE_REF(incfgut_dname_ncheck_short),

	CUTE_REF(incfgut_dname_get_assert),
	CUTE_REF(incfgut_dname_get),

	CUTE_REF(incfgut_dname_set_assert),
	CUTE_REF(incfgut_dname_set),
	CUTE_REF(incfgut_dname_nset_assert),
	CUTE_REF(incfgut_dname_nset),

	CUTE_REF(incfgut_dname_pack_assert),
	CUTE_REF(incfgut_dname_pack),
	CUTE_REF(incfgut_dname_pack_short),

	CUTE_REF(incfgut_dname_unpack_assert),
	CUTE_REF(incfgut_dname_unpack),
	CUTE_REF(incfgut_dname_unpack_fail),
	CUTE_REF(incfgut_dname_unpackn_check),
	CUTE_REF(incfgut_dname_unpackn_check_fail)
};

CUTE_SUITE_EXTERN(incfgut_dname_suite,
                  incfgut_dname_group,
                  incfgut_setup,
                  incfgut_dname_teardown,
                  CUTE_DFLT_TMOUT);
