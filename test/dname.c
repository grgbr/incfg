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

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_get_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_get_str(NULL));
	cute_expect_assertion(incfg_dname_get_str(&dname));
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_get_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_get)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);
	incfg_dname_lend(&dname, "host.domain.");

	cute_check_str(incfg_dname_get_str(&dname), equal, "host.domain.");
	cute_check_str(incfg_dname_get_str(&dname), unequal, "host.domain");

}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_lend_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_lend(NULL, "host.domain."));
	cute_expect_assertion(incfg_dname_lend(&dname, NULL));
	cute_expect_assertion(incfg_dname_lend(&dname, "-domain."));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_lend_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_lend)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct stroll_lvstr dname;

		incfg_dname_init(&dname);

		incfg_dname_lend(&dname, incfgut_dname_compliant_names[n]);
		cute_check_str(incfg_dname_get_str(&dname),
		               equal,
		               incfgut_dname_compliant_names[n]);
		cute_check_uint(incfg_dname_get_len(&dname),
		                equal,
		                strlen(incfgut_dname_compliant_names[n]));

		incfg_dname_fini(&dname);
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_nlend_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_nlend(NULL,
	                                        "host.domain.",
	                                        strlen("host.domain.")));
	cute_expect_assertion(incfg_dname_nlend(&dname, NULL, 1));
	cute_expect_assertion(incfg_dname_nlend(&dname,
	                                        "host.domain.",
	                                        0));
	cute_expect_assertion(incfg_dname_nlend(&dname,
	                                        "-domain.",
	                                        strlen("-domain.")));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_nlend_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_nlend)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct stroll_lvstr dname;
		size_t              len;

		len = strlen(incfgut_dname_compliant_names[n]);

		incfg_dname_init(&dname);

		incfg_dname_nlend(&dname,
		                  incfgut_dname_compliant_names[n],
		                  len);
		cute_check_str(incfg_dname_get_str(&dname),
		               equal,
		               incfgut_dname_compliant_names[n]);
		cute_check_uint(incfg_dname_get_len(&dname),
		                equal,
		                len);

		incfg_dname_fini(&dname);
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_cede_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_cede(NULL, "host.domain."));
	cute_expect_assertion(incfg_dname_cede(&dname, NULL));
	cute_expect_assertion(incfg_dname_cede(&dname, "-domain."));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_cede_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_cede)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct stroll_lvstr dname;
		char *              str;

		str = strdup(incfgut_dname_compliant_names[n]);
		incfgut_dname_tofree = str;
		cute_check_ptr(str, unequal, NULL);

		incfg_dname_init(&dname);

		incfg_dname_cede(&dname, str);
		cute_check_str(incfg_dname_get_str(&dname),
		               equal,
		               incfgut_dname_compliant_names[n]);
		cute_check_uint(incfg_dname_get_len(&dname),
		                equal,
		                strlen(incfgut_dname_compliant_names[n]));

		incfg_dname_fini(&dname);

		incfgut_dname_tofree = NULL;
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_ncede_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_ncede(NULL,
	                                        "host.domain.",
	                                        strlen("host.domain.")));
	cute_expect_assertion(incfg_dname_ncede(&dname, NULL, 1));
	cute_expect_assertion(incfg_dname_ncede(&dname,
	                                        "host.domain.",
	                                        0));
	cute_expect_assertion(incfg_dname_ncede(&dname,
	                                        "-domain.",
	                                        strlen("-domain.")));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_ncede_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_ncede)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct stroll_lvstr dname;
		size_t              len;
		char *              str;

		len = strlen(incfgut_dname_compliant_names[n]);

		str = strdup(incfgut_dname_compliant_names[n]);
		incfgut_dname_tofree = str;
		cute_check_ptr(str, unequal, NULL);

		incfg_dname_init(&dname);

		incfg_dname_ncede(&dname, str, len);
		cute_check_str(incfg_dname_get_str(&dname),
		               equal,
		               incfgut_dname_compliant_names[n]);
		cute_check_uint(incfg_dname_get_len(&dname),
		                equal,
		                len);

		incfg_dname_fini(&dname);
		incfgut_dname_tofree = NULL;
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_dup_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_dup(NULL, "host.domain."));
	cute_expect_assertion(incfg_dname_dup(&dname, NULL));
	cute_expect_assertion(incfg_dname_dup(&dname, "-domain."));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_dup_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_dup)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct stroll_lvstr dname;
		int                 ret;

		incfg_dname_init(&dname);

		if (!incfgut_expect_malloc())
			cute_check_sint(
				incfg_dname_dup(&dname,
				                incfgut_dname_compliant_names[n]),
				equal,
				-ENOMEM);

		ret = incfg_dname_dup(&dname, incfgut_dname_compliant_names[n]);
		incfgut_dname_tofree = dname.rwstr;
		cute_check_sint(ret, equal, 0);

		cute_check_str(incfg_dname_get_str(&dname),
		               equal,
		               incfgut_dname_compliant_names[n]);
		cute_check_ptr(incfg_dname_get_str(&dname),
		               unequal,
		               incfgut_dname_compliant_names[n]);
		cute_check_uint(incfg_dname_get_len(&dname),
		                equal,
		                strlen(incfgut_dname_compliant_names[n]));

		incfg_dname_fini(&dname);

		incfgut_dname_tofree = NULL;
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_ndup_assert)
{
	struct stroll_lvstr dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_ndup(NULL,
	                                       "host.domain.",
	                                       strlen("host.domain.")));
	cute_expect_assertion(incfg_dname_ndup(&dname, NULL, 1));
	cute_expect_assertion(incfg_dname_ndup(&dname,
	                                       "host.domain.",
	                                       0));
	cute_expect_assertion(incfg_dname_ndup(&dname,
	                                       "host.domain.",
	                                       strlen("host.domain.") + 1));
	cute_expect_assertion(incfg_dname_ndup(&dname,
	                                       "-domain.",
	                                       strlen("-domain.")));

	incfg_dname_fini(&dname);
}

#else  /* !defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_ndup_assert)
{
	cute_skip("assertion unsupported");
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */

CUTE_TEST(incfgut_dname_ndup)
{
	unsigned int n;

	for (n = 0; n < array_nr(incfgut_dname_compliant_names); n++) {
		struct stroll_lvstr dname;
		const char *        str;
		size_t              len;
		int                 ret;

		str = incfgut_dname_compliant_names[n];
		len = strlen(str);

		incfg_dname_init(&dname);

		if (!incfgut_expect_malloc())
			cute_check_sint(
				incfg_dname_ndup(&dname, str, len),
				equal,
				-ENOMEM);

		ret = incfg_dname_ndup(&dname, str, len);
		incfgut_dname_tofree = dname.rwstr;
		cute_check_sint(ret, equal, 0);

		cute_check_str(incfg_dname_get_str(&dname), equal, str);
		cute_check_ptr(incfg_dname_get_str(&dname), unequal, str);
		cute_check_uint(incfg_dname_get_len(&dname), equal, len);

		incfg_dname_fini(&dname);

		incfgut_dname_tofree = NULL;
	}
}

#if  defined(CONFIG_INCFG_ASSERT_API)

CUTE_TEST(incfgut_dname_pack_assert)
{
	struct dpack_encoder enc;
	struct stroll_lvstr  dname;

	incfg_dname_init(&dname);

	cute_expect_assertion(incfg_dname_pack(&dname, NULL));
	cute_expect_assertion(incfg_dname_pack(NULL, &enc));

	incfg_dname_init(&dname);
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
	struct stroll_lvstr  dname;
	const uint8_t        ref[] = "\xac"
	                             "\x68\x6f\x73\x74"
	                             "\x2e"
	                             "\x64\x6f\x6d\x61\x69\x6e"
	                             "\x2e";

	cute_check_uint(INCFG_DNAME_PACKSZ(12), equal, sizeof(ref) - 1);

	memset(buff, 0xff, sizeof(buff));
	dpack_encoder_init_buffer(&enc, buff, sizeof(buff));

	incfg_dname_init(&dname);
	incfg_dname_lend(&dname, "host.domain.");

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
	struct stroll_lvstr  dname;

	incfg_dname_init(&dname);
	incfg_dname_lend(&dname, "host.domain.");

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
	struct stroll_lvstr  dname;

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
	struct dpack_decoder dec;
	const char           buff[] = "\xac"
	                              "\x68\x6f\x73\x74"
	                              "\x2e"
	                              "\x64\x6f\x6d\x61\x69\x6e"
	                              "\x2e";
	struct stroll_lvstr  dname;

	incfg_dname_init(&dname);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_dname_unpack(&dname, &dec), equal, 0);
	incfgut_dname_tofree = dname.rwstr;
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_str(incfg_dname_get_str(&dname), equal, "host.domain.");

	dpack_decoder_fini(&dec);

	incfg_dname_fini(&dname);
	incfgut_dname_tofree = NULL;
}

static void
incfgut_dname_test_unpack_fail(const char * buff, size_t size, int error)
{
	struct dpack_decoder dec;
	struct stroll_lvstr  dname;

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
	struct dpack_decoder dec;
	const char           buff[] = "\xac"
	                              "\x68\x6f\x73\x74"
	                              "\x2e"
	                              "\x64\x6f\x6d\x61\x69\x6e"
	                              "\x2e";
	struct stroll_lvstr  dname;

	incfg_dname_init(&dname);

	dpack_decoder_init_buffer(&dec, buff, sizeof(buff) - 1);

	cute_check_sint(incfg_dname_unpackn_check(&dname, &dec), equal, 0);
	incfgut_dname_tofree = dname.rwstr;
	cute_check_uint(dpack_decoder_data_left(&dec), equal, 0);
	cute_check_str(incfg_dname_get_str(&dname), equal, "host.domain.");

	dpack_decoder_fini(&dec);

	incfg_dname_fini(&dname);
	incfgut_dname_tofree = NULL;
}

static void
incfgut_dname_test_unpackn_check_fail(const char * buff, size_t size, int error)
{
	struct dpack_decoder dec;
	struct stroll_lvstr  dname;

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

	CUTE_REF(incfgut_dname_get_assert),
	CUTE_REF(incfgut_dname_get),

	CUTE_REF(incfgut_dname_lend_assert),
	CUTE_REF(incfgut_dname_lend),
	CUTE_REF(incfgut_dname_nlend_assert),
	CUTE_REF(incfgut_dname_nlend),

	CUTE_REF(incfgut_dname_cede_assert),
	CUTE_REF(incfgut_dname_cede),
	CUTE_REF(incfgut_dname_ncede_assert),
	CUTE_REF(incfgut_dname_ncede),

	CUTE_REF(incfgut_dname_dup_assert),
	CUTE_REF(incfgut_dname_dup),
	CUTE_REF(incfgut_dname_ndup_assert),
	CUTE_REF(incfgut_dname_ndup),

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
