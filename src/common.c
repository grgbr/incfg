#include "common.h"
#include "dns.h"

static const char *
incfg_regex_errstr(int error)
{
	incfg_assert_intern(!error);

	/*
	 * PCRE2 error message storage.
	 *
	 * 128 bytes of memory should be enough as stated into section
	 * 'OBTAINING A TEXTUAL ERROR MESSAGE' of PCRE2's library functions
	 * manual found into file pcre2.txt of PCRE2's User Documentation.
	 */
	static __thread PCRE2_UCHAR msg[128];
	int                         err __unused;

	err = pcre2_get_error_message(error, msg, sizeof(msg));
	incfg_assert_intern(err != PCRE2_ERROR_NOMEMORY);
	incfg_assert_intern(err != PCRE2_ERROR_BADDATA);

	return (const char *)msg;
}

int
incfg_regex_nmatch(const struct incfg_regex * __restrict regex,
                   const char *                          string,
                   size_t                                length)
{
	incfg_assert_intern(regex);
	incfg_assert_intern(regex->name);
	incfg_assert_intern(*regex->name);
	incfg_assert_intern(regex->code);
	incfg_assert_intern(regex->data);
	incfg_assert_intern(string);

	int ret;

	ret = pcre2_match(regex->code,
	                  (const PCRE2_SPTR)string,
	                  length,
	                  0,
	                  PCRE2_ANCHORED | PCRE2_ENDANCHORED | PCRE2_NOTEMPTY,
	                  regex->data,
	                  NULL);
	incfg_assert_intern(ret);
	incfg_assert_intern(ret <= 1);
	incfg_assert_intern(ret != PCRE2_ERROR_BADOFFSET);
	incfg_assert_intern(ret != PCRE2_ERROR_PARTIAL);

	if (ret == 1)
		/* Successful match. */
		return 0;
	else if (ret == PCRE2_ERROR_NOMATCH)
		return -ENOMSG;

	incfg_debug("%s regex matching failed: %s",
	            regex->name,
	            incfg_regex_errstr(ret));

	return -EINVAL;
}

int
incfg_regex_ninit(struct incfg_regex * __restrict regex,
                  const char *         __restrict name,
                  const char *                    pattern,
                  size_t                          length)
{
	incfg_assert_intern(regex);
	incfg_assert_intern(name);
	incfg_assert_intern(*name);
	incfg_assert_intern(pattern);
	incfg_assert_intern(length || (length == PCRE2_ZERO_TERMINATED));

	pcre2_code *       code;
	int                err;
	PCRE2_SIZE         off;
	uint32_t           cnt __unused;
	pcre2_match_data * data;

	code = pcre2_compile((const PCRE2_SPTR)pattern,
	                     length,
	                     0,
	                     &err,
	                     &off,
	                     NULL);
	if (!code) {
		incfg_err("%s regex compilation failed at offset %zu: %s",
		          name,
		          off,
		          incfg_regex_errstr(err));
		return -EINVAL;
	}

	/* Ensure pattern do not carry capture groups !. */
	incfg_assert_intern(!pcre2_pattern_info(code,
	                                        PCRE2_INFO_CAPTURECOUNT,
	                                        &cnt));
	incfg_assert_intern(!cnt);

	data = pcre2_match_data_create(1U, NULL);
	if (!data) {
		incfg_err("%s regex data creation failed at offset %zu",
		          name,
		          off);
		pcre2_code_free(code);
		return -ENOMEM;
	}

	regex->code = code;
	regex->data = data;
	regex->name = name;

	return 0;
}

void
incfg_regex_fini(struct incfg_regex * __restrict regex)
{
	incfg_assert_intern(regex);
	incfg_assert_intern(regex->name);
	incfg_assert_intern(*regex->name);
	incfg_assert_intern(regex->code);
	incfg_assert_intern(regex->data);

	pcre2_match_data_free(regex->data);
	pcre2_code_free(regex->code);
}

struct elog * incfg_logger;

int
incfg_init(struct elog * logger)
{
	incfg_logger = logger;

	return incfg_dns_init();
}

void incfg_fini(void)
{
	incfg_dns_fini();
}
