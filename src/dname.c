#include "incfg/dname.h"
#include "common.h"
#include "dname.h"

static struct incfg_regex incfg_dname_regex;

#define INCFG_DNAME_PATTERN \
	"(?:(?:(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*" \
	"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)" \
	"|\\."

int
incfg_dname_check(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	return incfg_dname_ncheck(string,
	                          strnlen(string,
	                                  INCFG_DNAME_STRSZ_MAX));
}

int
incfg_dname_ncheck(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	if (length > INCFG_DNAME_STRLEN_MAX)
		return -EINVAL;

	if (incfg_regex_nmatch(&incfg_dname_regex, string, length))
		return -EINVAL;

	return 0;
}

void
incfg_dname_lend(struct stroll_lvstr * __restrict dname, const char * name)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(name);
	incfg_assert_api(incfg_dname_check(name));

	int err __unused;

	err = stroll_lvstr_lend(dname, name);
	incfg_assert_intern(!err);
}

void
incfg_dname_nlend(struct stroll_lvstr * __restrict dname,
                  const char *                     name,
                  size_t                           length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(name);
	incfg_assert_api(incfg_dname_check(name));
	incfg_assert_api(incfg_dname_ncheck(name, length));
	incfg_assert_api(strnlen(name, INCFG_DNAME_STRSZ_MAX) == length);

	stroll_lvstr_nlend(dname, name, length);
}

void
incfg_dname_cede(struct stroll_lvstr * __restrict dname, char * name)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(name);
	incfg_assert_api(incfg_dname_check(name));

	int err __unused;

	err = stroll_lvstr_cede(dname, name);
	incfg_assert_intern(!err);
}

void
incfg_dname_ncede(struct stroll_lvstr * __restrict dname,
                  char *                           name,
                  size_t                           length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(name);
	incfg_assert_api(incfg_dname_ncheck(name, length));
	incfg_assert_api(strnlen(name, INCFG_DNAME_STRSZ_MAX) == length);

	stroll_lvstr_ncede(dname, name, length);
}

void
incfg_dname_dup(struct stroll_lvstr * __restrict dname, const char * name)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(name);
	incfg_assert_api(incfg_dname_check(name));

	int err __unused;

	err = stroll_lvstr_dup(dname, name);
	incfg_assert_intern(!err);
}

void
incfg_dname_ndup(struct stroll_lvstr * __restrict dname,
                 const char *                     name,
                 size_t                           length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(name);
	incfg_assert_api(incfg_dname_ncheck(name, length));
	incfg_assert_api(strnlen(name, INCFG_DNAME_STRSZ_MAX) >= length);

	int err __unused;

	err = stroll_lvstr_ndup(dname, name, length);
	incfg_assert_intern(!err);
}

size_t
incfg_dname_packsz(size_t len)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(len);

	return dpack_lvstr_size(len);
}

int
incfg_dname_pack(const struct stroll_lvstr * __restrict dname,
                 struct dpack_encoder *                 encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(incfg_dname_ncheck(stroll_lvstr_cstr(dname),
	                                    stroll_lvstr_len(dname)));
	incfg_assert_api(encoder);

	return dpack_encode_lvstr(encoder, dname);
}

ssize_t
incfg_dname_unpack(struct stroll_lvstr *  __restrict dname,
                   struct dpack_decoder *            decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(decoder);

	return dpack_decode_lvstr_max(decoder, INCFG_DNAME_STRLEN_MAX, dname);
}

ssize_t
incfg_dname_checkn_unpack(struct stroll_lvstr *  __restrict dname,
                          struct dpack_decoder *            decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(decoder);

	char *  str;
	ssize_t len;

	len = dpack_decode_strdup_max(decoder, INCFG_DNAME_STRLEN_MAX, &str);
	if (len < 0)
		return len;

	if (incfg_dname_ncheck(str, (size_t)len)) {
		free(str);
		return -EINVAL;
	}

	stroll_lvstr_ncede(dname, str, (size_t)len);

	return 0;
}

void
incfg_dname_init(struct stroll_lvstr * __restrict dname)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);

	stroll_lvstr_init(dname);
}

void
incfg_dname_fini(struct stroll_lvstr * __restrict dname)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);

	stroll_lvstr_fini(dname);
}

int
incfg_dname_init_lib(void)
{
	incfg_assert_api(incfg_logger);

	return incfg_regex_init(&incfg_dname_regex,
	                        "domain name",
	                        INCFG_DNAME_PATTERN);
}

void
incfg_dname_fini_lib(void)
{
	incfg_assert_api(incfg_logger);

	incfg_regex_fini(&incfg_dname_regex);
}
