#include "incfg/dname.h"
#include "dname.h"
#include "common.h"

static struct incfg_regex incfg_dname_regex;

#define INCFG_DNAME_PATTERN \
	"(?:(?:(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*" \
	"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)" \
	"|\\."

static int
incfg_dname_validate(const struct incfg_addr * __restrict dname)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(dname);
	incfg_assert_intern(dname->type == INCFG_ADDR_DNAME_TYPE);

	return incfg_dname_ncheck(stroll_lvstr_cstr(&dname->lvstr),
	                          stroll_lvstr_len(&dname->lvstr));
}

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

	if (!length || (length > INCFG_DNAME_STRLEN_MAX))
		return -EINVAL;

	if (incfg_regex_nmatch(&incfg_dname_regex, string, length))
		return -EINVAL;

	return 0;
}

const struct stroll_lvstr *
incfg_dname_get(const struct incfg_addr * __restrict dname)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(!incfg_dname_validate(dname));

	return &dname->lvstr;
}

int
incfg_dname_set(struct incfg_addr * __restrict dname, const char * string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(!incfg_dname_check(string));

	int err __unused;

	err = stroll_lvstr_dup(&dname->lvstr, string);
	incfg_assert_intern(err != -E2BIG);

	return err;
}

int
incfg_dname_nset(struct incfg_addr * __restrict dname,
                 const char *                   string,
                 size_t                         length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(!incfg_dname_ncheck(string, length));

	int err __unused;

	err = stroll_lvstr_ndup(&dname->lvstr, string, length);
	incfg_assert_intern(err != -E2BIG);

	return err;
}

size_t
incfg_dname_packsz(const struct incfg_addr * __restrict dname)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(!incfg_dname_validate(dname));

	return dpack_str_size(stroll_lvstr_len(&dname->lvstr));
}

int
incfg_dname_pack(const struct incfg_addr * __restrict dname,
                 struct dpack_encoder *               encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(!incfg_dname_validate(dname));
	incfg_assert_api(encoder);

	return dpack_encode_lvstr(encoder, &dname->lvstr);
}

int
incfg_dname_unpack(struct incfg_addr *  __restrict dname,
                   struct dpack_decoder *          decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(decoder);

	ssize_t err;

	err = dpack_decode_lvstr_max(decoder,
	                             INCFG_DNAME_STRLEN_MAX,
	                             &dname->lvstr);
	if (err < 0)
		return (int)err;

	incfg_assert_api(!incfg_dname_validate(dname));

	return 0;
}

int
incfg_dname_unpackn_check(struct incfg_addr *  __restrict dname,
                          struct dpack_decoder *          decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);
	incfg_assert_api(decoder);

	char *  str;
	ssize_t len;

	len = dpack_decode_strdup_max(decoder, INCFG_DNAME_STRLEN_MAX, &str);
	if (len < 0)
		return (int)len;

	if (incfg_dname_ncheck(str, (size_t)len)) {
		free(str);
		return -EINVAL;
	}

	stroll_lvstr_ncede(&dname->lvstr, str, (size_t)len);

	return 0;
}

void
incfg_dname_init(struct incfg_addr * __restrict dname)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);

	dname->type = INCFG_ADDR_DNAME_TYPE;
	stroll_lvstr_init(&dname->lvstr);
}

void
incfg_dname_fini(struct incfg_addr * __restrict dname)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(dname);
	incfg_assert_api(dname->type == INCFG_ADDR_DNAME_TYPE);

	stroll_lvstr_fini(&dname->lvstr);
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
