#include "incfg/dns.h"
#include "dns.h"
#include "common.h"

static struct incfg_regex incfg_dns_regex;

#define INCFG_DNS_PATTERN \
	"(?:(?:(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*" \
	"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)" \
	"|\\."

int
incfg_dns_check_nstr(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	if (length > INCFG_DNS_STRLEN_MAX)
		return -EINVAL;

	if (incfg_regex_nmatch(&incfg_dns_regex, string, length))
		return -EINVAL;

	return 0;
}

int
incfg_dns_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	return incfg_dns_check_nstr(string,
	                            strnlen(string, INCFG_DNS_STRSZ_MAX));
}

int
incfg_dns_init(void)
{
	incfg_assert_api(incfg_logger);

	return incfg_regex_init(&incfg_dns_regex,
	                        "domain name",
	                        INCFG_DNS_PATTERN);
}

void
incfg_dns_fini(void)
{
	incfg_assert_api(incfg_logger);

	incfg_regex_fini(&incfg_dns_regex);
}
