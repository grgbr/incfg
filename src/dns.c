#include "incfg/dns.h"
#include "dns.h"
#include "common.h"

static struct incfg_regex incfg_dns_regex;

#define INCFG_DNS_PATTERN \
	"(?:(?:(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.)*" \
	"(?:[a-zA-Z0-9_](?:[a-zA-Z0-9\\-_]){0,61})?[a-zA-Z0-9]\\.?)" \
	"|\\."

int
incfg_dns_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);

	return incfg_regex_match(&incfg_dns_regex, string) ? -EINVAL : 0;
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
