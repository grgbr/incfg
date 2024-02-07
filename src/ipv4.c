#include "incfg/ipv4.h"
#include "common.h"
#include <dpack/codec.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Use Glibc's inet_pton() primitive here as it is about 15 times as fast as the
 * Perl regular expression used to parse IPv4 that is defined into RFC 6991 :
 *
 * #define INCFG_IPV4_ADDR_PATTERN \
 * 	"(?:(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}" \
 * 	"(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
 *
 * The regex above is a slightly modified version of `ipv4-address' Perl regular
 * expression defined into RFC 6991 (Common YANG Data Types) with capture groups
 * disabled and no support for IPv4 address zone matching...
 */

static int
incfg_ipv4_addr_parse_str(struct in_addr * __restrict addr,
                          const char * __restrict     string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(string);

	int ret;

	ret = inet_pton(AF_INET, string, addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

void
incfg_ipv4_addr_set_saddr(struct in_addr * __restrict addr, in_addr_t saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	addr->s_addr = htonl(saddr);
}

void
incfg_ipv4_addr_set_inet(struct in_addr * __restrict       addr,
                         const struct in_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	*addr = *inet;
}

const char *
incfg_ipv4_addr_get_str(const struct in_addr * __restrict addr,
                        char * __restrict                 string)
{
	incfg_assert_api(addr);
	incfg_assert_api(string);

	const char * str;

	str = inet_ntop(AF_INET, addr, string, INCFG_IPV4_ADDR_STRSZ_MAX);
	incfg_assert_intern(str);

	return str;
}

int
incfg_ipv4_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in_addr addr;

	return incfg_ipv4_addr_parse_str(&addr, string);
}

int
incfg_ipv4_addr_check_nstr(const char * __restrict string,
                           size_t                  length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INCFG_IPV4_ADDR_STRSZ_MAX) == length);

	struct in_addr addr;

	return incfg_ipv4_addr_parse_str(&addr, string);
}

int
incfg_ipv4_addr_set_str(struct in_addr * __restrict addr,
                        const char * __restrict     string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	return incfg_ipv4_addr_parse_str(addr, string);
}

int
incfg_ipv4_addr_set_nstr(struct in_addr * __restrict addr,
                         const char * __restrict     string,
                         size_t                      length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INCFG_IPV4_ADDR_STRSZ_MAX) == length);

	return incfg_ipv4_addr_parse_str(addr, string);
}

int
incfg_ipv4_addr_pack(const struct in_addr * __restrict addr,
                     struct dpack_encoder *            encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(encoder);

	return dpack_encode_bin(encoder,
	                        (const char *)&addr->s_addr,
	                        sizeof(addr->s_addr));
}

int
incfg_ipv4_addr_unpack(struct in_addr * __restrict addr,
                       struct dpack_decoder *      decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(decoder);

	ssize_t err;

	err = dpack_decode_bincpy_equ(decoder,
	                              sizeof(addr->s_addr),
	                              (char *)&addr->s_addr);

	return (err >= 0) ? 0 : (int)err;
}

#if defined(CONFIG_INCFG_ASSERT_API)

size_t
incfg_ipv4_addr_packsz(const struct in_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	return INCFG_IPV4_ADDR_PACKSZ;
}

void
incfg_ipv4_addr_init(struct in_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
}

void
incfg_ipv4_addr_fini(struct in_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */
