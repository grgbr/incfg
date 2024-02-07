#include "incfg/ipv6.h"
#include "common.h"
#include <dpack/codec.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Use Glibc's inet_pton() primitive here as it is much faster than the
 * `ipv6-address' Perl regular expression used to parse IPv6 that is defined
 * into RFC 6991.
 */

static int
incfg_ipv6_addr_parse_str(struct in6_addr * __restrict addr,
                          const char * __restrict      string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(string);

	int ret;

	ret = inet_pton(AF_INET6, string, addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

void
incfg_ipv6_addr_set_inet(struct in6_addr * __restrict       addr,
                         const struct in6_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	*addr = *inet;
}

const char *
incfg_ipv6_addr_get_str(const struct in6_addr * __restrict addr,
                        char * __restrict                  string)
{
	incfg_assert_api(addr);
	incfg_assert_api(string);

	const char * str;

	str = inet_ntop(AF_INET6, addr, string, INCFG_IPV6_ADDR_STRSZ_MAX);
	incfg_assert_intern(str);

	return str;
}

int
incfg_ipv6_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in6_addr addr;

	return incfg_ipv6_addr_parse_str(&addr, string);
}

int
incfg_ipv6_addr_check_nstr(const char * __restrict string,
                           size_t                  length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INCFG_IPV6_ADDR_STRSZ_MAX) == length);

	struct in6_addr addr;

	return incfg_ipv6_addr_parse_str(&addr, string);
}

int
incfg_ipv6_addr_set_str(struct in6_addr * __restrict addr,
                        const char * __restrict      string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	return incfg_ipv6_addr_parse_str(addr, string);
}

int
incfg_ipv6_addr_set_nstr(struct in6_addr * __restrict addr,
                         const char * __restrict      string,
                         size_t                       length __unused)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);
	incfg_assert_api(strnlen(string, INCFG_IPV6_ADDR_STRSZ_MAX) == length);

	return incfg_ipv6_addr_parse_str(addr, string);
}

int
incfg_ipv6_addr_pack(const struct in6_addr * __restrict addr,
                     struct dpack_encoder *             encoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(encoder);

	return dpack_encode_bin(encoder,
	                        (const char *)&addr->s6_addr,
	                        sizeof(addr->s6_addr));
}

int
incfg_ipv6_addr_unpack(struct in6_addr * __restrict addr,
                       struct dpack_decoder *       decoder)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(decoder);

	ssize_t err;

	err = dpack_decode_bincpy_equ(decoder,
	                              sizeof(addr->s6_addr),
	                              (char *)&addr->s6_addr);

	return (err >= 0) ? 0 : (int)err;
}

#if defined(CONFIG_INCFG_ASSERT_API)

size_t
incfg_ipv6_addr_packsz(const struct in6_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	return INCFG_IPV6_ADDR_PACKSZ;
}

void
incfg_ipv6_addr_init(struct in6_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
}

void
incfg_ipv6_addr_fini(struct in6_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
}

#endif /* defined(CONFIG_INCFG_ASSERT_API) */
