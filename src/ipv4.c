#include "incfg/ipv4.h"
#include "common.h"
#include <dpack/codec.h>
#include <arpa/inet.h>
#include <errno.h>

/*
 * Use Glibc's inet_pton() primitive here as it is about 15 times as fast as a
 * Perl regular expression used to parse IPv4 addresses such as :
 *
 * #define INCFG_IPV4_ADDR_PATTERN \
 * 	"(?:(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\\.){3}" \
 * 	"(?:[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5])"
 *
 * The regex above is a slightly modified version of `ipv4-address' Perl regular
 * expression defined into rfc 6991 (Common YANG Data Types) with capture groups
 * disabled and no support for IPv4 address zone matching...
 */
int
incfg_ipv4_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in_addr addr;
	int            ret;

	ret = inet_pton(AF_INET, string, &addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

const char *
incfg_ipv4_addr_str(const union incfg_ipv4_addr * __restrict addr,
                    char * __restrict                        string)
{
	incfg_assert_api(addr);
	incfg_assert_api(string);

	const char * str;

	str = inet_ntop(AF_INET, &addr->inet, string, INCFG_IPV4_ADDR_STRSZ);
	incfg_assert_intern(str);

	return str;
}

void
incfg_ipv4_addr_setup_saddr(union incfg_ipv4_addr * __restrict addr,
                            in_addr_t                          saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	addr->inet.s_addr = htonl(saddr);
}

void
incfg_ipv4_addr_setup_inet(union incfg_ipv4_addr * __restrict addr,
                           const struct in_addr * __restrict  inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	addr->inet = *inet;
}

int
incfg_ipv4_addr_setup_str(union incfg_ipv4_addr * __restrict addr,
                          const char * __restrict            string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	int ret;

	ret = inet_pton(AF_INET, string, &addr->inet);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

int
incfg_ipv4_addr_pack(struct dpack_encoder *                   encoder,
                     const union incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(encoder);
	incfg_assert_api(addr);

	return dpack_encode_bin(encoder,
	                        (const char *)addr->bytes,
	                        sizeof(addr->bytes));
}

ssize_t
incfg_ipv4_addr_unpack(struct dpack_decoder *             decoder,
                       union incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(decoder);
	incfg_assert_api(addr);

	return dpack_decode_bincpy(decoder,
	                           sizeof(addr->bytes),
	                           (char *)addr->bytes);
}

union incfg_ipv4_addr *
incfg_ipv4_addr_create_saddr(in_addr_t saddr)
{
	incfg_assert_api(incfg_logger);
	union incfg_ipv4_addr * addr;

	addr = incfg_ipv4_addr_alloc();
	if (!addr)
		return NULL;

	incfg_ipv4_addr_setup_saddr(addr, saddr);

	return addr;
}

union incfg_ipv4_addr *
incfg_ipv4_addr_create_inet(const struct in_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(inet);

	union incfg_ipv4_addr * addr;

	addr = incfg_ipv4_addr_alloc();
	if (!addr)
		return NULL;

	incfg_ipv4_addr_setup_inet(addr, inet);

	return addr;
}

union incfg_ipv4_addr *
incfg_ipv4_addr_create_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	union incfg_ipv4_addr * addr;
	int                     err;

	addr = incfg_ipv4_addr_alloc();
	if (!addr)
		return NULL;

	err = incfg_ipv4_addr_setup_str(addr, string);
	if (err) {
		incfg_ipv4_addr_free(addr);
		errno = -err;
		return NULL;
	}

	return addr;
}
