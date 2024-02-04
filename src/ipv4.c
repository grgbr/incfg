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

static int
incfg_ipv4_addr_strncpy(char * __restrict       addr,
                        const char * __restrict string,
                        size_t                  length)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(string);

	if (!length || (length > INCFG_IPV4_ADDR_STRLEN_MAX))
		return -EINVAL;

	memcpy(addr, string, length);
	addr[length] = '\0';

	return 0;
}

static int
incfg_ipv4_addr_parse_str(struct in_addr * __restrict addr,
                          const char * __restrict     string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(string);
	incfg_assert_intern(addr);

	int ret;

	ret = inet_pton(AF_INET, string, addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

static int
incfg_ipv4_addr_parse_nstr(struct in_addr * __restrict addr,
                           const char * __restrict     string,
                           size_t                      length)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(addr);
	incfg_assert_intern(string);

	char str[INCFG_IPV4_ADDR_STRSZ_MAX];
	int  err;

	err = incfg_ipv4_addr_strncpy(str, string, length);
	if (err)
		return err;

	return incfg_ipv4_addr_parse_str(addr, str);
}

int
incfg_ipv4_addr_check_nstr(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in_addr addr;

	return incfg_ipv4_addr_parse_nstr(&addr, string, length);
}

int
incfg_ipv4_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	struct in_addr addr;

	return incfg_ipv4_addr_parse_str(&addr, string);
}

const char *
incfg_ipv4_addr_str(const union incfg_ipv4_addr * __restrict addr,
                    char * __restrict                        string)
{
	incfg_assert_api(addr);
	incfg_assert_api(string);

	const char * str;

	str = inet_ntop(AF_INET,
	                &addr->inet,
	                string,
	                INCFG_IPV4_ADDR_STRSZ_MAX);
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
incfg_ipv4_addr_setup_nstr(union incfg_ipv4_addr * __restrict addr,
                           const char * __restrict            string,
                           size_t                             length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	return incfg_ipv4_addr_parse_nstr(&addr->inet, string, length);
}

int
incfg_ipv4_addr_setup_str(union incfg_ipv4_addr * __restrict addr,
                          const char * __restrict            string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(string);

	return incfg_ipv4_addr_parse_str(&addr->inet, string);
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

	return dpack_decode_bincpy_equ(decoder,
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

static union incfg_ipv4_addr *
incfg_ipv4_addr_build_str(const char * __restrict string)
{
	incfg_assert_intern(incfg_logger);
	incfg_assert_intern(string);

	union incfg_ipv4_addr * addr;
	int                     err;

	addr = incfg_ipv4_addr_alloc();
	if (!addr)
		return NULL;

	err = incfg_ipv4_addr_parse_str(&addr->inet, string);
	if (err) {
		incfg_ipv4_addr_free(addr);
		errno = -err;
		return NULL;
	}

	return addr;
}

union incfg_ipv4_addr *
incfg_ipv4_addr_create_nstr(const char * __restrict string, size_t length)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	char str[INCFG_IPV4_ADDR_STRSZ_MAX];
	int  err;

	err = incfg_ipv4_addr_strncpy(str, string, length);
	if (err) {
		errno = -err;
		return NULL;
	}

	return incfg_ipv4_addr_build_str(str);
}

union incfg_ipv4_addr *
incfg_ipv4_addr_create_str(const char * __restrict string)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(string);

	return incfg_ipv4_addr_build_str(string);
}
