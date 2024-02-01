#include "incfg/ipv4.h"
#include "common.h"
#include <dpack/codec.h>
#include <arpa/inet.h>
#include <errno.h>

int
incfg_ipv4_addr_check_str(const char * __restrict string)
{
	incfg_assert_api(string);

	struct in_addr addr;
	int            ret;

	ret = inet_pton(AF_INET, string, &addr);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

int
incfg_ipv4_addr_from_str(union incfg_ipv4_addr * __restrict addr,
                         const char * __restrict            string)
{
	incfg_assert_api(addr);
	incfg_assert_api(string);

	int ret;

	ret = inet_pton(AF_INET, string, &addr->inet);
	incfg_assert_intern(ret >= 0);

	return ret ? 0 : -EINVAL;
}

void
incfg_ipv4_addr_to_str(union incfg_ipv4_addr * __restrict addr,
                       char * __restrict                  string)
{
	incfg_assert_api(addr);
	incfg_assert_api(string);

	const char * str __unused;

	str = inet_ntop(AF_INET, &addr->inet, string, INCFG_IPV4_ADDR_STRSZ);
	incfg_assert_intern(str);
}

void
incfg_ipv4_addr_from_inet(union incfg_ipv4_addr * __restrict addr,
                          const struct in_addr * __restrict  inet)
{
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	addr->inet = *inet;
}

int
incfg_ipv4_addr_pack(struct dpack_encoder *                   encoder,
                     const union incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(encoder);
	incfg_assert_api(addr);
	incfg_assert_api(dpack_encoder_space_left(encoder) >=
	                 INCFG_IPV4_ADDR_PACKSZ);

	return dpack_encode_bin(encoder,
	                        (const char *)addr->bytes,
	                        sizeof(addr->bytes));
}

ssize_t
incfg_ipv4_addr_unpack(struct dpack_decoder *             decoder,
                       union incfg_ipv4_addr * __restrict addr)
{
	incfg_assert_api(decoder);
	incfg_assert_api(addr);
	incfg_assert_api(dpack_decoder_data_left(decoder) >=
	                 INCFG_IPV4_ADDR_PACKSZ);

	return dpack_decode_bincpy(decoder,
	                           sizeof(addr->bytes),
	                           (char *)addr->bytes);
}

union incfg_ipv4_addr *
incfg_ipv4_addr_alloc(void)
{
	return malloc(sizeof(union incfg_ipv4_addr));
}

void
incfg_ipv4_addr_free(union incfg_ipv4_addr * addr)
{
	free(addr);
}
