#include "incfg/ip.h"
#include "common.h"
#include "incfg/ipv4.h"
#include "incfg/ipv6.h"
#include <dpack/codec.h>

void
incfg_ip_addr_set_saddr4(struct incfg_ip_addr * __restrict addr,
                         in_addr_t                         saddr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);

	addr->type = INCFG_ADDR_IPV4_TYPE;
	incfg_ipv4_addr_set_saddr(&addr->ipv4, saddr);
}

void
incfg_ip_addr_set_inet4(struct incfg_ip_addr * __restrict addr,
                        const struct in_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	addr->type = INCFG_ADDR_IPV4_TYPE;
	incfg_ipv4_addr_set_inet(&addr->ipv4, inet);
}

void
incfg_ip_addr_set_inet6(struct incfg_ip_addr * __restrict  addr,
                        const struct in6_addr * __restrict inet)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	addr->type = INCFG_ADDR_IPV6_TYPE;
	incfg_ipv6_addr_set_inet(&addr->ipv6, inet);
}

const char *
incfg_ip_addr_get_str(const struct incfg_ip_addr * __restrict addr)
{
	incfg_assert_api(incfg_logger);
	incfg_assert_api(addr);
	incfg_assert_api(inet);

	const char * str;

	switch (addr->type) {
	case INCFG_ADDR_IPV4_TYPE:
		return incfg_ipv4_addr_get_str(addr);

	case INCFG_ADDR_IPV6_TYPE:
		return incfg_ipv6_addr_get_str(addr);

	case INCFG_ADDR_TYPE_NR:
		return incfg_ipv6_addr_get_str(addr);

	default:
		incfg_assert_api(0);
	}

	unreachable();
}


