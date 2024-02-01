/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#include "utest.h"
#include "incfg/ipv4.h"
#include <cute/cute.h>
#include <cute/check.h>
#include <cute/expect.h>
#include <errno.h>

CUTE_TEST(incfgut_ipv4_addr_to_str)
{
	union incfg_ipv4_addr addr0 = INCFG_IPV4_ADDR_INIT(0, 0, 0, 0);
	union incfg_ipv4_addr addr1 = INCFG_IPV4_ADDR_INIT(192, 168, 7, 10);
	union incfg_ipv4_addr addr2 = INCFG_IPV4_ADDR_INIT(255, 255, 255, 255);
	union incfg_ipv4_addr addr3 = INCFG_IPV4_ADDR_INIT(169, 254, 0, 0);

	char                  str[INCFG_IPV4_ADDR_STRSZ];

	incfg_ipv4_addr_to_str(&addr0, str);
	cute_check_str(str, equal, "0.0.0.0");

	incfg_ipv4_addr_to_str(&addr1, str);
	cute_check_str(str, equal, "192.168.7.10");

	incfg_ipv4_addr_to_str(&addr2, str);
	cute_check_str(str, equal, "255.255.255.255");

	incfg_ipv4_addr_to_str(&addr3, str);
	cute_check_str(str, equal, "169.254.0.0");
}

CUTE_GROUP(incfgut_ipv4_group) = {
	CUTE_REF(incfgut_ipv4_addr_to_str),
};

CUTE_SUITE_EXTERN(incfgut_ipv4_suite,
                  incfgut_ipv4_group,
                  CUTE_NULL_SETUP,
                  CUTE_NULL_TEARDOWN,
                  CUTE_DFLT_TMOUT);
