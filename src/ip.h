/******************************************************************************
 * SPDX-License-Identifier: LGPL-3.0-only
 *
 * This file is part of InCfg.
 * Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
 ******************************************************************************/

#ifndef _INCFG_IP_INTERN_H
#define _INCFG_IP_INTERN_H

#include "incfg/ip.h"
#include "common.h"
#include <dpack/codec.h>

extern int
incfg_ip_addr_decode(union incfg_ip_addr * __restrict  addr,
                     enum incfg_addr_type              type,
                     struct dpack_decoder *            decoder);

#endif /* _INCFG_IP_INTERN_H */
