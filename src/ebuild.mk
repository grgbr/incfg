################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of InCfg.
# Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

common-cflags         := -Wall \
                         -Wextra \
                         -Wformat=2 \
                         -Wconversion \
                         -Wundef \
                         -Wshadow \
                         -Wcast-qual \
                         -Wcast-align \
                         -Wmissing-declarations \
                         -D_GNU_SOURCE \
                         -I $(TOPDIR)/include \
                         $(filter-out -ffinite-math-only,$(EXTRA_CFLAGS)) \
                         -fno-finite-math-only \
                         -fvisibility=hidden
common-ldflags        := $(common-cflags) \
                         $(EXTRA_LDFLAGS) \
                         -Wl,-z,start-stop-visibility=hidden

# When assertions are enabled, ensure NDEBUG macro is not set to enable glibc
# assertions.
ifneq ($(filter y,$(CONFIG_INCFG_ASSERT_API) $(CONFIG_INCFG_ASSERT_INTERN)),)
common-cflags         := $(filter-out -DNDEBUG,$(common-cflags))
common-ldflags        := $(filter-out -DNDEBUG,$(common-ldflags))
endif # ($(filter y,$(CONFIG_INCFG_ASSERT_API) $(CONFIG_INCFG_ASSERT_INTERN)),)

solibs                := libincfg.so
libincfg.so-objs      := shared/common.o
libincfg.so-objs      += $(call kconf_enabled,INCFG_IPV4,shared/ipv4.o)
libincfg.so-objs      += $(call kconf_enabled,INCFG_DNS,shared/dns.o)
libincfg.so-cflags    := $(filter-out -fpie -fPIE,$(common-cflags)) -fpic
libincfg.so-ldflags   := $(filter-out -fpie -fPIE,$(common-ldflags)) \
                         -shared -fpic -Bsymbolic -Wl,-soname,libincfg.so
libincfg.so-pkgconf   := libdpack libstroll libelog libpcre2-8

arlibs                := libincfg.a
libincfg.a-objs       := static/common.o
libincfg.a-objs       += $(call kconf_enabled,INCFG_IPV4,static/ipv4.o)
libincfg.a-objs       += $(call kconf_enabled,INCFG_DNS,static/dns.o)
libincfg.a-cflags     := $(common-cflags)

# vim: filetype=make :
