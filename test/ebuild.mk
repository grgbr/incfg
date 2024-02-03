################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of InCfg.
# Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

# Enable a bunch of warning options and disable -fno-signed-zeros optimization
# since negative floating point zero is tested.
test-cflags  := -Wall \
                -Wextra \
                -Wformat=2 \
                -Wconversion \
                -Wundef \
                -Wshadow \
                -Wcast-qual \
                -Wcast-align \
                -Wmissing-declarations \
                -D_GNU_SOURCE \
                -DINCFG_VERSION_STRING="\"$(VERSION)\"" \
                -I $(TOPDIR)/include \
                $(filter-out -fno-signed-zeros -fassociative-math, \
                             $(EXTRA_CFLAGS)) \
                -fsigned-zeros -fno-associative-math
test-ldflags := $(test-cflags) \
                -L$(BUILDDIR)/../src \
                $(EXTRA_LDFLAGS) \
                -Wl,-z,start-stop-visibility=hidden \
                -Wl,-whole-archive $(BUILDDIR)/builtin.a -Wl,-no-whole-archive \
                -lincfg -lelog

ifneq ($(filter y,$(CONFIG_INCFG_ASSERT_API) $(CONFIG_INCFG_ASSERT_INTERN)),)
test-cflags         := $(filter-out -DNDEBUG,$(test-cflags))
test-ldflags        := $(filter-out -DNDEBUG,$(test-ldflags))
endif # ($(filter y,$(CONFIG_INCFG_ASSERT_API) $(CONFIG_INCFG_ASSERT_INTERN)),)

builtins            := builtin.a
builtin.a-objs      := utest.o $(config-obj)
builtin.a-cflags    := $(test-cflags)

checkbins           := incfg-utest

incfg-utest-objs    += $(call kconf_enabled,INCFG_IPV4,ipv4.o)
incfg-utest-cflags  := $(test-cflags)
incfg-utest-ldflags := $(test-ldflags)
incfg-utest-pkgconf := libdpack libcute

# ex: filetype=make :
