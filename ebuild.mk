################################################################################
# SPDX-License-Identifier: LGPL-3.0-only
#
# This file is part of InCfg.
# Copyright (C) 2024 Grégor Boirie <gregor.boirie@free.fr>
################################################################################

config-in  := Config.in
config-h   := $(PACKAGE)/config.h
config-obj := config.o

ifneq ($(realpath $(kconf_config)),)
ifeq ($(call kconf_is_enabled,INCFG_ENABLED),)
$(error Invalid build configuration !)
endif # ($(call kconf_is_enabled,INCFG_ENABLED),)
endif # ($(realpath $(kconf_config)),)

HEADERDIR := $(CURDIR)/include
headers   := $(PACKAGE)/cdefs.h
headers   := $(PACKAGE)/common.h
headers   += $(call kconf_enabled,INCFG_IPV4,$(PACKAGE)/ipv4.h)
headers   += $(call kconf_enabled,INCFG_IPV6,$(PACKAGE)/ipv6.h)
headers   += $(call kconf_enabled,INCFG_DNAME,$(PACKAGE)/dname.h)

subdirs   := src

ifeq ($(CONFIG_INCFG_UTEST),y)
subdirs   += test
test-deps := src
endif # ($(CONFIG_INCFG_UTEST),y)

define libincfg_pkgconf_tmpl
prefix=$(PREFIX)
exec_prefix=$${prefix}
libdir=$${exec_prefix}/lib
includedir=$${prefix}/include

Name: libincfg
Description: incfg library
Version: %%PKG_VERSION%%
Requires.private: libdpack libstroll libelog libpcre2-8
Cflags: -I$${includedir}
Libs: -L$${libdir} -lincfg
endef

pkgconfigs       := libincfg.pc
libincfg.pc-tmpl := libincfg_pkgconf_tmpl

################################################################################
# Source code tags generation
################################################################################

tagfiles := $(shell find $(addprefix $(CURDIR)/,$(subdirs)) \
                    $(HEADERDIR) \
                    -type f)

################################################################################
# Documentation generation
################################################################################

doxyconf  := $(CURDIR)/sphinx/Doxyfile
doxyenv   := SRCDIR="$(HEADERDIR) $(SRCDIR)/src"
