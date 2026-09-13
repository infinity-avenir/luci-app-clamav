#
# Copyright (C) 2024 Spark Secure
#
# This is free software, licensed under the Apache License, Version 2.0
#

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI ClamAV Interface
LUCI_DESCRIPTION:=Web interface to configure, monitor, and manage ClamAV antivirus on OpenWrt
LUCI_DEPENDS:=+luci-base +clamav
LUCI_PKGARCH:=all

PKG_NAME:=luci-app-clamav
PKG_VERSION:=1.0.0
PKG_RELEASE:=1
PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=Spark Secure <alan@spark-secure.com>

include $(TOPDIR)/feeds/luci/luci.mk

# call BuildPackage - OpenWrt Buildroot signature
$(eval $(call BuildPackage,luci-app-clamav))
