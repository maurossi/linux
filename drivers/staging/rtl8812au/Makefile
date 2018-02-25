EXTRA_CFLAGS += $(USER_EXTRA_CFLAGS)
EXTRA_CFLAGS += -O1
#EXTRA_CFLAGS += -O3
#EXTRA_CFLAGS += -Wall
#EXTRA_CFLAGS += -Wextra
#EXTRA_CFLAGS += -Werror
#EXTRA_CFLAGS += -pedantic
#EXTRA_CFLAGS += -Wshadow -Wpointer-arith -Wcast-qual -Wstrict-prototypes -Wmissing-prototypes

EXTRA_CFLAGS += -Wno-unused-variable
EXTRA_CFLAGS += -Wno-unused-value
EXTRA_CFLAGS += -Wno-unused-label
EXTRA_CFLAGS += -Wno-unused-parameter
EXTRA_CFLAGS += -Wno-unused-function
EXTRA_CFLAGS += -Wno-unused

EXTRA_CFLAGS += -Wno-uninitialized
EXTRA_CFLAGS += -Wno-int-to-pointer-cast

EXTRA_CFLAGS += -I$(src)/include

CONFIG_AUTOCFG_CP = n

CONFIG_MULTIDRV = n

CONFIG_USB_HCI = y
CONFIG_PCI_HCI = n
CONFIG_SDIO_HCI = n
CONFIG_GSPI_HCI = n

CONFIG_MP_INCLUDED = y
CONFIG_POWER_SAVING = y
CONFIG_USB_AUTOSUSPEND = n
CONFIG_HW_PWRP_DETECTION = n
CONFIG_WIFI_TEST = n
CONFIG_BT_COEXIST = n
CONFIG_INTEL_WIDI = n
CONFIG_WAPI_SUPPORT = n
CONFIG_EFUSE_CONFIG_FILE = n
CONFIG_EXT_CLK = n
CONFIG_FTP_PROTECT = n

CONFIG_DRVEXT_MODULE = n

export TopDIR ?= $(shell pwd)

########### COMMON  #################################
HCI_NAME = usb



_OS_INTFS_FILES :=	os_dep/osdep_service.o \
			os_dep/os_intfs.o \
			os_dep/usb_intf.o \
			os_dep/usb_ops_linux.o \
			os_dep/ioctl_linux.o \
			os_dep/xmit_linux.o \
			os_dep/mlme_linux.o \
			os_dep/recv_linux.o \
			os_dep/ioctl_cfg80211.o \
			os_dep/rtw_android.o

_HAL_INTFS_FILES :=	hal/hal_intf.o \
			hal/hal_com.o \
			hal/hal_com_phycfg.o \
			hal/hal_phy.o \
			hal/hal_usb_led.o

_OUTSRC_FILES := hal/odm_debug.o	\
		hal/odm_interface.o\
		hal/odm_HWConfig.o\
		hal/odm.o\
		hal/HalPhyRf.o

		
########### HAL_RTL8812A_RTL8821A #################################

rtl8812a = rtl8812a
MODULE_NAME = 8812au

_HAL_INTFS_FILES +=  hal/HalPwrSeqCmd.o \
					hal/Hal8812PwrSeq.o \
					hal/Hal8821APwrSeq.o\
					hal/$(rtl8812a)_xmit.o\
					hal/$(rtl8812a)_sreset.o

_HAL_INTFS_FILES +=	hal/$(rtl8812a)_hal_init.o \
			hal/$(rtl8812a)_phycfg.o \
			hal/$(rtl8812a)_rf6052.o \
			hal/$(rtl8812a)_dm.o \
			hal/$(rtl8812a)_rxdesc.o \
			hal/$(rtl8812a)_cmd.o \
			hal/usb_halinit.o \
			hal/rtl$(MODULE_NAME)_led.o \
			hal/rtl$(MODULE_NAME)_xmit.o \
			hal/rtl$(MODULE_NAME)_recv.o

_HAL_INTFS_FILES += hal/usb_ops_linux.o

ifeq ($(CONFIG_MP_INCLUDED), y)
_HAL_INTFS_FILES += hal/$(rtl8812a)_mp.o
endif

_OUTSRC_FILES += hal/HalHWImg8812A_FW.o\
		hal/HalHWImg8812A_MAC.o\
		hal/HalHWImg8812A_BB.o\
		hal/HalHWImg8812A_RF.o\
		hal/HalPhyRf_8812A.o\
		hal/odm_RegConfig8812A.o

_OUTSRC_FILES += hal/HalHWImg8821A_FW.o\
		hal/HalHWImg8821A_MAC.o\
		hal/HalHWImg8821A_BB.o\
		hal/HalHWImg8821A_RF.o\
		hal/HalPhyRf_8812A.o\
		hal/HalPhyRf_8821A.o\
		hal/odm_RegConfig8821A.o		

########### AUTO_CFG  #################################	
		
ifeq ($(CONFIG_AUTOCFG_CP), y)

ifeq ($(CONFIG_MULTIDRV), y)	
$(shell cp $(TopDIR)/autoconf_multidrv_usb_linux.h $(TopDIR)/include/autoconf.h)
else
$(shell cp $(TopDIR)/autoconf_$(rtl8812a)_usb_linux.h $(TopDIR)/include/autoconf.h)
endif

endif

########### END OF PATH  #################################


ifeq ($(CONFIG_USB_AUTOSUSPEND), y)
EXTRA_CFLAGS += -DCONFIG_USB_AUTOSUSPEND
endif

ifeq ($(CONFIG_MP_INCLUDED), y)
#MODULE_NAME := $(MODULE_NAME)_mp
EXTRA_CFLAGS += -DCONFIG_MP_INCLUDED
endif

ifeq ($(CONFIG_POWER_SAVING), y)
EXTRA_CFLAGS += -DCONFIG_POWER_SAVING
endif

ifeq ($(CONFIG_HW_PWRP_DETECTION), y)
EXTRA_CFLAGS += -DCONFIG_HW_PWRP_DETECTION
endif

ifeq ($(CONFIG_WIFI_TEST), y)
EXTRA_CFLAGS += -DCONFIG_WIFI_TEST
endif

ifeq ($(CONFIG_BT_COEXIST), y)
EXTRA_CFLAGS += -DCONFIG_BT_COEXIST
endif

ifeq ($(CONFIG_INTEL_WIDI), y)
EXTRA_CFLAGS += -DCONFIG_INTEL_WIDI
endif

ifeq ($(CONFIG_WAPI_SUPPORT), y)
EXTRA_CFLAGS += -DCONFIG_WAPI_SUPPORT
endif

ifeq ($(CONFIG_EFUSE_CONFIG_FILE), y)
EXTRA_CFLAGS += -DCONFIG_EFUSE_CONFIG_FILE
endif

ifeq ($(CONFIG_EXT_CLK), y)
EXTRA_CFLAGS += -DCONFIG_EXT_CLK
endif

ifeq ($(CONFIG_FTP_PROTECT), y)
EXTRA_CFLAGS += -DCONFIG_FTP_PROTECT
endif

SUBARCH := $(shell uname -m | sed -e s/i.86/i386/)
ARCH ?= $(SUBARCH)
CROSS_COMPILE ?=
KVER  := $(shell uname -r)
KSRC := /lib/modules/$(KVER)/build
MODDESTDIR := /lib/modules/$(KVER)/kernel/drivers/net/wireless/
INSTALL_PREFIX :=

ifneq ($(USER_MODULE_NAME),)
MODULE_NAME := $(USER_MODULE_NAME)
endif

ifneq ($(KERNELRELEASE),)

rtk_core :=	core/rtw_cmd.o \
		core/rtw_security.o \
		core/rtw_debug.o \
		core/rtw_io.o \
		core/rtw_ioctl_query.o \
		core/rtw_ioctl_set.o \
		core/rtw_ieee80211.o \
		core/rtw_mlme.o \
		core/rtw_mlme_ext.o \
		core/rtw_wlan_util.o \
		core/rtw_vht.o \
		core/rtw_pwrctrl.o \
		core/rtw_rf.o \
		core/rtw_recv.o \
		core/rtw_sta_mgt.o \
		core/rtw_ap.o \
		core/rtw_xmit.o	\
		core/rtw_p2p.o \
		core/rtw_tdls.o \
		core/rtw_br_ext.o \
		core/rtw_iol.o \
		core/rtw_sreset.o\
		core/efuse/rtw_efuse.o

$(MODULE_NAME)-y += $(rtk_core)

$(MODULE_NAME)-$(CONFIG_INTEL_WIDI) += core/rtw_intel_widi.o

$(MODULE_NAME)-$(CONFIG_WAPI_SUPPORT) += core/rtw_wapi.o	\
					core/rtw_wapi_sms4.o
					
$(MODULE_NAME)-y += $(_OS_INTFS_FILES)
$(MODULE_NAME)-y += $(_HAL_INTFS_FILES)
$(MODULE_NAME)-y += $(_OUTSRC_FILES)

$(MODULE_NAME)-$(CONFIG_MP_INCLUDED) += core/rtw_mp.o \
					core/rtw_mp_ioctl.o

obj-m := $(MODULE_NAME).o

else

all: modules

modules:
	$(MAKE) CROSS_COMPILE=$(CROSS_COMPILE) -C $(KSRC) M=$(shell pwd)  modules

strip:
	$(CROSS_COMPILE)strip $(MODULE_NAME).ko --strip-unneeded

install:
	install -p -m 644 $(MODULE_NAME).ko  $(MODDESTDIR)
	/sbin/depmod -a ${KVER}

uninstall:
	rm -f $(MODDESTDIR)/$(MODULE_NAME).ko
	/sbin/depmod -a ${KVER}

config_r:
	@echo "make config"
	/bin/bash script/Configure script/config.in

.PHONY: modules clean

clean:
	cd hal ; rm -fr */*.mod.c */*.mod */*.o */.*.cmd */*.ko
	cd hal ; rm -fr *.mod.c *.mod *.o .*.cmd *.ko
	cd core/efuse ; rm -fr *.mod.c *.mod *.o .*.cmd *.ko
	cd core ; rm -fr *.mod.c *.mod *.o .*.cmd *.ko
	cd os_dep/linux ; rm -fr *.mod.c *.mod *.o .*.cmd *.ko
	cd os_dep ; rm -fr *.mod.c *.mod *.o .*.cmd *.ko
	rm -fr Module.symvers ; rm -fr Module.markers ; rm -fr modules.order
	rm -fr *.mod.c *.mod *.o .*.cmd *.ko *~
	rm -fr .tmp_versions
endif

