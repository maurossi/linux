/******************************************************************************
 *
 * Copyright(c) 2007 - 2011 Realtek Corporation. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 ******************************************************************************/
//***** temporarily flag *******
#define CONFIG_SINGLE_IMG
#define CONFIG_ODM_REFRESH_RAMASK
#define CONFIG_PHY_SETTING_WITH_ODM
//for FPGA VERIFICATION config
#define RTL8188E_FPGAtrue_PHY_VERIFICATION 0

//***** temporarily flag *******
/*
 * Public  General Config
 */
#define AUTOCONF_INCLUDED
#define RTL871X_MODULE_NAME "8812AU"
#define DRV_NAME "rtl8812au"

#define PLATFORM_LINUX	1

#ifdef CONFIG_IOCTL_CFG80211
	#define CONFIG_CFG80211_FORCE_COMPATIBLE_2_6_37_UNDER
	#define CONFIG_SET_SCAN_DENY_TIMER
#endif

/*
 * Internal  General Config
 */

#define CONFIG_EMBEDDED_FWIMG	1

#define CONFIG_80211N_HT	1

#ifdef CONFIG_80211N_HT
	#define CONFIG_80211AC_VHT 1
#endif

#define CONFIG_RECV_REORDERING_CTRL	1

#define CONFIG_DFS	1

#define CONFIG_IPS	1

#define CONFIG_LPS	1

#ifdef CONFIG_LPS_LCLK
#define CONFIG_XMIT_THREAD_MODE
#endif

//after link
#ifdef CONFIG_ANTENNA_DIVERSITY
#define CONFIG_HW_ANTENNA_DIVERSITY
#endif

#ifdef CONFIG_CONCURRENT_MODE
	#define CONFIG_TSF_RESET_OFFLOAD 1		// For 2 PORT TSF SYNC.
#endif

#define CONFIG_AP_MODE	1
#ifdef CONFIG_AP_MODE
	#if defined(CONFIG_CONCURRENT_MODE) && defined(CONFIG_INTERRUPT_BASED_TXBCN)
		#undef CONFIG_INTERRUPT_BASED_TXBCN
	#endif
	#ifdef CONFIG_INTERRUPT_BASED_TXBCN
		#define CONFIG_INTERRUPT_BASED_TXBCN_BCN_OK_ERR
	#endif

	#define CONFIG_NATIVEAP_MLME
	#ifndef CONFIG_NATIVEAP_MLME
		#define CONFIG_HOSTAPD_MLME	1
	#endif
	#define CONFIG_FIND_BEST_CHANNEL	1
#endif

#define CONFIG_P2P	1
#ifdef CONFIG_P2P
	//The CONFIG_WFD is for supporting the Wi-Fi display
	#define CONFIG_WFD

	#ifndef CONFIG_WIFI_TEST
		#define CONFIG_P2P_REMOVE_GROUP_INFO
	#endif

	#define CONFIG_P2P_PS
#endif

#define CONFIG_SKB_COPY	1//for amsdu

#define CONFIG_LED
#ifdef CONFIG_LED
	#define CONFIG_SW_LED
#endif // CONFIG_LED

#ifdef CONFIG_IOL
	#define CONFIG_IOL_READ_EFUSE_MAP
	#define CONFIG_IOL_LLT
#endif

#define USB_INTERFERENCE_ISSUE // this should be checked in all usb interface
#define CONFIG_GLOBAL_UI_PID

#define CONFIG_LAYER2_ROAMING
#define CONFIG_LAYER2_ROAMING_RESUME
#define CONFIG_LONG_DELAY_ISSUE
#define CONFIG_NEW_SIGNAL_STAT_PROCESS
#define RTW_NOTCH_FILTER 0 /* 0:Disable, 1:Enable, */

#define CONFIG_BR_EXT	1	// Enable NAT2.5 support for STA mode interface with a L2 Bridge
#ifdef CONFIG_BR_EXT
#define CONFIG_BR_EXT_BRNAME	"br0"
#endif	// CONFIG_BR_EXT

#define CONFIG_TX_MCAST2UNI	1	// Support IP multicast->unicast

/*
 * Interface  Related Config
 */

#ifndef CONFIG_MINIMAL_MEMORY_USAGE
	#define CONFIG_USB_TX_AGGREGATION	1
	#define CONFIG_USB_RX_AGGREGATION	1
#endif

#define CONFIG_PREALLOC_RECV_SKB	1

/*
 * CONFIG_USE_USB_BUFFER_ALLOC_XX uses Linux USB Buffer alloc API and is for Linux platform only now!
 */

#ifdef CONFIG_USE_USB_BUFFER_ALLOC_RX
#undef CONFIG_PREALLOC_RECV_SKB
#endif

/*
 * USB VENDOR REQ BUFFER ALLOCATION METHOD
 * if not set we'll use function local variable (stack memory)
 */
#define CONFIG_USB_VENDOR_REQ_BUFFER_PREALLOC

#define CONFIG_USB_VENDOR_REQ_MUTEX
#define CONFIG_VENDOR_REQ_RETRY

/*
 * HAL  Related Config
 */
#define RTL8812A_RX_PACKET_INCLUDE_CRC	0

#define CONFIG_OUT_EP_WIFI_MODE	0

#define ENABLE_USB_DROP_INCORRECT_OUT	0

#define RTL8192CU_ADHOC_WORKAROUND_SETTING	1

#define ENABLE_NEW_RFE_TYPE	0

#define DISABLE_BB_RF	0

#ifdef CONFIG_MP_INCLUDED
	#define MP_DRIVER 1
	#define CONFIG_MP_IWPRIV_SUPPORT	1
#else
	#define MP_DRIVER 0
#endif

/*
 * Outsource  Related Config
 */

#define RTL8723_FPGA_VERIFICATION		0

#define RATE_ADAPTIVE_SUPPORT		0
#define POWER_TRAINING_ACTIVE			0

#define	RTL8188E_EARLY_MODE_PKT_NUM_10	0

#define CONFIG_80211D

#define CONFIG_ATTEMPT_TO_FIX_AP_BEACON_ERROR

/*
 * Debug Related Config
 */
#define DBG	0
