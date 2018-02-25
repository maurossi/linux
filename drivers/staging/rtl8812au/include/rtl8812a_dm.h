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
#ifndef __RTL8812A_DM_H__
#define __RTL8812A_DM_H__

void rtl8812_init_dm_priv(PADAPTER Adapter);
void rtl8812_deinit_dm_priv(PADAPTER Adapter);
void rtl8812_InitHalDm(PADAPTER Adapter);
void rtl8812_HalDmWatchDog(PADAPTER Adapter);

//void rtl8192c_dm_CheckTXPowerTracking(PADAPTER Adapter);

//void rtl8192c_dm_RF_Saving(PADAPTER pAdapter, u8 bForceInNormal);

#ifdef CONFIG_ANTENNA_DIVERSITY
void	AntDivCompare8812(PADAPTER Adapter, WLAN_BSSID_EX *dst, WLAN_BSSID_EX *src);
u8 AntDivBeforeLink8812(PADAPTER Adapter );
#endif
#endif
