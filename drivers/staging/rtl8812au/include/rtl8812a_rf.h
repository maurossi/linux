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
#ifndef __RTL8812A_RF_H__
#define __RTL8812A_RF_H__

void
PHY_RF6052SetBandwidth8812(
	PADAPTER				Adapter,
	CHANNEL_WIDTH		Bandwidth);


int
PHY_RF6052_Config_8812(
	PADAPTER	Adapter	);

void
PHY_RF6052SetCckTxPower8812(
	PADAPTER	Adapter,
	u8*			pPowerlevel);

void
PHY_RF6052SetOFDMTxPower8812(
	PADAPTER	Adapter,
	u8*			pPowerLevelOFDM,
	u8*			pPowerLevelBW20,
	u8*			pPowerLevelBW40,
	u8			Channel);

#endif//__RTL8188E_RF_H__
