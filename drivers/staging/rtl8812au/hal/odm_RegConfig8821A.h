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
#ifndef __INC_ODM_REGCONFIG_H_8821A
#define __INC_ODM_REGCONFIG_H_8821A

void
odm_ConfigRFReg_8821A(
	PDM_ODM_T				pDM_Odm,
	u32					Addr,
	u32					Data,
	ODM_RF_RADIO_PATH_E     RF_PATH,
	u32				    RegAddr
	);

void
odm_ConfigRF_RadioA_8821A(
	PDM_ODM_T				pDM_Odm,
	u32					Addr,
	u32					Data
	);

void
odm_ConfigRF_RadioB_8821A(
	PDM_ODM_T				pDM_Odm,
	u32					Addr,
	u32					Data
	);

void
odm_ConfigMAC_8821A(
	PDM_ODM_T	pDM_Odm,
	u32		Addr,
	u8		Data
	);

void
odm_ConfigBB_AGC_8821A(
    PDM_ODM_T	pDM_Odm,
    u32		Addr,
    u32		Bitmask,
    u32		Data
    );

void
odm_ConfigBB_PHY_REG_PG_8821A(
	PDM_ODM_T	pDM_Odm,
    	u32		Addr,
    	u32		Bitmask,
    	u32		Data
    );

void
odm_ConfigBB_PHY_8821A(
	PDM_ODM_T	pDM_Odm,
    	u32		Addr,
    	u32		Bitmask,
    	u32		Data
    );

void
odm_ConfigBB_TXPWR_LMT_8821A(
	PDM_ODM_T	pDM_Odm,
	const u8 *		Regulation,
	const u8 *		Band,
	const u8 *		Bandwidth,
	const u8 *		RateSection,
	const u8 *		RfPath,
	const u8 *		Channel,
	const u8 *		PowerLimit
    );

#endif
