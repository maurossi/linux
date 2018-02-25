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

#ifndef __HAL_PHY_RF_8812A_H__
#define __HAL_PHY_RF_8812A_H__

/*--------------------------Define Parameters-------------------------------*/
#define	IQK_DELAY_TIME_8812A		10		//ms
#define	IQK_DEFERRED_TIME_8812A		4		//sec
#define	index_mapping_NUM_8812A	15
#define AVG_THERMAL_NUM_8812A	4
#define RF_T_METER_8812A		0x42


void ConfigureTxpowerTrack_8812A(
	PTXPWRTRACK_CFG	pConfig
	);

void
GetDeltaSwingTable_8812A(
	PDM_ODM_T			pDM_Odm,
	u8 *			*TemperatureUP_A,
	u8 *			*TemperatureDOWN_A,
	u8 *			*TemperatureUP_B,
	u8 *			*TemperatureDOWN_B
	);

void DoIQK_8812A(
	PDM_ODM_T	pDM_Odm,
	u8		DeltaThermalIndex,
	u8		ThermalValue,
	u8		Threshold
	);

void
ODM_TxPwrTrackSetPwr8812A(
	PDM_ODM_T			pDM_Odm,
	PWRTRACK_METHOD		Method,
	u8				RFPath,
	u8				ChannelMappedIndex
	);

//1 7.	IQK

void
PHY_IQCalibrate_8812A(
	PADAPTER	pAdapter,
	bool		bReCovery
);


//
// LC calibrate
//
void
PHY_LCCalibrate_8812A(
	PDM_ODM_T		pDM_Odm
);

//
// AP calibrate
//
void
PHY_APCalibrate_8812A(PADAPTER	pAdapter, s1Byte delta);
void
PHY_DigitalPredistortion_8812A(PADAPTER	pAdapter);

void
PHY_DPCalibrate_8812A(
	PDM_ODM_T	pDM_Odm
);
void PHY_SetRFPathSwitch_8812A(
	PADAPTER	pAdapter,
	bool		bMain
	);


#endif	// #ifndef __HAL_PHY_RF_8812A_H__
