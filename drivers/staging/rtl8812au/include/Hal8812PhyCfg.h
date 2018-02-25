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
#ifndef __INC_HAL8812PHYCFG_H__
#define __INC_HAL8812PHYCFG_H__


/*--------------------------Define Parameters-------------------------------*/
#define LOOP_LIMIT				5
#define MAX_STALL_TIME			50		//us
#define AntennaDiversityValue	0x80	//(Adapter->bSoftwareAntennaDiversity ? 0x00:0x80)
#define MAX_TXPWR_IDX_NMODE_92S	63
#define Reset_Cnt_Limit			3


#ifdef CONFIG_PCI_HCI
#define MAX_AGGR_NUM	0x0B
#else
#define MAX_AGGR_NUM	0x07
#endif // CONFIG_PCI_HCI


/*--------------------------Define Parameters-------------------------------*/

/*------------------------------Define structure----------------------------*/


/* BB/RF related */

/*------------------------------Define structure----------------------------*/


/*------------------------Export global variable----------------------------*/
/*------------------------Export global variable----------------------------*/


/*------------------------Export Marco Definition---------------------------*/
/*------------------------Export Marco Definition---------------------------*/


/*--------------------------Exported Function prototype---------------------*/
//
// BB and RF register read/write
//
u32	PHY_QueryBBReg8812(	PADAPTER	Adapter,
				u32			RegAddr,
				u32			BitMask	);
void	PHY_SetBBReg8812(	PADAPTER		Adapter,
				u32			RegAddr,
				u32			BitMask,
				u32			Data	);
u32	PHY_QueryRFReg8812(	PADAPTER	Adapter,
				u8			eRFPath,
				u32			RegAddr,
				u32			BitMask	);
void	PHY_SetRFReg8812(	PADAPTER		Adapter,
				u8			eRFPath,
				u32			RegAddr,
				u32			BitMask,
				u32			Data	);

//
// Initialization related function
//
/* MAC/BB/RF HAL config */
int	PHY_MACConfig8812(PADAPTER	Adapter	);
int	PHY_BBConfig8812(PADAPTER	Adapter	);
void	PHY_BB8812_Config_1T(PADAPTER	Adapter );
int	PHY_RFConfig8812(PADAPTER	Adapter	);

void
PHY_InitPowerLimitTable(
	PDM_ODM_T	pDM_Odm
	);

void
PHY_ConvertPowerLimitToPowerIndex(
	PADAPTER			Adapter
	);

void
PHY_SetPowerLimitTableValue(
	PDM_ODM_T		pDM_Odm,
	const s8*				Regulation,
	const s8*				Band,
	const s8*				Bandwidth,
	const s8*				RateSection,
	const s8*				RfPath,
	const s8*				Channel,
	const s8*				PowerLimit
	);

u8
PHY_GetPowerLimitValue(
	PADAPTER			Adapter,
	u32					RegPwrTblSel,
	BAND_TYPE			Band,
	CHANNEL_WIDTH		Bandwidth,
	RF_PATH				RfPath,
	u8					DataRate,
	u8					Channel
	);

/* RF config */

s32
PHY_SwitchWirelessBand8812(
	PADAPTER		Adapter,
	u8			Band
);

//
// BB TX Power R/W
//
void	PHY_GetTxPowerLevel8812(PADAPTER	Adapter, u32*	powerlevel	);
void	PHY_SetTxPowerLevel8812(PADAPTER	Adapter, u8	Channel	);
bool	PHY_UpdateTxPowerDbm8812(PADAPTER	Adapter, int	powerInDbm	);
u32 PHY_GetTxPowerIndex_8812A(
	PADAPTER			pAdapter,
	u8					RFPath,
	u8					Rate,
	CHANNEL_WIDTH		BandWidth,
	u8					Channel
	);

u32 PHY_GetTxBBSwing_8812A(
	PADAPTER	Adapter,
	BAND_TYPE	Band,
	u8			RFPath
	);

void
PHY_SetTxPowerIndex_8812A(
	PADAPTER			Adapter,
	u32				PowerIndex,
	u8				RFPath,
	u8				Rate
	);
//
// Switch bandwidth for 8192S
//
void
PHY_SetBWMode8812(
	PADAPTER			pAdapter,
	CHANNEL_WIDTH		Bandwidth,
	u8					Offset
);

//
// channel switch related funciton
//
void
PHY_SwChnl8812(
	PADAPTER	Adapter,
	u8			channel
);


void
PHY_SetSwChnlBWMode8812(
	PADAPTER			Adapter,
	u8					channel,
	CHANNEL_WIDTH		Bandwidth,
	u8					Offset40,
	u8					Offset80
);

//
// BB/MAC/RF other monitor API
//

void
PHY_SetRFPathSwitch_8812A(
	PADAPTER	pAdapter,
	bool		bMain
);

void
storePwrIndexDiffRateOffset(
	PADAPTER	Adapter,
	u32		RegAddr,
	u32		BitMask,
	u32		Data
	);

/*--------------------------Exported Function prototype---------------------*/
#endif	// __INC_HAL8192CPHYCFG_H
