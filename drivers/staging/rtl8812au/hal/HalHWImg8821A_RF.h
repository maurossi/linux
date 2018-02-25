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

#ifndef __INC_MP_RF_HW_IMG_8821A_H
#define __INC_MP_RF_HW_IMG_8821A_H

static bool CheckCondition(const u32 Condition, const u32 Hex);

/******************************************************************************
*                           RadioA.TXT
******************************************************************************/

void
ODM_ReadAndConfig_MP_8821A_RadioA( // TC: Test Chip, MP: MP Chip
	PDM_ODM_T  pDM_Odm
);

/******************************************************************************
*                           TxPowerTrack_AP.TXT
******************************************************************************/

void
ODM_ReadAndConfig_MP_8821A_TxPowerTrack_AP( // TC: Test Chip, MP: MP Chip
	PDM_ODM_T  pDM_Odm
);

/******************************************************************************
*                           TxPowerTrack_PCIE.TXT
******************************************************************************/

void
ODM_ReadAndConfig_MP_8821A_TxPowerTrack_PCIE( // TC: Test Chip, MP: MP Chip
	PDM_ODM_T  pDM_Odm
);

/******************************************************************************
*                           TxPowerTrack_USB.TXT
******************************************************************************/

void
ODM_ReadAndConfig_MP_8821A_TxPowerTrack_USB( // TC: Test Chip, MP: MP Chip
	PDM_ODM_T  pDM_Odm
);

/******************************************************************************
*                           TXPWR_LMT.TXT
******************************************************************************/

void
ODM_ReadAndConfig_MP_8821A_TXPWR_LMT( // TC: Test Chip, MP: MP Chip
	PDM_ODM_T  pDM_Odm
);

#endif
