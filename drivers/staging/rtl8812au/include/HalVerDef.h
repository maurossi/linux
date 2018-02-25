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
#ifndef __HAL_VERSION_DEF_H__
#define __HAL_VERSION_DEF_H__

// HAL_IC_TYPE_E
typedef enum tag_HAL_IC_Type_Definition
{
	CHIP_8812	=	0,
	CHIP_8821	=	1,
}HAL_IC_TYPE_E;

//HAL_CHIP_TYPE_E
typedef enum tag_HAL_CHIP_Type_Definition
{
	TEST_CHIP		=	0,
	NORMAL_CHIP	=	1,
	FPGA			=	2,
}HAL_CHIP_TYPE_E;

//HAL_CUT_VERSION_E
typedef enum tag_HAL_Cut_Version_Definition
{
	A_CUT_VERSION		=	0,
	B_CUT_VERSION		=	1,
	C_CUT_VERSION		=	2,
	D_CUT_VERSION		=	3,
	E_CUT_VERSION		=	4,
	F_CUT_VERSION		=	5,
	G_CUT_VERSION		=	6,
}HAL_CUT_VERSION_E;

// HAL_Manufacturer
typedef enum tag_HAL_Manufacturer_Version_Definition
{
	CHIP_VENDOR_TSMC	=	0,
	CHIP_VENDOR_UMC		=	1,
	CHIP_VENDOR_SMIC	=	2,
}HAL_VENDOR_E;

typedef enum tag_HAL_RF_Type_Definition
{
	RF_TYPE_1T1R	=	0,
	RF_TYPE_1T2R	=	1,
	RF_TYPE_2T2R	=	2,
	RF_TYPE_2T3R	=	3,
	RF_TYPE_2T4R	=	4,
	RF_TYPE_3T3R	=	5,
	RF_TYPE_3T4R	=	6,
	RF_TYPE_4T4R	=	7,
}HAL_RF_TYPE_E;

typedef	struct tag_HAL_VERSION
{
	HAL_IC_TYPE_E		ICType;
	HAL_CHIP_TYPE_E		ChipType;
	HAL_CUT_VERSION_E	CUTVersion;
	HAL_VENDOR_E		VendorType;
	HAL_RF_TYPE_E		RFType;
	u8					ROMVer;
}HAL_VERSION,*PHAL_VERSION;

// Get element
#define GET_CVID_IC_TYPE(version)			(((version).ICType)	)
#define GET_CVID_CHIP_TYPE(version)			(((version).ChipType)	)
#define GET_CVID_RF_TYPE(version)			(((version).RFType))
#define GET_CVID_MANUFACTUER(version)		(((version).VendorType))
#define GET_CVID_CUT_VERSION(version)		(((version).CUTVersion))
#define GET_CVID_ROM_VERSION(version)		(((version).ROMVer) & ROM_VERSION_MASK)

//----------------------------------------------------------------------------
//Common Macro. --
//----------------------------------------------------------------------------
//HAL_VERSION VersionID

// HAL_IC_TYPE_E
#define IS_8812_SERIES(version)		((GET_CVID_IC_TYPE(version) == CHIP_8812)? true : false)
#define IS_8821_SERIES(version)		((GET_CVID_IC_TYPE(version) == CHIP_8821)? true : false)


//HAL_CHIP_TYPE_E
#define IS_TEST_CHIP(version)		((GET_CVID_CHIP_TYPE(version)==TEST_CHIP)? true: false)
#define IS_NORMAL_CHIP(version)		((GET_CVID_CHIP_TYPE(version)==NORMAL_CHIP)? true: false)

//HAL_CUT_VERSION_E
#define IS_A_CUT(version)		((GET_CVID_CUT_VERSION(version) == A_CUT_VERSION) ? true : false)
#define IS_B_CUT(version)		((GET_CVID_CUT_VERSION(version) == B_CUT_VERSION) ? true : false)
#define IS_C_CUT(version)		((GET_CVID_CUT_VERSION(version) == C_CUT_VERSION) ? true : false)
#define IS_D_CUT(version)		((GET_CVID_CUT_VERSION(version) == D_CUT_VERSION) ? true : false)
#define IS_E_CUT(version)		((GET_CVID_CUT_VERSION(version) == E_CUT_VERSION) ? true : false)


//HAL_VENDOR_E
#define IS_CHIP_VENDOR_TSMC(version)	((GET_CVID_MANUFACTUER(version) == CHIP_VENDOR_TSMC)? true: false)
#define IS_CHIP_VENDOR_UMC(version)	((GET_CVID_MANUFACTUER(version) == CHIP_VENDOR_UMC)? true: false)
#define IS_CHIP_VENDOR_SMIC(version)	((GET_CVID_MANUFACTUER(version) == CHIP_VENDOR_SMIC)? true: false)

//HAL_RF_TYPE_E
#define IS_1T1R(version)		((GET_CVID_RF_TYPE(version) == RF_TYPE_1T1R)? true : false )
#define IS_1T2R(version)		((GET_CVID_RF_TYPE(version) == RF_TYPE_1T2R)? true : false)
#define IS_2T2R(version)		((GET_CVID_RF_TYPE(version) == RF_TYPE_2T2R)? true : false)


//----------------------------------------------------------------------------
//Chip version Macro. --
//----------------------------------------------------------------------------

#define IS_VENDOR_8812A_TEST_CHIP(_Adapter)	((IS_8812_SERIES(GET_HAL_DATA(_Adapter)->VersionID)) ? ((IS_NORMAL_CHIP(GET_HAL_DATA(_Adapter)->VersionID)) ? false : true) : false)
#define IS_VENDOR_8812A_MP_CHIP(_Adapter)	((IS_8812_SERIES(GET_HAL_DATA(_Adapter)->VersionID)) ? ((IS_NORMAL_CHIP(GET_HAL_DATA(_Adapter)->VersionID)) ? true : false) : false)
#define IS_VENDOR_8812A_C_CUT(_Adapter)		((IS_8812_SERIES(GET_HAL_DATA(_Adapter)->VersionID)) ? ((GET_CVID_CUT_VERSION(GET_HAL_DATA(_Adapter)->VersionID) == C_CUT_VERSION) ? true : false) : false)

#define IS_VENDOR_8821A_TEST_CHIP(_Adapter)	((IS_8821_SERIES(GET_HAL_DATA(_Adapter)->VersionID)) ? ((IS_NORMAL_CHIP(GET_HAL_DATA(_Adapter)->VersionID)) ? false : true) : false)
#define IS_VENDOR_8821A_MP_CHIP(_Adapter)	((IS_8821_SERIES(GET_HAL_DATA(_Adapter)->VersionID)) ? ((IS_NORMAL_CHIP(GET_HAL_DATA(_Adapter)->VersionID)) ? true : false) : false)

#endif
