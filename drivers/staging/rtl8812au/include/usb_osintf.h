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
#ifndef __USB_OSINTF_H
#define __USB_OSINTF_H

#include <usb_vendor_req.h>

#define USBD_HALTED(Status) ((u32)(Status) >> 30 == 3)


//uint usb_dvobj_init(_adapter * adapter);
//void usb_dvobj_deinit(_adapter * adapter);

u8 usbvendorrequest(struct dvobj_priv *pdvobjpriv, RT_USB_BREQUEST brequest, RT_USB_WVALUE wvalue, u8 windex, void* data, u8 datalen, u8 isdirectionin);


#endif
