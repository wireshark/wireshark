/* wimax_tlv.c
 * WiMax TLV handling functions
 *
 * Copyright (c) 2007 by Intel Corporation.
 *
 * Author: Lu Pan <lu.pan@intel.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "wimax_tlv.h"

/**************************************************************/
/* init_tlv_info()                                            */
/* retrieve the tlv information from specified tvb and offset */
/* parameter:                                                 */
/*   info - pointer of a tlv information data structure       */
/* return:                                                    */
/*   0-success                                                */
/*   !=0-the invalid size of the TLV length (failed)          */
/**************************************************************/
int init_tlv_info(tlv_info_t *info, tvbuff_t *tvb, int offset)
{
	unsigned tlv_len;

	/* get TLV type */
	info->type = (uint8_t)tvb_get_uint8( tvb, offset );
	/* get TLV length */
	tlv_len = (unsigned)tvb_get_uint8( tvb, (offset + 1) );
	/* set the TLV value offset */
	info->value_offset = 2;
	/* adjust for multiple-byte TLV length */
	if((tlv_len & WIMAX_TLV_EXTENDED_LENGTH_MASK) != 0)
	{	/* multiple bytes TLV length */
		info->length_type = 1;
		/* get the size of the TLV length */
		tlv_len = (tlv_len & WIMAX_TLV_LENGTH_MASK);
		info->size_of_length = tlv_len;
		/* update the TLV value offset */
		info->value_offset += tlv_len;
		switch (tlv_len)
		{
			case 0:
				info->length = 0;  /* no length */
			break;
			case 1:
				info->length = (int32_t)tvb_get_uint8( tvb, (offset + 2) ); /* 8 bit */
			break;
			case 2:
				info->length = (int32_t)tvb_get_ntohs( tvb, (offset + 2) ); /* 16 bit */
			break;
			case 3:
				info->length = (int32_t)tvb_get_ntoh24( tvb, (offset + 2) ); /* 24 bit */
			break;
			case 4:
				info->length = (int32_t)tvb_get_ntohl( tvb, (offset + 2) ); /* 32 bit */
			break;
			default:
				/* mark invalid tlv */
				info->valid = 0;
				/* failed, return the invalid size of the tlv length */
				return (int)tlv_len;
			break;
		}
	}
	else	/* single byte length */
	{
		info->length_type = 0;
		info->size_of_length = 0;
		info->length = (int32_t)tlv_len;
	}
	/* mark valid tlv */
	info->valid = 1;
	/* success */
	return 0;
}

/*************************************************************/
/* get_tlv_type()                                            */
/* get the tlv type of the specified tlv information         */
/* parameter:                                                */
/*   info - pointer of a tlv information data structure      */
/* return:                                                   */
/*   >=0 - TLV type                                           */
/*   =-1 - invalid tlv info                                  */
/*************************************************************/
int get_tlv_type(tlv_info_t *info)
{
	if(info->valid)
		return (int)info->type;
	return -1;
}

/**************************************************************/
/* get_tlv_size_of_length()                                   */
/* get the size of tlv length of the specified tlv information*/
/* parameter:                                                 */
/*   info - pointer of a tlv information data structure       */
/* return:                                                    */
/*   >=0 - the size of TLV length                              */
/*   =-1 - invalid tlv info                                   */
/**************************************************************/
int get_tlv_size_of_length(tlv_info_t *info)
{
	if(info->valid)
		return (int)info->size_of_length;
	return -1;
}

/*************************************************************/
/* get_tlv_length()                                          */
/* get the tlv length of the specified tlv information       */
/* parameter:                                                */
/*   info - pointer of a tlv information data structure      */
/* return:                                                   */
/*   >=0 - TLV length                                         */
/*   =-1 - invalid tlv info                                  */
/*************************************************************/
int32_t get_tlv_length(tlv_info_t *info)
{
	if(info->valid)
		return (int32_t)info->length;
	return -1;
}

/*************************************************************/
/* get_tlv_value_offset()                                    */
/* get the tlv value offset of the specified tlv information */
/* parameter:                                                */
/*   info - pointer of a tlv information data structure      */
/* return:                                                   */
/*   >0 - TLV value offset in byte                           */
/*   =-1 - invalid tlv info                                  */
/*************************************************************/
int get_tlv_value_offset(tlv_info_t *info)
{
	if(info->valid)
		return (int)info->value_offset;
	return -1;
}

/*************************************************************/
/* get_tlv_length_type()                                     */
/* get the tlv length type of the specified tlv information  */
/* parameter:                                                */
/*   info - pointer of a tlv information data structure      */
/* return:                                                   */
/*   0 - single byte TLV length                              */
/*   1 - multiple bytes TLV length                           */
/*************************************************************/
int get_tlv_length_type(tlv_info_t *info)
{
	if(info->valid)
		return (int)info->length_type;
	return -1;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
