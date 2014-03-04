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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*************************************************************/
/*   ----------------------- NOTE -------------------------  */
/* There is an identical copy of this file, wimax_tlv.c, in  */
/* both .../plugins/m2m and .../plugins/wimax.  If either    */
/* one needs to be modified, please be sure to copy the file */
/* to the sister directory and check it in there also.       */
/* This prevents having to generate a complicated            */
/* Makefile.nmake in .../plugins/m2m.                        */
/*************************************************************/

#include "config.h"

#include <plugins/wimax/wimax_tlv.h>

/*************************************************************/
/* init_tlv_info()                                           */
/* retrive the tlv information from specified tvb and offset */
/* parameter:                                                */
/*   info - pointer of a tlv information data structure      */
/* return:                                                   */
/*   0-success                                               */
/*   !=0-the invalid size of the TLV length (failed)         */
/*************************************************************/
gint init_tlv_info(tlv_info_t *info, tvbuff_t *tvb, gint offset)
{
	guint tlv_len;

	/* get TLV type */
	info->type = (guint8)tvb_get_guint8( tvb, offset );
	/* get TLV length */
	tlv_len = (guint)tvb_get_guint8( tvb, (offset + 1) );
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
				info->length = (gint32)tvb_get_guint8( tvb, (offset + 2) ); /* 8 bit */
			break;
			case 2:
				info->length = (gint32)tvb_get_ntohs( tvb, (offset + 2) ); /* 16 bit */
			break;
			case 3:
				info->length = (gint32)tvb_get_ntoh24( tvb, (offset + 2) ); /* 24 bit */
			break;
			case 4:
				info->length = (gint32)tvb_get_ntohl( tvb, (offset + 2) ); /* 32 bit */
			break;
			default:
				/* mark invalid tlv */
				info->valid = 0;
				/* failed, return the invalid size of the tlv length */
				return (gint)tlv_len;
			break;
		}
	}
	else	/* single byte length */
	{
		info->length_type = 0;
		info->size_of_length = 0;
		info->length = (gint32)tlv_len;
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
gint get_tlv_type(tlv_info_t *info)
{
	if(info->valid)
		return (gint)info->type;
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
gint get_tlv_size_of_length(tlv_info_t *info)
{
	if(info->valid)
		return (gint)info->size_of_length;
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
gint32 get_tlv_length(tlv_info_t *info)
{
	if(info->valid)
		return (gint32)info->length;
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
gint get_tlv_value_offset(tlv_info_t *info)
{
	if(info->valid)
		return (gint)info->value_offset;
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
gint get_tlv_length_type(tlv_info_t *info)
{
	if(info->valid)
		return (gint)info->length_type;
	return -1;
}
