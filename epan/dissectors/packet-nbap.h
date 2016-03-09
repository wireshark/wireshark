/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nbap.h                                                              */
/* asn2wrs.py -p nbap -c ./nbap.cnf -s ./packet-nbap-template -D . -O ../.. NBAP-CommonDataTypes.asn NBAP-Constants.asn NBAP-Containers.asn NBAP-IEs.asn NBAP-PDU-Contents.asn NBAP-PDU-Descriptions.asn */

/* Input file: packet-nbap-template.h */

#line 1 "./asn1/nbap/packet-nbap-template.h"
/* packet-nbap-template.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#ifndef PACKET_NBAP_H
#define PACKET_NBAP_H

#include "packet-rlc.h"
#include "packet-umts_mac.h"

/*
 * Ericsson specific mapping for various dissector settings.
 * Must be altered for other equipment.
 */

/*Array are indexed on logical channel id, meaning they need to be defined for 1-15*/
/* Mapping from logical channel id to MAC content type ie. DCCH or DTCH*/
extern guint8 lchId_type_table[];

/* Mapping logicalchannel id to RLC_MODE */
extern guint8 lchId_rlc_map[];

#if 0
static const value_string lchid_name_resolve[] = {
	{1,"DCCH"},	/* 1 to 4 SRB => DCCH*/
	{2,"DCCH"},
	{3,"DCCH"},
	{4,"DCCH"},
	{8,"DCCH"},	/* 8 SRB => DCCH*/
	{9,"DTCH"},	/*9 maps to DTCH*/
	{10,"UNKNOWN"},	/*10 Conv CS unknown*/
	{11,"DTCH"},	/*11 Interactive PS => DTCH*/
	{12,"DTCH"},	/*12 13 Streaming PS => DTCH*/
	{13,"DTCH"},
	{14,"DTCH"},	/*14 Interatictive PS => DTCH*/
	{15,"MAC_CONTENT_UNKNOWN"},
	{0, NULL}	/* This is CCCH? */
};
#endif
#endif
