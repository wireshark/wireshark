/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-nbap.h                                                              */
/* ../../tools/asn2wrs.py -p nbap -c ./nbap.cnf -s ./packet-nbap-template -D . -O ../../epan/dissectors NBAP-CommonDataTypes.asn NBAP-Constants.asn NBAP-Containers.asn NBAP-IEs.asn NBAP-PDU-Contents.asn NBAP-PDU-Descriptions.asn */

/* Input file: packet-nbap-template.h */

#line 1 "../../asn1/nbap/packet-nbap-template.h"
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
static const guint8 lchId_rlc_map[] = {
	0,
	RLC_UM,	/* Logical channel id = 1 is SRB1 which uses RLC_UM*/
	RLC_AM,
	RLC_AM,
	RLC_AM,
	RLC_TM,	/*5 to 7 Conv CS Speech*/
	RLC_TM,
	RLC_TM, /*...*/
	RLC_AM,
	RLC_AM,
	RLC_AM,
	RLC_AM,
	RLC_AM,
	RLC_AM,
	RLC_AM,
	RLC_AM,	/* This is CCCH which is UM?, probably not */
	};

/* 1 to 8*/
static const guint8 hsdsch_macdflow_id_rlc_map[] = {
	RLC_UM,	           /*1 SRB */
	RLC_AM,            /*2 Interactive PS*/
	RLC_AM,	           /*3 Interatcive PS*/
	RLC_UNKNOWN_MODE, /*4 ???*/
	RLC_AM,	          /*5 Streaming PS*/
	RLC_UNKNOWN_MODE,
	RLC_UNKNOWN_MODE
	};

/* Mapping hsdsch MACd-FlowId to MAC_CONTENT, basically flowid = 1 (0) => SRB*/
/* 1 to 8*/
static const guint8 hsdsch_macdflow_id_mac_content_map[] = {
	MAC_CONTENT_DCCH,	/*1 SRB */
	MAC_CONTENT_PS_DTCH, /*2 Interactive PS*/
	MAC_CONTENT_PS_DTCH,	/*3 Interatcive PS*/
	RLC_UNKNOWN_MODE, /*4 ???*/
	MAC_CONTENT_PS_DTCH,	/*5 Streaming PS*/
	RLC_UNKNOWN_MODE,
	RLC_UNKNOWN_MODE,
	RLC_UNKNOWN_MODE
	};

/* Make fake logical channel id's based on MACdFlow-ID's*/
static const guint8 fake_lchid_macd_flow[] = {1,9,14,11,0,12};

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
