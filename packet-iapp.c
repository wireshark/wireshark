/* packet-iapp.c
 * Routines for IAPP dissection
 * Copyright 2002, Alfred Arnold <aarnold@elsa.de>
 *
 * $Id: packet-iapp.c,v 1.1 2002/02/02 12:04:22 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "oui.h"

/* Initialize the protocol and registered fields */
static int proto_iapp = -1;
static int hf_iapp_version = -1;
static int hf_iapp_type = -1;

/* Initialize the subtree pointers */
static gint ett_iapp = -1;
static gint ett_iapp_pdu = -1;
static gint ett_iapp_cap = -1;
static gint ett_iapp_auth = -1;

#define UDP_PORT_IAPP     2313

#define IAPP_ANNOUNCE_REQUEST  0 
#define IAPP_ANNOUNCE_RESPONSE 1 
#define IAPP_HANDOVER_REQUEST 2 
#define IAPP_HANDOVER_RESPONSE 3 

#define IAPP_PDU_SSID 0
#define IAPP_PDU_BSSID 1
#define IAPP_PDU_OLDBSSID 2
#define IAPP_PDU_MSADDR 3
#define IAPP_PDU_CAPABILITY 4
#define IAPP_PDU_ANNOUNCEINT 5
#define IAPP_PDU_HOTIMEOUT 6
#define IAPP_PDU_MESSAGEID 7
#define IAPP_PDU_PHYTYPE 0x10
#define IAPP_PDU_REGDOMAIN 0x11
#define IAPP_PDU_CHANNEL 0x12
#define IAPP_PDU_BEACONINT 0x13
#define IAPP_PDU_OUIIDENT 0x80
#define IAPP_PDU_AUTHINFO 0x81

#define IAPP_CAP_FORWARDING 0x40
#define IAPP_CAP_WEP 0x20

#define IAPP_PHY_PROP 0x00
#define IAPP_PHY_FHSS 0x01
#define IAPP_PHY_DSSS 0x02
#define IAPP_PHY_IR 0x03
#define IAPP_PHY_OFDM 0x04

#define IAPP_DOM_FCC 0x10
#define IAPP_DOM_IC 0x20
#define IAPP_DOM_ETSI 0x30
#define IAPP_DOM_SPAIN 0x31
#define IAPP_DOM_FRANCE 0x32
#define IAPP_DOM_MKK 0x40

#define IAPP_AUTH_STATUS 0x01
#define IAPP_AUTH_USERNAME 0x02
#define IAPP_AUTH_PROVNAME 0x03
#define IAPP_AUTH_RXPKTS 0x04
#define IAPP_AUTH_TXPKTS 0x05
#define IAPP_AUTH_RXBYTES 0x06
#define IAPP_AUTH_TXBYTES 0x07
#define IAPP_AUTH_LOGINTIME 0x08
#define IAPP_AUTH_TIMELIMIT 0x09
#define IAPP_AUTH_VOLLIMIT 0x0a
#define IAPP_AUTH_ACCCYCLE 0x0b
#define IAPP_AUTH_RXGWORDS 0x0c
#define IAPP_AUTH_TXGWORDS 0x0d
#define IAPP_AUTH_IPADDR 0x0e
#define IAPP_AUTH_TRAILER 0xff


typedef struct _e_iapphdr {
        guint8 ia_version;
        guint8 ia_type;
} e_iapphdr;

typedef struct _e_pduhdr {
	guint8 pdu_type;
	guint8 pdu_len_h;
	guint8 pdu_len_l;
} e_pduhdr;

static value_string iapp_vals[] = {
  {IAPP_ANNOUNCE_REQUEST, "Announce Request"},
  {IAPP_ANNOUNCE_RESPONSE, "Announce Response"},
  {IAPP_HANDOVER_REQUEST, "Handover Request"},
  {IAPP_HANDOVER_RESPONSE, "Handover Response"},
  {0, NULL}};

static value_string iapp_pdu_type_vals[] = {
  {IAPP_PDU_SSID, "Network Name"},
  {IAPP_PDU_BSSID, "BSSID"},
  {IAPP_PDU_OLDBSSID, "Old BSSID"},
  {IAPP_PDU_MSADDR, "Mobile Station Address"},
  {IAPP_PDU_CAPABILITY, "Capabilities"},
  {IAPP_PDU_ANNOUNCEINT, "Announce Interval"},
  {IAPP_PDU_HOTIMEOUT, "Handover Timeout"},
  {IAPP_PDU_MESSAGEID, "Message ID"},
  {IAPP_PDU_PHYTYPE, "PHY Type"},
  {IAPP_PDU_REGDOMAIN, "Regulatory Domain"},
  {IAPP_PDU_CHANNEL, "Radio Channel"},
  {IAPP_PDU_BEACONINT, "Beacon Interval"},
  {IAPP_PDU_OUIIDENT, "OUI Identifier"},
  {IAPP_PDU_AUTHINFO, "ELSA Authentication Info"},
  {0, NULL}};

static value_string iapp_cap_vals[] = {
  {IAPP_CAP_FORWARDING, "Forwarding"},
  {IAPP_CAP_WEP, "WEP"},
  {0, NULL}};

static value_string iapp_phy_vals[] = {
  {IAPP_PHY_PROP, "Proprietary"},
  {IAPP_PHY_FHSS, "FHSS"},
  {IAPP_PHY_DSSS, "DSSS"},
  {IAPP_PHY_IR, "Infrared"},
  {IAPP_PHY_OFDM, "OFDM"},
  {0, NULL}};

static value_string iapp_dom_vals[] = {
  {IAPP_DOM_FCC, "FCC (USA)"},
  {IAPP_DOM_IC, "IC (Canada)"},
  {IAPP_DOM_ETSI, "ETSI (Europe)"},
  {IAPP_DOM_SPAIN, "Spain"},
  {IAPP_DOM_FRANCE, "France"},
  {IAPP_DOM_MKK, "MKK (Japan)"},
  {0, NULL}};

static value_string iapp_auth_type_vals[] = {
  {IAPP_AUTH_STATUS, "Status"},
  {IAPP_AUTH_USERNAME, "User Name"},
  {IAPP_AUTH_PROVNAME, "Provider Name"},
  {IAPP_AUTH_RXPKTS, "Received Packets"},
  {IAPP_AUTH_TXPKTS, "Transmitted Packets"},
  {IAPP_AUTH_RXBYTES, "Received Octets"},
  {IAPP_AUTH_TXBYTES, "Transmitted Octets"},
  {IAPP_AUTH_LOGINTIME, "Session Time"},
  {IAPP_AUTH_TIMELIMIT, "Time Limit"},
  {IAPP_AUTH_VOLLIMIT, "Volume Limit"},
  {IAPP_AUTH_ACCCYCLE, "Accounting Cycle"},
  {IAPP_AUTH_TRAILER, "Authenticator"},
  {IAPP_AUTH_RXGWORDS, "Received Gigawords"},
  {IAPP_AUTH_TXGWORDS, "Transmitted Gigawords"},
  {IAPP_AUTH_IPADDR, "Client IP Address"},
  {0, NULL}};


static gchar textbuffer[2000];

gchar *iaconvertbufftostr(gchar *dest, tvbuff_t *tvb, int offset, int length)
{
/*converts the raw buffer into printable text */
	guint32 i;
	guint32 totlen=0;
	const guint8 *pd = tvb_get_ptr(tvb, offset, length);

        dest[0]='"';
        dest[1]=0;
        totlen=1;
        for (i=0; i < (guint32)length; i++)
        {
                if( isalnum((int)pd[i])||ispunct((int)pd[i])
                                ||((int)pd[i]==' '))            {
                        dest[totlen]=(gchar)pd[i];
                        totlen++;
                }
                else
                {
                        sprintf(&(dest[totlen]), "\\%03u", pd[i]);
                        totlen=totlen+strlen(&(dest[totlen]));
                }
        }
        dest[totlen]='"';
        dest[totlen+1]=0;
        return dest;
}

/* dissect a capability bit field */

static void dissect_caps(proto_item *pitem, tvbuff_t *tvb, int offset)
{
	proto_tree *captree;
	int bit, val, z, thisbit;
	gchar *strval, bitval[20];

	captree = proto_item_add_subtree(pitem, ett_iapp_cap);
	val = tvb_get_guint8(tvb, offset + 3);

	bitval[8] = '\0';
	for (bit = 7; bit >= 0; bit--)
	{
		strval = match_strval(1 << bit, iapp_cap_vals);
		if (strval)
		{
			thisbit = (val & (1 << bit)) ? 1 : 0;
			for (z = 0; z < 7; z++)
				if (z == 7 - bit)
					bitval[z] = thisbit + '0';
				else
					bitval[z] = '.';
			proto_tree_add_text(captree, tvb, offset + 3, 1, "%s %s: %s",
				bitval, strval, thisbit ? "Yes" : "No");
		}
	}
}

static gchar*
authval_to_str(int type, int len, tvbuff_t *tvb, int offset)
{
	gchar *run;
	const guint8 *mac;
	int z, val;
	gchar *strval;

	run = textbuffer;
	run += sprintf(run, "Value: ");

	switch (type)
	{
		case IAPP_AUTH_STATUS:
			strcpy(textbuffer, tvb_get_guint8(tvb, offset + 3) ? "Authenticated" : "Not authenticated");
			break;
		case IAPP_AUTH_USERNAME:
		case IAPP_AUTH_PROVNAME:
			iaconvertbufftostr(run, tvb, offset + 3, len);
			break;
		case IAPP_AUTH_RXPKTS:
		case IAPP_AUTH_TXPKTS:
		case IAPP_AUTH_RXBYTES:
		case IAPP_AUTH_TXBYTES:
		case IAPP_AUTH_RXGWORDS:
		case IAPP_AUTH_TXGWORDS:
		case IAPP_AUTH_VOLLIMIT:
			val = tvb_get_ntohl(tvb, offset + 3);
			run += sprintf(run, "%d", val);
			break;
		case IAPP_AUTH_LOGINTIME:
		case IAPP_AUTH_TIMELIMIT:
		case IAPP_AUTH_ACCCYCLE:
			val = tvb_get_ntohl(tvb, offset + 3);
                        run += sprintf(run, "%d seconds", val);
			break;
		case IAPP_AUTH_IPADDR:
			run += sprintf(run, "%d.%d.%d.%d", 
				tvb_get_guint8(tvb, offset + 3),
				tvb_get_guint8(tvb, offset + 4),
				tvb_get_guint8(tvb, offset + 5),
				tvb_get_guint8(tvb, offset + 6));
			break;
		case IAPP_AUTH_TRAILER:
			for (z = 0; z < len; z++)
			run += sprintf(run, " %02x", tvb_get_guint8(tvb, offset + 3 + z));
			break;
	}
	
	return textbuffer;
}

/* dissect authentication info */

static void dissect_authinfo(proto_item *pitem, tvbuff_t *tvb, int offset, int sumlen)
{
	proto_tree *authtree;
        e_pduhdr pduhdr;
	gchar *authstrval, *valstr;
	int len;

	authtree = proto_item_add_subtree(pitem, ett_iapp_auth);

	while (sumlen > 0)
	{
		tvb_memcpy(tvb, (guint8 *)&pduhdr, offset, sizeof(e_pduhdr));
		len = (((int)pduhdr.pdu_len_h) << 8) + pduhdr.pdu_len_l;

		authstrval = val_to_str(pduhdr.pdu_type, iapp_auth_type_vals,
			"Unknown PDU Type");
		valstr = authval_to_str(pduhdr.pdu_type, len, tvb, offset);
		proto_tree_add_text(authtree, tvb, offset, len + 3, "%s(%d) %s",
			authstrval, pduhdr.pdu_type, valstr);

		sumlen -= (len + 3);
		offset += (len + 3);
	}
}

/* get displayable values of PDU contents */

static int is_fhss = 0;

static gchar*
pduval_to_str(int type, int len, tvbuff_t *tvb, int offset)
{
	gchar *run;
	const guint8 *mac;
	int z, val;
	gchar *strval;

	run = textbuffer;
	run += sprintf(run, "Value: ");

	switch (type)
	{
		case IAPP_PDU_SSID:
			iaconvertbufftostr(run, tvb, offset + 3, len);
			break;
		case IAPP_PDU_BSSID:
		case IAPP_PDU_OLDBSSID:
		case IAPP_PDU_MSADDR:
			mac = tvb_get_ptr(tvb, offset + 3, len);
			for (z = 0; z < len; z++)
				run += sprintf(run, "%s%02x", z ? ":" : "", mac[z]);
			break;
		case IAPP_PDU_CAPABILITY:
		{
			int mask, first = 1;
			
			val = tvb_get_guint8(tvb, offset + 3);
			run += sprintf(run, "%02x (", val);
			for (mask = 0x80; mask; mask >>= 1)
				if (val & mask)
				{
					strval = match_strval(mask, iapp_cap_vals);
					if (strval)
					{
						if (!first)
							run += sprintf(run, " ");
						run += sprintf(run, strval);
					}
				}
			run += sprintf(run, ")");
			break;
		}
		case IAPP_PDU_ANNOUNCEINT:
			val = tvb_get_ntohs(tvb, offset + 3);
			run += sprintf(run, "%d seconds", val);
			break;
		case IAPP_PDU_HOTIMEOUT:
		case IAPP_PDU_BEACONINT:
			val = tvb_get_ntohs(tvb, offset + 3);
			run += sprintf(run, "%d Kus", val);
			break;
		case IAPP_PDU_MESSAGEID:
			val = tvb_get_ntohs(tvb, offset + 3);
			run += sprintf(run, "%d", val);
			break;
		case IAPP_PDU_PHYTYPE:
			val = tvb_get_guint8(tvb, offset + 3);
			strval = val_to_str(val, iapp_phy_vals, "Unknown");
			run += sprintf(run, strval);
                        is_fhss = (val == IAPP_PHY_FHSS);
			break;
		case IAPP_PDU_REGDOMAIN:
			val = tvb_get_guint8(tvb, offset + 3);
			strval = val_to_str(val, iapp_dom_vals, "Unknown");
			run += sprintf(run, strval);
			break;
		case IAPP_PDU_CHANNEL:
			val = tvb_get_guint8(tvb, offset + 3);
			if (is_fhss)
				run += sprintf(run, "Pattern set %d, sequence %d",
						((val >> 6) & 3) + 1, (val & 31) + 1);
			else
				run += sprintf(run, "%d", val);
			break;
		case IAPP_PDU_OUIIDENT:
			for (val = z = 0; z < 3; z++)
				val = (val << 8) | tvb_get_guint8(tvb, offset + 3 + z);
			strval = val_to_str(val, oui_vals, "Unknown");
			run += sprintf(run, strval);
			break;
	}
	
	return textbuffer;
}

/* code to dissect a list of PDUs */

static void 
dissect_pdus(tvbuff_t *tvb, int offset, proto_tree *pdutree, int pdulen)
{
	e_pduhdr pduhdr;
	int len;
	gchar *pdustrval, *valstr;
	proto_item *ti;

	if (!pdulen)
	{
		proto_tree_add_text(pdutree, tvb, offset, 0, "No PDUs found");
		return;
	}

	while (pdulen > 0)
	{
		tvb_memcpy(tvb, (guint8 *)&pduhdr, offset, sizeof(e_pduhdr));
		len = (((int)pduhdr.pdu_len_h) << 8) + pduhdr.pdu_len_l;

		pdustrval = val_to_str(pduhdr.pdu_type, iapp_pdu_type_vals,
			"Unknown PDU Type");
		valstr = pduval_to_str(pduhdr.pdu_type, len, tvb, offset);
		ti = proto_tree_add_text(pdutree, tvb, offset, len + 3, "%s(%d) %s",
			pdustrval, pduhdr.pdu_type, valstr);

		if (pduhdr.pdu_type == IAPP_PDU_CAPABILITY)
			dissect_caps(ti, tvb, offset); 

		if (pduhdr.pdu_type == IAPP_PDU_AUTHINFO)
			dissect_authinfo(ti, tvb, offset + 3, len); 

		pdulen -= (len + 3);
		offset += (len + 3);
	}
}

/* code to dissect an IAPP packet */
static void
dissect_iapp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti, *pdutf;
	proto_tree *iapp_tree, *pdutree;
	e_iapphdr ih;
	int ia_version;
	int ia_type;
	gchar *codestrval;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "IAPP");
    
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	tvb_memcpy(tvb, (guint8 *)&ih, 0, sizeof(e_iapphdr));

	ia_version = (int)ih.ia_version;
        ia_type = (int)ih.ia_type;
	codestrval = val_to_str(ia_type, iapp_vals,  "Unknown Packet");
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s(%d) (version=%d)",
		             codestrval, ia_type, ia_version);
	}

	if (tree)
	{
		ti = proto_tree_add_item(tree, proto_iapp, tvb, 0, -1, FALSE);
		iapp_tree = proto_item_add_subtree(ti, ett_iapp);

                /* common header for all IAPP frames */

		proto_tree_add_uint(iapp_tree, hf_iapp_version, tvb, 0, 1,
			ih.ia_version);
		proto_tree_add_uint_format(iapp_tree, hf_iapp_type, tvb, 1, 1,
			ih.ia_type, "Type: %s(%d)", codestrval, ia_type);

		pdutf = proto_tree_add_text(iapp_tree, tvb, 2, -1,
				"Protocol data units");
		pdutree = proto_item_add_subtree(pdutf, ett_iapp_pdu);

		if (pdutree)
		{
			dissect_pdus(tvb, 2, pdutree,
				tvb_length_remaining(tvb, 2));
		}
	}
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_iapp(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_iapp_version,
			{ "Version", "iapp.version", FT_UINT8, BASE_DEC, NULL, 0x00, "", HFILL }
		},
		{ &hf_iapp_type,
			{ "type", "iapp.type", FT_UINT8, BASE_DEC, NULL, 0x00, "", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_iapp,
		&ett_iapp_pdu,
		&ett_iapp_cap,
		&ett_iapp_auth
	};

/* Register the protocol name and description */
	proto_iapp = proto_register_protocol("Inter-Access-Point Protocol",
	    "IAPP", "iapp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_iapp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_iapp(void)
{
	dissector_handle_t iapp_handle;

	iapp_handle = create_dissector_handle(dissect_iapp, proto_iapp);
	dissector_add("udp.port", UDP_PORT_IAPP, iapp_handle);
}
