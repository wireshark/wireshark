/* packet-dhcpfo.c
 * Routines for ISC DHCP Server failover protocol dissection
 * Copyright 2004, M. Ortega y Strupp <moys@loplof.de>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * This implementation is loosely based on draft-ietf-dhc-failover-07.txt.
 * As this document does not represent the actual implementation, the
 * source code of ISC DHCPD 3.0 was used too.
 *
 * See also
 *
 *	http://community.roxen.com/developers/idocs/drafts/draft-ietf-dhc-failover-10.html
 *
 * upon which the handling of the message-digest option is based.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <prefs.h>
#include "packet-arp.h"

#define TCP_PORT_DHCPFO 519

static unsigned int tcp_port_pref = TCP_PORT_DHCPFO;

static dissector_handle_t dhcpfo_handle;

/* Initialize the protocol and registered fields */
static int proto_dhcpfo = -1;
static int hf_dhcpfo_length = -1;
static int hf_dhcpfo_type = -1;
static int hf_dhcpfo_poffset = -1;
static int hf_dhcpfo_time = -1;
static int hf_dhcpfo_xid = -1;
static int hf_dhcpfo_additional_HB = -1;
static int hf_dhcpfo_payload_data = -1;
static int hf_dhcpfo_option_code = -1;
static int hf_dhcpfo_dhcp_style_option = -1;
static int hf_dhcpfo_option_length = -1;
static int hf_dhcpfo_binding_status = -1;
static int hf_dhcpfo_server_state = -1;
static int hf_dhcpfo_assigned_ip_address = -1;
static int hf_dhcpfo_sending_server_ip_address = -1;
static int hf_dhcpfo_addresses_transfered = -1;
static int hf_dhcpfo_client_identifier = -1;
static int hf_dhcpfo_client_hw_type = -1;
static int hf_dhcpfo_client_hardware_address = -1;
static int hf_dhcpfo_ftddns = -1;
static int hf_dhcpfo_reject_reason = -1;
static int hf_dhcpfo_message = -1;
static int hf_dhcpfo_mclt = -1;
static int hf_dhcpfo_vendor_class = -1;
static int hf_dhcpfo_lease_expiration_time = -1;
static int hf_dhcpfo_grace_expiration_time = -1;
static int hf_dhcpfo_potential_expiration_time = -1;
static int hf_dhcpfo_client_last_transaction_time = -1;
static int hf_dhcpfo_start_time_of_state = -1;
static int hf_dhcpfo_vendor_option = -1;
static int hf_dhcpfo_max_unacked_bndupd = -1;
static int hf_dhcpfo_protocol_version = -1;
static int hf_dhcpfo_receive_timer = -1;
static int hf_dhcpfo_message_digest = -1;
static int hf_dhcpfo_hash_bucket_assignment = -1;

/* Initialize the subtree pointers */
static gint ett_dhcpfo = -1;
static gint ett_fo_payload = -1;
static gint ett_fo_option = -1;

/* structure for payload data */
struct payloadMessage {
	struct payloadMessage *next;
	int opcode;
	int length;
	/*guint data;*/
	int actualpoffset;
};
struct payloadMessage *liste;

/* message-types of failover */
enum {
	DHCP_FO_RESERVED,
	DHCP_FO_POOLREQ,
	DHCP_FO_POOLRESP,
	DHCP_FO_BNDUPD,
	DHCP_FO_BNDACK,
	DHCP_FO_CONNECT,
	DHCP_FO_CONNECTACK,
	DHCP_FO_UPDREQ,
	DHCP_FO_UPDDONE,
	DHCP_FO_UPDREQALL,
	DHCP_FO_STATE,
	DHCP_FO_CONTACT,
	DHCP_FO_DISCONNECT
};

static const value_string failover_vals[] =
{
	{DHCP_FO_RESERVED,	"Reserved"},
	{DHCP_FO_POOLREQ,	"Pool request"},
	{DHCP_FO_POOLRESP,	"Pool response"},
	{DHCP_FO_BNDUPD,	"Binding update"},
	{DHCP_FO_BNDACK,	"Binding acknowledge"},
	{DHCP_FO_CONNECT,	"Connect"},
	{DHCP_FO_CONNECTACK,	"Connect acknowledge"},
	{DHCP_FO_UPDREQ,	"Update request all"},
	{DHCP_FO_UPDDONE,	"Update done"},
	{DHCP_FO_UPDREQALL,	"Update request"},
	{DHCP_FO_STATE,		"State"},
	{DHCP_FO_CONTACT,	"Contact"},
	{DHCP_FO_DISCONNECT,	"Disconnect"},
	{0, NULL}
};

/*options of payload-data*/
enum {
	DHCP_FO_PD_UNKNOWN_PACKET0,
        DHCP_FO_PD_BINDING_STATUS,
	DHCP_FO_PD_ASSIGNED_IP_ADDRESS,
	DHCP_FO_PD_SENDING_SERVER_IP_ADDRESS,
	DHCP_FO_PD_ADDRESSES_TRANSFERED,
	DHCP_FO_PD_CLIENT_IDENTIFIER,
	DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS,
	DHCP_FO_PD_FTDDNS,
	DHCP_FO_PD_REJECT_REASON,
	DHCP_FO_PD_MESSAGE,
	DHCP_FO_PD_MCLT,
	DHCP_FO_PD_VENDOR_CLASS,
	DHCP_FO_PD_UNKNOWN_PACKET12,
	DHCP_FO_PD_LEASE_EXPIRATION_TIME,
	DHCP_FO_PD_POTENTIAL_EXPIRATION_TIME,
	DHCP_FO_PD_GRACE_EXPIRATION_TIME,
	DHCP_FO_PD_CLIENT_LAST_TRANSACTION_TIME,
	DHCP_FO_PD_START_TIME_OF_STATE,
	DHCP_FO_PD_SERVERSTATE,
	DHCP_FO_PD_SERVERFLAG,
	DHCP_FO_PD_VENDOR_OPTION,
	DHCP_FO_PD_MAX_UNACKED_BNDUPD,
	DHCP_FO_PD_UNKNOWN_PACKET22,
	DHCP_FO_PD_RECEIVE_TIMER,
	DHCP_FO_PD_HASH_BUCKET_ASSIGNMENT,
	DHCP_FO_PD_MESSAGE_DIGEST,
	DHCP_FO_PD_PROTOCOL_VERSION,
	DHCP_FO_PD_TLS_REQUEST,
	DHCP_FO_PD_TLS_REPLY,
	DHCP_FO_PD_REQUEST_OPTION,
	DHCP_FO_PD_REPLY_OPTION
};

static const value_string option_code_vals[] =
{
	{DHCP_FO_PD_UNKNOWN_PACKET0,			"Unknown Packet"},
	{DHCP_FO_PD_BINDING_STATUS,			"binding-status"},
	{DHCP_FO_PD_ASSIGNED_IP_ADDRESS,		"assigned-IP-address"},
	{DHCP_FO_PD_SENDING_SERVER_IP_ADDRESS,		"sending-server-IP-address"},
	{DHCP_FO_PD_ADDRESSES_TRANSFERED,		"addresses-transfered"},
	{DHCP_FO_PD_CLIENT_IDENTIFIER,			"client-identifier"},
	{DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS,		"client-hardware-address"},
	{DHCP_FO_PD_FTDDNS,				"FTDDNS"},
	{DHCP_FO_PD_REJECT_REASON,			"reject-reason"},
	{DHCP_FO_PD_MESSAGE,				"message"},
	{DHCP_FO_PD_MCLT,				"MCLT"},
	{DHCP_FO_PD_VENDOR_CLASS,			"vendor-class"},
	{DHCP_FO_PD_UNKNOWN_PACKET12,			"Unknown Packet"},
	{DHCP_FO_PD_LEASE_EXPIRATION_TIME,		"lease-expiration-time"},
	{DHCP_FO_PD_POTENTIAL_EXPIRATION_TIME,		"potential-expiration-time"},
	{DHCP_FO_PD_GRACE_EXPIRATION_TIME,		"grace-expiration-time"},
	{DHCP_FO_PD_CLIENT_LAST_TRANSACTION_TIME,	"client-last-transaction-time"},
	{DHCP_FO_PD_START_TIME_OF_STATE,		"start-time-of-state"},
	{DHCP_FO_PD_SERVERSTATE,			"server-state"},
	{DHCP_FO_PD_SERVERFLAG,				"server-flag"},
	{DHCP_FO_PD_VENDOR_OPTION,			"vendor-option"},
	{DHCP_FO_PD_MAX_UNACKED_BNDUPD,			"max-unacked-BNDUPD"},
	{DHCP_FO_PD_UNKNOWN_PACKET22,			"Unknown Packet"},
	{DHCP_FO_PD_RECEIVE_TIMER,			"receive-timer"},
	{DHCP_FO_PD_HASH_BUCKET_ASSIGNMENT,		"hash-bucket-assignment"},
	{DHCP_FO_PD_MESSAGE_DIGEST,			"message-digest"},
	{DHCP_FO_PD_PROTOCOL_VERSION,			"protocol-version"},
	{DHCP_FO_PD_TLS_REQUEST,			"TLS-request"},
	{DHCP_FO_PD_TLS_REPLY,				"TLS-reply"},
	{DHCP_FO_PD_REQUEST_OPTION,			"request-option"},
	{DHCP_FO_PD_REPLY_OPTION,			"reply-option"},
	{0, NULL}

};

/* Binding-status */
enum {
        DHCP_FO_BS_UNKNOWN_PACKET,
	DHCP_FO_BS_FREE,
	DHCP_FO_BS_ACTIVE,
	DHCP_FO_BS_EXPIRED,
	DHCP_FO_BS_RELEASED,
	DHCP_FO_BS_ABANDONED,
	DHCP_FO_BS_RESET,
	DHCP_FO_BS_BACKUP
};

static const value_string binding_status_vals[] =
{
        {DHCP_FO_BS_UNKNOWN_PACKET,	"Unknown Packet"},
	{DHCP_FO_BS_FREE,		"FREE"},
	{DHCP_FO_BS_ACTIVE,		"ACTIVE"},
	{DHCP_FO_BS_EXPIRED,		"EXPIRED"},
	{DHCP_FO_BS_RELEASED,		"RELEASED"},
	{DHCP_FO_BS_ABANDONED,		"ABANDONED"},
	{DHCP_FO_BS_RESET,		"RESET"},
	{DHCP_FO_BS_BACKUP,		"BACKUP"},
	{0, NULL}

};

/* Server-status */
enum {
	DHCP_FO_SS_UNKNOWN_PACKET,
	DHCP_FO_SS_PARTNER_DOWN,
	DHCP_FO_SS_NORMAL,
	DHCP_FO_SS_COMMUNICATION_INTERRUPTED,
	DHCP_FO_SS_RESOLUTION_INTERRUPTED,
	DHCP_FO_SS_POTENTIAL_CONFLICT,
	DHCP_FO_SS_RECOVER,
	DHCP_FO_SS_RECOVER_DONE,
	DHCP_FO_SS_SHUTDOWN,
	DHCP_FO_SS_PAUSED,
	DHCP_FO_SS_STARTUP,
	DHCP_FO_SS_RECOVER_WAIT
};


static const value_string server_state_vals[] =
{
        {DHCP_FO_SS_UNKNOWN_PACKET,		"Unknown Packet"},
	{DHCP_FO_SS_PARTNER_DOWN,		"partner down"},
	{DHCP_FO_SS_NORMAL,			"normal"},
	{DHCP_FO_SS_COMMUNICATION_INTERRUPTED,	"communication interrupted"},
	{DHCP_FO_SS_RESOLUTION_INTERRUPTED,	"resolution interrupted"},
	{DHCP_FO_SS_POTENTIAL_CONFLICT,		"potential conflict"},
	{DHCP_FO_SS_RECOVER,			"recover"},
	{DHCP_FO_SS_RECOVER_DONE,		"recover done"},
	{DHCP_FO_SS_SHUTDOWN,			"shutdown"},
	{DHCP_FO_SS_PAUSED,			"paused"},
	{DHCP_FO_SS_STARTUP,			"startup"},
	{DHCP_FO_SS_RECOVER_WAIT,		"recover wait"},
	{0, NULL}
};

/* reject reasons */


enum {
	DHCP_FO_RR_0,
	DHCP_FO_RR_1,
	DHCP_FO_RR_2,
	DHCP_FO_RR_3,
	DHCP_FO_RR_4,
	DHCP_FO_RR_5,
	DHCP_FO_RR_6,
	DHCP_FO_RR_7,
	DHCP_FO_RR_8,
	DHCP_FO_RR_9,
	DHCP_FO_RR_10,
	DHCP_FO_RR_11,
	DHCP_FO_RR_12,
	DHCP_FO_RR_13,
	DHCP_FO_RR_14,
	DHCP_FO_RR_15,
	DHCP_FO_RR_16,
	DHCP_FO_RR_17,
	DHCP_FO_RR_18,
	DHCP_FO_RR_19,
	DHCP_FO_RR_254 = 254 
	
};


static const value_string reject_reason_vals[] =
{
        {DHCP_FO_RR_0,	"Reserved"},
	{DHCP_FO_RR_1,	"Illegal IP address (not part of any address pool)"},
	{DHCP_FO_RR_2,	"Fatal conflict exists: address in use by other client"},
	{DHCP_FO_RR_3,	"Missing binding information"},
	{DHCP_FO_RR_4,	"Connection rejected, time mismatch too great"},
	{DHCP_FO_RR_5,	"Connection rejected, invalid MCLT"},
	{DHCP_FO_RR_6,	"Connection rejected, unknown reason"},
	{DHCP_FO_RR_7,	"Connection rejected, duplicate connection"},
	{DHCP_FO_RR_8,	"Connection rejected, invalid failover partner"},
	{DHCP_FO_RR_9,	"TLS not supported"},
	{DHCP_FO_RR_10,	"TLS supported but not configured"},
	{DHCP_FO_RR_11,	"TLS required but not supported by partner"},
	{DHCP_FO_RR_12,	"Message digest not supported"},
	{DHCP_FO_RR_13,	"Message digest not configured"},
	{DHCP_FO_RR_14,	"Protocol version mismatch"},
	{DHCP_FO_RR_15,	"Missing binding information"},
	{DHCP_FO_RR_16,	"Outdated binding information"},
	{DHCP_FO_RR_17,	"Less critical binding information"},
	{DHCP_FO_RR_18,	"No traffic within sufficient time"},
	{DHCP_FO_RR_19,	"Hash bucket assignment conflict"},
	{DHCP_FO_RR_254, "Unknown: Error occurred but does not match any reason"}, 
	{0, NULL}
};

/* Code to actually dissect the packets */
static void
dissect_dhcpfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti, *pi, *oi, *receive_timer_item;
	proto_tree *dhcpfo_tree, *payload_tree, *option_tree;
	guint16 length, tls_request;
	guint type, serverflag;
	guint poffset;
	guint32 xid;
	gchar *typestrval, *optionstrval, *tls_request_string;
	guint32 time, lease_expiration_time, grace_expiration_time;
	guint32 potential_expiration_time, client_last_transaction_time;
	guint32 start_time_of_state;
	enum DHCPFOBoolean { false, true } additionalHB, more_payload;
	guint additionalHBlength;
	struct payloadMessage *helpliste;
	int actualoffset;
	guint8 htype, reject_reason, message_digest_type;
	const guint8 *chaddr;
	guint8 binding_status;
	gchar *binding_status_str, *reject_reason_str;
	gchar *assigned_ip_address_str, *sending_server_ip_address_str;
	guint32 addresses_transfered;
	const guint8 *client_identifier_str, *vendor_class_str;
	gchar *htype_str, *chaddr_str;
	gchar *lease_expiration_time_str;
	gchar *grace_expiration_time_str, *potential_expiration_time_str;
	gchar *client_last_transaction_time_str, *start_time_of_state_str;
	gchar *server_state_str;
	guint32 mclt;
	guint8 server_state, protocol_version;
	guint32 max_unacked_bndupd, receive_timer;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DHCPFO");
    
	length = tvb_get_ntohs(tvb, 0);
        type = tvb_get_guint8(tvb, 2);
	typestrval=  match_strval(type,failover_vals);
  	if (typestrval==NULL) {
        	typestrval="Unknown Packet";
  	}
	poffset = tvb_get_guint8(tvb, 3);
	
	if(poffset > 12)
	{
		additionalHB = true;
		additionalHBlength = poffset-12;
	}
	else
	{
		additionalHB = false;
		additionalHBlength = 0;
	}
	xid = tvb_get_ntohl(tvb, 8);

	if (check_col(pinfo->cinfo, COL_INFO)){ 
		col_add_fstr(pinfo->cinfo, 
				COL_INFO,"%s xid: %x", typestrval,xid);
	}
	
	actualoffset = poffset;
	liste = NULL;

        /* payload-data */
        if(length-poffset != 0)
        {
		more_payload = true;
                /*liste->next = NULL;*/
		liste = (struct payloadMessage*)g_malloc(sizeof(struct payloadMessage));
		helpliste = liste;
		actualoffset = poffset;

                while(more_payload == true)
                {
			
                	helpliste->opcode = tvb_get_ntohs(tvb, actualoffset);
			helpliste->length = tvb_get_ntohs(tvb, actualoffset+2);
			helpliste->next = NULL;
			helpliste->actualpoffset = actualoffset;
			actualoffset = actualoffset + helpliste->length + 4;
			if(actualoffset>=length)
			{
				more_payload = false;
			}
			else
			{
				helpliste->next = (struct payloadMessage*)g_malloc(sizeof(struct payloadMessage));
			}
			helpliste = helpliste->next;
		}
		
	}
	
	if (tree) {


		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_dhcpfo, tvb, 0, -1, FALSE);

		dhcpfo_tree = proto_item_add_subtree(ti, ett_dhcpfo);

		proto_tree_add_item(dhcpfo_tree,
		    hf_dhcpfo_length, tvb, 0, 2, FALSE);

		proto_tree_add_item(dhcpfo_tree,
		    hf_dhcpfo_type, tvb, 2, 1, FALSE);

		proto_tree_add_item(dhcpfo_tree,
		    hf_dhcpfo_poffset, tvb, 3, 1, FALSE);

		time = tvb_get_ntohl(tvb, 4);
		proto_tree_add_uint_format(dhcpfo_tree, hf_dhcpfo_time, tvb, 4, 4,time,"%s", abs_time_secs_to_str(time)); 
		

		proto_tree_add_item(dhcpfo_tree,
		    hf_dhcpfo_xid, tvb, 8, 4, FALSE);

		/* if there are any additional header bytes */
		if(additionalHB==true)
		{
			proto_tree_add_item(dhcpfo_tree,
				hf_dhcpfo_additional_HB, tvb, 12, additionalHBlength, FALSE);
		} 
		

		if(length-poffset != 0)
		{

			/* create display subtree for the protocol */
                	pi = proto_tree_add_item(dhcpfo_tree, hf_dhcpfo_payload_data, tvb, poffset, length-poffset, FALSE);
                	payload_tree = proto_item_add_subtree(pi, ett_fo_payload);

			
			
			helpliste = liste;	
			while(helpliste!=NULL)
			{
				oi = proto_tree_add_item(payload_tree, hf_dhcpfo_dhcp_style_option, tvb, helpliste->actualpoffset, helpliste->length+4, FALSE);
				option_tree = proto_item_add_subtree(oi, ett_fo_option);
				
				/*** DHCP-Style-Options ****/

				optionstrval=  match_strval(helpliste->opcode,option_code_vals);
			        if (optionstrval==NULL) {
			                optionstrval="Unknown Packet";
        			}


				proto_item_append_text(oi, ", %s (%d)", 
					optionstrval, helpliste->opcode);

				proto_tree_add_item(option_tree,
                			hf_dhcpfo_option_code, tvb, 
					helpliste->actualpoffset, 2, FALSE);
		

				proto_tree_add_item(option_tree,
					hf_dhcpfo_option_length, tvb,
					helpliste->actualpoffset+2, 2, FALSE); 

				
				/** opcode dependent format **/

				switch(helpliste->opcode){
        			
				case DHCP_FO_PD_BINDING_STATUS:

					binding_status = tvb_get_guint8(tvb,
						helpliste->actualpoffset+4);
					binding_status_str = 
						match_strval(binding_status,
							binding_status_vals);
					if(binding_status_str == NULL)
					{
						binding_status_str = "Unknown Packet";
					}
					proto_item_append_text(oi, ", %s (%d)",
							binding_status_str, 
							binding_status);

					proto_tree_add_item(option_tree,
						hf_dhcpfo_binding_status, tvb,
						helpliste->actualpoffset + 4, 1, FALSE);
					break;   

        			case DHCP_FO_PD_ASSIGNED_IP_ADDRESS:

					assigned_ip_address_str = ip_to_str(
						tvb_get_ptr(tvb,
							helpliste->actualpoffset+4,
							helpliste->length));

					proto_item_append_text(oi, ", %s ",
						assigned_ip_address_str);

					proto_tree_add_item(option_tree,
						hf_dhcpfo_assigned_ip_address, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break;

        			case DHCP_FO_PD_SENDING_SERVER_IP_ADDRESS:

					sending_server_ip_address_str = ip_to_str(tvb_get_ptr(tvb,helpliste->actualpoffset+4,helpliste->length));
					
					proto_item_append_text(oi, ", %s ",
							sending_server_ip_address_str); 
					proto_tree_add_item(option_tree,
						hf_dhcpfo_sending_server_ip_address, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break;

        			case DHCP_FO_PD_ADDRESSES_TRANSFERED:

					addresses_transfered = tvb_get_ntohl(tvb,
								helpliste->actualpoffset+4);

					proto_item_append_text(oi,", %d",addresses_transfered);	
					proto_tree_add_item(option_tree,
						hf_dhcpfo_addresses_transfered, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break; 

        			case DHCP_FO_PD_CLIENT_IDENTIFIER:

					client_identifier_str = tvb_get_ptr(tvb,
									helpliste->actualpoffset+4,
									helpliste->length);
					proto_item_append_text(oi,", \"%s\"",client_identifier_str);
					proto_tree_add_item(option_tree,
						hf_dhcpfo_client_identifier, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break;  

        			case DHCP_FO_PD_CLIENT_HARDWARE_ADDRESS:

					htype = tvb_get_guint8(tvb,helpliste->actualpoffset+4);
					chaddr = tvb_get_ptr(tvb, helpliste->actualpoffset+5, 
								helpliste->length-1);
					htype_str = arphrdtype_to_str(htype, "Unknown (0x%02x)");
					chaddr_str = arphrdaddr_to_str(tvb_get_ptr(tvb, 
							helpliste->actualpoffset+5, 6),6,htype);

					proto_item_append_text(oi, ", %s, %s",
						htype_str, chaddr_str);

                        		proto_tree_add_text(option_tree, tvb, 
						helpliste->actualpoffset+4, 1,
                                		"Hardware type: %s",
                                		htype_str);

                        		proto_tree_add_text(option_tree, tvb, 
						helpliste->actualpoffset+5, 6,
                                		"Client hardware address: %s",
                                        	chaddr_str);
					break;    

        			case DHCP_FO_PD_FTDDNS:

					proto_tree_add_item(option_tree,
                                                hf_dhcpfo_ftddns, tvb,
                                                helpliste->actualpoffset + 4,
                                                helpliste->length , FALSE);
					break;        

        			case DHCP_FO_PD_REJECT_REASON:

					reject_reason = tvb_get_guint8(tvb, 
								helpliste->actualpoffset +4);
					reject_reason_str = match_strval(reject_reason,
                                                        reject_reason_vals);
					if (reject_reason_str==NULL) {
						reject_reason_str="Unknown Packet";
					}
					 
					proto_item_append_text(oi, ", %s (%d)",
							reject_reason_str, 
							reject_reason);

					proto_tree_add_item(option_tree,
						hf_dhcpfo_reject_reason, tvb,
						helpliste->actualpoffset +4,
						helpliste->length, FALSE);
					break;            

        			case DHCP_FO_PD_MESSAGE:

					proto_tree_add_item(option_tree,
						hf_dhcpfo_message, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break;            

        			case DHCP_FO_PD_MCLT:

					mclt = tvb_get_ntohl(tvb, helpliste->actualpoffset+4);
					proto_item_append_text(oi,", %d seconds",mclt);
					proto_tree_add_item(option_tree,
						hf_dhcpfo_mclt, tvb,
						helpliste->actualpoffset +4,
						helpliste->length, FALSE);
					break;    

        			case DHCP_FO_PD_VENDOR_CLASS:

					vendor_class_str = tvb_get_ptr(tvb,
						helpliste->actualpoffset+4,helpliste->length);
					proto_item_append_text(oi,", \"%s\"",vendor_class_str);
					proto_tree_add_item(option_tree,
						hf_dhcpfo_vendor_class, tvb,
						helpliste->actualpoffset +4,
						helpliste->length, FALSE);
					break;                    

        			case DHCP_FO_PD_LEASE_EXPIRATION_TIME:

					lease_expiration_time = tvb_get_ntohl(tvb,
								helpliste->actualpoffset+4);
					lease_expiration_time_str = 
						abs_time_secs_to_str(lease_expiration_time);
	
					proto_item_append_text(oi, ", %s", 
								lease_expiration_time_str);

					proto_tree_add_uint_format(option_tree, 
						hf_dhcpfo_lease_expiration_time, tvb, 
						helpliste->actualpoffset +4, 
						helpliste->length,
						lease_expiration_time,
						"Lease expiration time: %s", 
						lease_expiration_time_str); 
					break;        

        			case DHCP_FO_PD_POTENTIAL_EXPIRATION_TIME:

					potential_expiration_time = tvb_get_ntohl(tvb,
								helpliste->actualpoffset+4);

					potential_expiration_time_str = 
						abs_time_secs_to_str(potential_expiration_time);
					
					proto_item_append_text(oi, ", %s", 
								potential_expiration_time_str);	

					proto_tree_add_uint_format(option_tree, 
						hf_dhcpfo_potential_expiration_time, tvb, 
						helpliste->actualpoffset +4, 
						helpliste->length,
						potential_expiration_time,
						"Potential expiration time: %s", 
						potential_expiration_time_str); 
					break;          

        			case DHCP_FO_PD_GRACE_EXPIRATION_TIME:

					grace_expiration_time = tvb_get_ntohl(tvb,
                                                                helpliste->actualpoffset+4);

					grace_expiration_time_str =
						abs_time_secs_to_str(grace_expiration_time);

					proto_item_append_text(oi, ", %s",
								grace_expiration_time_str);

                                        proto_tree_add_uint_format(option_tree,
                                                hf_dhcpfo_grace_expiration_time, tvb,
                                                helpliste->actualpoffset +4,
                                                helpliste->length,
                                                grace_expiration_time,
                                                "Grace expiration time: %s", 
							grace_expiration_time_str);

					break;                 

        			case DHCP_FO_PD_CLIENT_LAST_TRANSACTION_TIME:

					client_last_transaction_time = tvb_get_ntohl(tvb,
                                                                helpliste->actualpoffset+4);
					client_last_transaction_time_str =
						abs_time_secs_to_str(client_last_transaction_time);

					proto_item_append_text(oi, ", %s", 
								client_last_transaction_time_str);

                                        proto_tree_add_uint_format(option_tree,
                                                hf_dhcpfo_client_last_transaction_time, tvb,
                                                helpliste->actualpoffset +4,
                                                helpliste->length,
                                                client_last_transaction_time,
                                                "Last transaction time: %s", abs_time_secs_to_str(client_last_transaction_time));
					break;                 

        			case DHCP_FO_PD_START_TIME_OF_STATE:           
					start_time_of_state = tvb_get_ntohl(tvb,
                                                                helpliste->actualpoffset+4);
					start_time_of_state_str =
						abs_time_secs_to_str(start_time_of_state);

					proto_item_append_text(oi, ", %s",
								start_time_of_state_str);

                                        proto_tree_add_uint_format(option_tree,
                                                hf_dhcpfo_start_time_of_state, tvb,
                                                helpliste->actualpoffset +4,
                                                helpliste->length,
                                                start_time_of_state,
                                                "Start time of state: %s", abs_time_secs_to_str(start_time_of_state));
					break;  

        			case DHCP_FO_PD_SERVERSTATE:     

					server_state = tvb_get_guint8(tvb, helpliste->actualpoffset+4);

					server_state_str = match_strval(server_state,server_state_vals);
					if (server_state_str==NULL) {
						server_state_str="Unknown Packet";
					}
					proto_item_append_text(oi, ", %s (%d)", 
						server_state_str, server_state);

					proto_tree_add_item(option_tree,
						hf_dhcpfo_server_state, tvb,
						helpliste->actualpoffset + 4, 1, FALSE);
					break;

        			case DHCP_FO_PD_SERVERFLAG:

					serverflag = tvb_get_guint8(tvb,
							helpliste->actualpoffset+4);

					if(serverflag == 1)
					{
						proto_item_append_text(oi, ", STARTUP (1)");
						proto_tree_add_text(option_tree,tvb,
                                                        helpliste->actualpoffset +4,
                                                        helpliste->length,
                                                        "Serverflag: STARTUP");

					}
					else if(serverflag == 0)
					{
						proto_item_append_text(oi, ", NONE (%d)",
								serverflag);
						proto_tree_add_text(option_tree,tvb,
                                                        helpliste->actualpoffset +4,
                                                        helpliste->length,
                                                        "Serverflag: NONE");
					}
					else
					{
						proto_item_append_text(oi, 
							"UNKNOWN FLAGS (%d)", serverflag);

						proto_tree_add_text(option_tree,tvb,
                                                        helpliste->actualpoffset +4,
                                                        helpliste->length,
                                                        "Serverflag: UNKNOWN FLAGS");
					}
					break;                

        			case DHCP_FO_PD_VENDOR_OPTION:

					proto_tree_add_item(option_tree,
						hf_dhcpfo_vendor_option, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 

					break;         

        			case DHCP_FO_PD_MAX_UNACKED_BNDUPD:

					max_unacked_bndupd = 
						tvb_get_ntohl(tvb,helpliste->actualpoffset+4);
					proto_item_append_text(oi,", %d", max_unacked_bndupd);

					proto_tree_add_item(option_tree,
						hf_dhcpfo_max_unacked_bndupd, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break;               

        			case DHCP_FO_PD_RECEIVE_TIMER:

					receive_timer = 
						tvb_get_ntohl(tvb,helpliste->actualpoffset+4);
					proto_item_append_text(oi,", %d seconds", receive_timer);

					receive_timer_item = proto_tree_add_item(option_tree,
						hf_dhcpfo_receive_timer, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					proto_item_append_text(receive_timer_item, " seconds");
					break;             

        			case DHCP_FO_PD_HASH_BUCKET_ASSIGNMENT:

					proto_tree_add_item(option_tree,
						hf_dhcpfo_hash_bucket_assignment, tvb,
						helpliste->actualpoffset +4,
						helpliste->length, FALSE);
					break;               

        			case DHCP_FO_PD_MESSAGE_DIGEST:

					message_digest_type = tvb_get_guint8(tvb,helpliste->actualpoffset+4);
					if(message_digest_type == 1)
					{
						proto_item_append_text(oi, ", HMAC-MD5");
						proto_tree_add_text(option_tree, tvb, helpliste->actualpoffset+4, 1, "Message digest type: HMAC-MD5");
					}
					else
					{
						proto_item_append_text(oi, ", type not allowed");
						proto_tree_add_text(option_tree, tvb, helpliste->actualpoffset+4, 1, "Message digest type: not allowed");
					}

					proto_tree_add_item(option_tree,
						hf_dhcpfo_message_digest, tvb,
						helpliste->actualpoffset+5,
						helpliste->length-1,FALSE);
					break;             

        			case DHCP_FO_PD_PROTOCOL_VERSION:

					protocol_version = 
						tvb_get_guint8(tvb, helpliste->actualpoffset+4);

					proto_item_append_text(oi, ", version: %d", 
									protocol_version);
					proto_tree_add_item(option_tree,
						hf_dhcpfo_protocol_version, tvb,
						helpliste->actualpoffset + 4, 
						helpliste->length , FALSE); 
					break;            

        			case DHCP_FO_PD_TLS_REQUEST:

					tls_request = tvb_get_ntohs(tvb,helpliste->actualpoffset+4);
					if(tls_request == 0)
					{
						tls_request_string = "No TLS operation";
					}
					else if(tls_request == 1)
					{
						tls_request_string = "TLS operation desired but not required";
					}
					else if(tls_request == 2)
					{
						tls_request_string = "TLS operation is required";
					}
					else
					{
						tls_request_string = "Unknown value";
					}
					proto_item_append_text(oi, ", %s", tls_request_string);

					proto_tree_add_text(option_tree, tvb,
						helpliste->actualpoffset+4,
						helpliste->length,
						"TLS request: %s", tls_request_string);
					break;                   

        			case DHCP_FO_PD_TLS_REPLY:
					break;               
				case DHCP_FO_PD_REQUEST_OPTION:
					break;
        			case DHCP_FO_PD_REPLY_OPTION:
					break;
				default:
					break;
				}

				helpliste=helpliste->next;
			}

		}


	}
	g_free(liste);

}

void
proto_reg_handoff_dhcpfo(void)
{
	static gboolean initialized = FALSE;
	static unsigned int port = 0;

	if (initialized) {
		dissector_delete("tcp.port", port, dhcpfo_handle);
	} else {
		initialized = TRUE;
	}
	port = tcp_port_pref;
	dissector_add("tcp.port", tcp_port_pref, dhcpfo_handle);
}

/* Register the protocol with Ethereal */
void
proto_register_dhcpfo(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_dhcpfo_length,
			{ "Message length",           "dhcpfo.length",
			FT_UINT16, BASE_DEC, NULL, 0,          
			"", HFILL }
		},
		{ &hf_dhcpfo_type,
			{ "Message Type",           "dhcpfo.type",
			FT_UINT8, BASE_DEC, VALS(failover_vals), 0,          
			"", HFILL }
		},

		{ &hf_dhcpfo_poffset,
			{ "Payload Offset",           "dhcpfo.poffset",
			FT_UINT8, BASE_DEC, NULL, 0,          
			"", HFILL }
		},

		{ &hf_dhcpfo_time,
			{ "Time",           "dhcpfo.time",
			FT_UINT32, BASE_DEC, NULL, 0,          
			"", HFILL }
		},

		{ &hf_dhcpfo_xid,
			{ "Xid",           "dhcpfo.xid",
			FT_UINT32, BASE_HEX, NULL, 0,          
			"", HFILL }
		},

		{ &hf_dhcpfo_additional_HB,
			{"Additional Header Bytes",	"dhcpfo.additionalheaderbytes",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"", HFILL }
		},

		{ &hf_dhcpfo_payload_data,
			{"Payload Data",	"dhcpfo.payloaddata",
			FT_NONE, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		{ &hf_dhcpfo_dhcp_style_option,
			{"DHCP Style Option",	"dhcpfo.dhcpstyleoption",
			FT_NONE, BASE_NONE, NULL, 0,
			"", HFILL }
		},
		
		{ &hf_dhcpfo_option_code,
			{"Option Code",		"dhcpfo.optioncode",
			FT_UINT16, BASE_DEC, VALS(option_code_vals), 0,
                        "", HFILL }
                },

		{&hf_dhcpfo_option_length,
			{"Length",		"dhcpfo.optionlength",
			FT_UINT16, BASE_DEC, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_binding_status,
			{"Type", "dhcpfo.bindingstatus",
			FT_UINT32, BASE_DEC, VALS(binding_status_vals), 0,
			"", HFILL }
		},

		
		{&hf_dhcpfo_server_state,
			{"server status", "dhcpfo.serverstatus",
			FT_UINT8, BASE_DEC, VALS(server_state_vals), 0,
			"", HFILL }
		},


		{&hf_dhcpfo_assigned_ip_address,
			{"assigned ip address", "dhcpfo.assignedipaddress",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }
		},

		{&hf_dhcpfo_sending_server_ip_address,
			{"sending server ip-address", "dhcpfo.sendingserveripaddress",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"", HFILL }
		},


		{&hf_dhcpfo_addresses_transfered,
			{"addresses transfered", "dhcpfo.addressestransfered",
			FT_UINT8, BASE_DEC, NULL, 0,
			"", HFILL }
		},


		{&hf_dhcpfo_client_identifier,
			{"Client Identifier", "dhcpfo.clientidentifier",
			FT_STRING, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_client_hw_type,
			{"Client Hardware Type", "dhcpfo.clienthardwaretype",
			FT_UINT8, BASE_HEX, NULL, 0x0,
        		"", HFILL }},

		{&hf_dhcpfo_client_hardware_address,
			{"Client Hardware Address", "dhcpfo.clienthardwareaddress",
			FT_BYTES, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_ftddns,
			{"FTDDNS", "dhcpfo.ftddns",
			FT_STRING, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_reject_reason,
			{"Reject reason", "dhcpfo.rejectreason",
			FT_UINT8, BASE_DEC, VALS(reject_reason_vals), 0,
			"", HFILL }
		},

		{&hf_dhcpfo_message,
			{"Message", "dhcpfo.message",
			FT_STRING, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		
		{&hf_dhcpfo_mclt,
			{"MCLT", "dhcpfo.mclt",
			FT_UINT32, BASE_DEC, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_vendor_class,
			{"Vendor class", "dhcpfo.vendorclass",
			FT_STRING, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_lease_expiration_time,
			{"Lease expiration time", "dhcpfo.leaseexpirationtime",
			FT_UINT32, BASE_DEC, NULL, 0,	
			"", HFILL }
		},

		{&hf_dhcpfo_grace_expiration_time,
			{"Grace expiration time", "dhcpfo.graceexpirationtime",
			FT_UINT32, BASE_DEC, NULL, 0,	
			"", HFILL }
		},

		{&hf_dhcpfo_potential_expiration_time,
			{"Potential expiration time", "dhcpfo.potentialexpirationtime",
			FT_UINT32, BASE_DEC, NULL, 0,	
			"", HFILL }
		},

		{&hf_dhcpfo_client_last_transaction_time,
			{"Client last transaction time", "dhcpfo.clientlasttransactiontime",
			FT_UINT32, BASE_DEC, NULL, 0,	
			"", HFILL }
		},
	
		{&hf_dhcpfo_start_time_of_state,
			{"Start time of state", "dhcpfo.starttimeofstate",
			FT_UINT32, BASE_DEC, NULL, 0,	
			"", HFILL }
		},

		{&hf_dhcpfo_vendor_option,
			{"Vendor option", "dhcpfo.vendoroption",
			FT_NONE, BASE_NONE, NULL, 0x0,	
			"", HFILL }
		},

		{&hf_dhcpfo_max_unacked_bndupd,
			{"Max unacked BNDUPD", "dhcpfo.maxunackedbndupd",
			FT_UINT8, BASE_DEC, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_protocol_version,
			{"Protocol version", "dhcpfo.protocolversion",
			FT_UINT8, BASE_DEC, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_receive_timer,
			{"Receive timer", "dhcpfo.receivetimer",
			FT_UINT8, BASE_DEC, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_message_digest,
			{"Message digest", "dhcpfo.messagedigest",
			FT_STRING, BASE_NONE, NULL, 0,
			"", HFILL }
		},

		{&hf_dhcpfo_hash_bucket_assignment,
			{"Hash bucket assignment", "dhcpfo.hashbucketassignment",
			FT_BYTES, BASE_HEX, NULL, 0,
			"", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_dhcpfo,
		&ett_fo_payload,
		&ett_fo_option,
	};

	module_t *dhcpfo_module;

/* Register the protocol name and description */
	proto_dhcpfo = proto_register_protocol("DHCP Failover", "DHCPFO",
	    "dhcpfo");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_dhcpfo, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	dhcpfo_handle = create_dissector_handle(dissect_dhcpfo, proto_dhcpfo);

	dhcpfo_module = prefs_register_protocol(proto_dhcpfo, proto_reg_handoff_dhcpfo);
	prefs_register_uint_preference(dhcpfo_module, "tcp_port",
		"DHCP failover TCP Port", "Set the port for DHCP failover communications",
		10, &tcp_port_pref);
}
