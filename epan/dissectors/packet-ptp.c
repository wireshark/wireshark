/* packet-ptp.c
 * Routines for PTP (Precision Time Protocol) dissection
 * Copyright 2004, Auges Tchouante <tchouante2001@yahoo.fr>
 * Copyright 2004, Dominic Béchaz <bdo@zhwin.ch> , ZHW/InES
 * Copyright 2004, Markus Seehofer <mseehofe@nt.hirschmann.de>
 *
 * Revisions:
 * - Markus Seehofer 09.08.2005 <mseehofe@nt.hirschmann.de>
 *   - Included the "startingBoundaryHops" field in
 *     ptp_management messages.
 * -
 * 
 * $Id$
 *
 * A plugin for:
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>


/**********************************************************/
/* Port definition's for PTP							  */
/**********************************************************/
#define EVENT_PORT_PTP      319
#define GENERAL_PORT_PTP    320

/*END Port definition's for PTP*/

/**********************************************************/
/* Offsets of fields within a PTP packet.				  */
/**********************************************************/

/*Common offsets for all Messages (Synch, Delay_Req, Follow_Up, Delay_Resp ....)*/
#define	PTP_VERSIONPTP_OFFSET			0
#define	PTP_VERSIONNETWORK_OFFSET		2
#define	PTP_SUBDOMAIN_OFFSET			4
#define	PTP_MESSAGETYPE_OFFSET			20
#define	PTP_SOURCECOMMUNICATIONTECHNOLOGY_OFFSET	21
#define	PTP_SOURCEUUID_OFFSET			22
#define	PTP_SOURCEPORTID_OFFSET			28
#define	PTP_SEQUENCEID_OFFSET			30
#define	PTP_CONTROL_OFFSET				32
#define	PTP_FLAGS_OFFSET				34
#define	PTP_FLAGS_LI61_OFFSET			34
#define	PTP_FLAGS_LI59_OFFSET			34
#define	PTP_FLAGS_BOUNDARY_CLOCK_OFFSET	34
#define	PTP_FLAGS_ASSIST_OFFSET			34
#define	PTP_FLAGS_EXT_SYNC_OFFSET		34
#define	PTP_FLAGS_PARENT_STATS_OFFSET	34
#define	PTP_FLAGS_SYNC_BURST_OFFSET		34

/*Offsets for PTP_Sync and Delay_Req (=SDR) messages*/
#define PTP_SDR_ORIGINTIMESTAMP_OFFSET						40
#define	PTP_SDR_ORIGINTIMESTAMP_SECONDS_OFFSET				40
#define	PTP_SDR_ORIGINTIMESTAMP_NANOSECONDS_OFFSET			44
#define	PTP_SDR_EPOCHNUMBER_OFFSET							48
#define	PTP_SDR_CURRENTUTCOFFSET_OFFSET						50
#define	PTP_SDR_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET	53
#define	PTP_SDR_GRANDMASTERCLOCKUUID_OFFSET					54
#define	PTP_SDR_GRANDMASTERPORTID_OFFSET					60
#define	PTP_SDR_GRANDMASTERSEQUENCEID_OFFSET				62
#define	PTP_SDR_GRANDMASTERCLOCKSTRATUM_OFFSET				67
#define	PTP_SDR_GRANDMASTERCLOCKIDENTIFIER_OFFSET			68
#define	PTP_SDR_GRANDMASTERCLOCKVARIANCE_OFFSET				74
#define	PTP_SDR_GRANDMASTERPREFERRED_OFFSET					77
#define	PTP_SDR_GRANDMASTERISBOUNDARYCLOCK_OFFSET			79
#define	PTP_SDR_SYNCINTERVAL_OFFSET							83
#define	PTP_SDR_LOCALCLOCKVARIANCE_OFFSET					86
#define	PTP_SDR_LOCALSTEPSREMOVED_OFFSET					90
#define	PTP_SDR_LOCALCLOCKSTRATUM_OFFSET					95
#define	PTP_SDR_LOCALCLOCKIDENTIFIER_OFFSET					96
#define	PTP_SDR_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET		101
#define	PTP_SDR_PARENTUUID_OFFSET							102
#define	PTP_SDR_PARENTPORTFIELD_OFFSET						110
#define	PTP_SDR_ESTIMATEDMASTERVARIANCE_OFFSET				114
#define	PTP_SDR_ESTIMATEDMASTERDRIFT_OFFSET					116
#define	PTP_SDR_UTCREASONABLE_OFFSET						123

/*Offsets for Follow_Up (=FU) messages*/
#define	PTP_FU_ASSOCIATEDSEQUENCEID_OFFSET					42
#define	PTP_FU_PRECISEORIGINTIMESTAMP_OFFSET				44
#define	PTP_FU_PRECISEORIGINTIMESTAMP_SECONDS_OFFSET		44
#define	PTP_FU_PRECISEORIGINTIMESTAMP_NANOSECONDS_OFFSET	48

/*Offsets for Delay_Resp (=DR) messages*/
#define	PTP_DR_DELAYRECEIPTTIMESTAMP_OFFSET					40
#define	PTP_DR_DELAYRECEIPTTIMESTAMP_SECONDS_OFFSET			40
#define	PTP_DR_DELAYRECEIPTTIMESTAMP_NANOSECONDS_OFFSET		44
#define	PTP_DR_REQUESTINGSOURCECOMMUNICATIONTECHNOLOGY_OFFSET	49
#define	PTP_DR_REQUESTINGSOURCEUUID_OFFSET					50
#define	PTP_DR_REQUESTINGSOURCEPORTID_OFFSET				56
#define	PTP_DR_REQUESTINGSOURCESEQUENCEID_OFFSET			58

/*Offsets for Management (=MM) messages*/
#define	PTP_MM_TARGETCOMMUNICATIONTECHNOLOGY_OFFSET			41
#define	PTP_MM_TARGETUUID_OFFSET							42
#define	PTP_MM_TARGETPORTID_OFFSET							48
#define	PTP_MM_STARTINGBOUNDARYHOPS_OFFSET					50
#define	PTP_MM_BOUNDARYHOPS_OFFSET							52
#define	PTP_MM_MANAGEMENTMESSAGEKEY_OFFSET					55
#define	PTP_MM_PARAMETERLENGTH_OFFSET						58
	/*PARAMETERLENGTH > 0*/
#define	PTP_MM_MESSAGEPARAMETERS_OFFSET						60
	/*PTP_MM_CLOCK_IDENTITY (PARAMETERLENGTH = 64)*/
#define	PTP_MM_CLOCK_IDENTITY_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET	63
#define	PTP_MM_CLOCK_IDENTITY_CLOCKUUIDFIELD_OFFSET					64
#define	PTP_MM_CLOCK_IDENTITY_CLOCKPORTFIELD_OFFSET					74
#define	PTP_MM_CLOCK_IDENTITY_MANUFACTURERIDENTITY_OFFSET			76

	/*PTP_MM_INITIALIZE_CLOCK (PARAMETERLENGTH = 4)*/
#define	PTP_MM_INITIALIZE_CLOCK_INITIALISATIONKEY_OFFSET			62

	/*PTP_MM_SET_SUBDOMAIN (PARAMETERLENGTH = 16)*/
#define	PTP_MM_SET_SUBDOMAIN_SUBDOMAINNAME_OFFSET					60

	/*PTP_MM_DEFAULT_DATA_SET (PARAMETERLENGTH = 76)*/
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET	63
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKUUIDFIELD_OFFSET				64
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKPORTFIELD_OFFSET				74
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET					79
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET				80
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET				86
#define	PTP_MM_DEFAULT_DATA_SET_CLOCKFOLLOWUPCAPABLE_OFFSET			89
#define	PTP_MM_DEFAULT_DATA_SET_PREFERRED_OFFSET					95
#define	PTP_MM_DEFAULT_DATA_SET_INITIALIZABLE_OFFSET				99
#define	PTP_MM_DEFAULT_DATA_SET_EXTERNALTIMING_OFFSET				103
#define	PTP_MM_DEFAULT_DATA_SET_ISBOUNDARYCLOCK_OFFSET				107
#define	PTP_MM_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET					111
#define	PTP_MM_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET				112
#define	PTP_MM_DEFAULT_DATA_SET_NUMBERPORTS_OFFSET					130
#define	PTP_MM_DEFAULT_DATA_SET_NUMBERFOREIGNRECORDS_OFFSET			134

	/*PTP_MM_UPDATE_DEFAULT_DATA_SET (PARAMETERLENGTH = 36)*/
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET			63
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET		64
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET			70
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET_PREFERRED_OFFSET				75
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET			79
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET			80

	/*PTP_MM_CURRENT_DATA_SET (PARAMETERLENGTH = 20)*/
#define	PTP_MM_CURRENT_DATA_SET_STEPSREMOVED_OFFSET					62
#define	PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTER_OFFSET				64
#define	PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERSECONDS_OFFSET		64
#define	PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERNANOSECONDS_OFFSET	68
#define	PTP_MM_CURRENT_DATA_SET_ONEWAYDELAY_OFFSET					72
#define	PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYSECONDS_OFFSET			72
#define	PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYNANOSECONDS_OFFSET		76

	/*PTP_MM_PARENT_DATA_SET (PARAMETERLENGTH = 90)*/
#define	PTP_MM_PARENT_DATA_SET_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET	63
#define	PTP_MM_PARENT_DATA_SET_PARENTUUID_OFFSET					64
#define	PTP_MM_PARENT_DATA_SET_PARENTPORTID_OFFSET					74
#define	PTP_MM_PARENT_DATA_SET_PARENTLASTSYNCSEQUENCENUMBER_OFFSET	78
#define	PTP_MM_PARENT_DATA_SET_PARENTFOLLOWUPCAPABLE_OFFSET			83
#define	PTP_MM_PARENT_DATA_SET_PARENTEXTERNALTIMING_OFFSET			87
#define	PTP_MM_PARENT_DATA_SET_PARENTVARIANCE_OFFSET				90
#define	PTP_MM_PARENT_DATA_SET_PARENTSTATS_OFFSET					95
#define	PTP_MM_PARENT_DATA_SET_OBSERVEDVARIANCE_OFFSET				98
#define	PTP_MM_PARENT_DATA_SET_OBSERVEDDRIFT_OFFSET					100
#define	PTP_MM_PARENT_DATA_SET_UTCREASONABLE_OFFSET					107
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET	111
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERUUIDFIELD_OFFSET			112
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERPORTIDFIELD_OFFSET		122
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERSTRATUM_OFFSET			127
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERIDENTIFIER_OFFSET			128
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERVARIANCE_OFFSET			134
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERPREFERRED_OFFSET			139
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERISBOUNDARYCLOCK_OFFSET	143
#define	PTP_MM_PARENT_DATA_SET_GRANDMASTERSEQUENCENUMBER_OFFSET		146

	/*PTP_MM_PORT_DATA_SET (PARAMETERLENGTH = 52)*/
#define	PTP_MM_PORT_DATA_SET_RETURNEDPORTNUMBER_OFFSET				62
#define	PTP_MM_PORT_DATA_SET_PORTSTATE_OFFSET						67
#define	PTP_MM_PORT_DATA_SET_LASTSYNCEVENTSEQUENCENUMBER_OFFSET		70
#define	PTP_MM_PORT_DATA_SET_LASTGENERALEVENTSEQUENCENUMBER_OFFSET	74
#define	PTP_MM_PORT_DATA_SET_PORTCOMMUNICATIONTECHNOLOGY_OFFSET		79
#define	PTP_MM_PORT_DATA_SET_PORTUUIDFIELD_OFFSET					80
#define	PTP_MM_PORT_DATA_SET_PORTIDFIELD_OFFSET						90
#define	PTP_MM_PORT_DATA_SET_BURSTENABLED_OFFSET					95
#define	PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESSOCTETS_OFFSET			97
#define	PTP_MM_PORT_DATA_SET_EVENTPORTADDRESSOCTETS_OFFSET			98
#define	PTP_MM_PORT_DATA_SET_GENERALPORTADDRESSOCTETS_OFFSET		99
#define	PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESS_OFFSET				100
#define	PTP_MM_PORT_DATA_SET_EVENTPORTADDRESS_OFFSET				106
#define	PTP_MM_PORT_DATA_SET_GENERALPORTADDRESS_OFFSET				110

	/*PTP_MM_GLOBAL_TIME_DATA_SET (PARAMETERLENGTH = 24)*/
#define	PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIME_OFFSET				60
#define	PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMESECONDS_OFFSET			60
#define	PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMENANOSECONDS_OFFSET		64
#define	PTP_MM_GLOBAL_TIME_DATA_SET_CURRENTUTCOFFSET_OFFSET			70
#define	PTP_MM_GLOBAL_TIME_DATA_SET_LEAP59_OFFSET					75
#define	PTP_MM_GLOBAL_TIME_DATA_SET_LEAP61_OFFSET					79
#define	PTP_MM_GLOBAL_TIME_DATA_SET_EPOCHNUMBER_OFFSET				82

	/*PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES (PARAMETERLENGTH = 16)*/
#define	PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_CURRENTUTCOFFSET_OFFSET	62
#define	PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP59_OFFSET			67
#define	PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP61_OFFSET			71
#define	PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_EPOCHNUMBER_OFFSET		74

	/*PTP_MM_GET_FOREIGN_DATA_SET (PARAMETERLENGTH = 4)*/
#define	PTP_MM_GET_FOREIGN_DATA_SET_RECORDKEY_OFFSET				62

	/*PTP_MM_FOREIGN_DATA_SET (PARAMETERLENGTH = 28)*/
#define	PTP_MM_FOREIGN_DATA_SET_RETURNEDPORTNUMBER_OFFSET			62
#define	PTP_MM_FOREIGN_DATA_SET_RETURNEDRECORDNUMBER_OFFSET			66
#define	PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERCOMMUNICATIONTECHNOLOGY_OFFSET	71
#define	PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERUUIDFIELD_OFFSET		72
#define	PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERPORTIDFIELD_OFFSET		82
#define	PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERSYNCS_OFFSET			86

	/*PTP_MM_SET_SYNC_INTERVAL (PARAMETERLENGTH = 4)*/
#define	PTP_MM_SET_SYNC_INTERVAL_SYNCINTERVAL_OFFSET				62

	/*PTP_MM_SET_TIME (PARAMETERLENGTH = 8)*/
#define	PTP_MM_SET_TIME_LOCALTIME_OFFSET							60
#define	PTP_MM_SET_TIME_LOCALTIMESECONDS_OFFSET						60
#define	PTP_MM_SET_TIME_LOCALTIMENANOSECONDS_OFFSET					64

/*END Offsets of fields within a PTP packet.*/

/**********************************************************/
/* flag-field-mask-definitions 		 					  */
/**********************************************************/
#define	PTP_FLAGS_LI61_BITMASK				0x01
#define	PTP_FLAGS_LI59_BITMASK				0x02
#define	PTP_FLAGS_BOUNDARY_CLOCK_BITMASK	0x04
#define	PTP_FLAGS_ASSIST_BITMASK			0x08
#define	PTP_FLAGS_EXT_SYNC_BITMASK			0x10
#define	PTP_FLAGS_PARENT_STATS_BITMASK		0x20
#define	PTP_FLAGS_SYNC_BURST_BITMASK		0x40

/*END flag-field-mask-definitions*/

/**********************************************************/
/* managementMessage definitions 						  */
/**********************************************************/
#define	PTP_MM_NULL							0
#define	PTP_MM_OBTAIN_IDENTITY				1
#define	PTP_MM_CLOCK_IDENTITY				2
#define	PTP_MM_INITIALIZE_CLOCK				3
#define	PTP_MM_SET_SUBDOMAIN				4
#define	PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER	5
#define	PTP_MM_SET_DESIGNATED_PREFERRED_MASTER		6
#define	PTP_MM_GET_DEFAULT_DATA_SET			7
#define	PTP_MM_DEFAULT_DATA_SET				8
#define	PTP_MM_UPDATE_DEFAULT_DATA_SET		9
#define	PTP_MM_GET_CURRENT_DATA_SET 		10
#define	PTP_MM_CURRENT_DATA_SET 			11
#define	PTP_MM_GET_PARENT_DATA_SET 			12
#define	PTP_MM_PARENT_DATA_SET 				13
#define	PTP_MM_GET_PORT_DATA_SET 			14
#define	PTP_MM_PORT_DATA_SET 				15
#define	PTP_MM_GET_GLOBAL_TIME_DATA_SET		16
#define	PTP_MM_GLOBAL_TIME_DATA_SET			17
#define	PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES	18
#define	PTP_MM_GOTO_FAULTY_STATE 			19
#define	PTP_MM_GET_FOREIGN_DATA_SET 		20
#define	PTP_MM_FOREIGN_DATA_SET				21
#define	PTP_MM_SET_SYNC_INTERVAL			22
#define	PTP_MM_DISABLE_PORT					23
#define	PTP_MM_ENABLE_PORT					24
#define	PTP_MM_DISABLE_BURST				25
#define	PTP_MM_ENABLE_BURST					26
#define	PTP_MM_SET_TIME 					27

static const value_string ptp_managementMessageKey_vals[] = {
  {PTP_MM_NULL,  "PTP_MM_NULL"},
  {PTP_MM_OBTAIN_IDENTITY,  "PTP_MM_OBTAIN_IDENTITY"},
  {PTP_MM_CLOCK_IDENTITY,  "PTP_MM_CLOCK_IDENTITY"},
  {PTP_MM_INITIALIZE_CLOCK,  "PTP_MM_INITIALIZE_CLOCK"},
  {PTP_MM_SET_SUBDOMAIN,  "PTP_MM_SET_SUBDOMAIN"},
  {PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER,  "PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER"},
  {PTP_MM_SET_DESIGNATED_PREFERRED_MASTER,  "PTP_MM_SET_DESIGNATED_PREFERRED_MASTER"},
  {PTP_MM_GET_DEFAULT_DATA_SET,  "PTP_MM_GET_DEFAULT_DATA_SET"},
  {PTP_MM_DEFAULT_DATA_SET,  "PTP_MM_DEFAULT_DATA_SET"},
  {PTP_MM_UPDATE_DEFAULT_DATA_SET,  "PTP_MM_UPDATE_DEFAULT_DATA_SET"},
  {PTP_MM_GET_CURRENT_DATA_SET,  "PTP_MM_GET_CURRENT_DATA_SET"},
  {PTP_MM_CURRENT_DATA_SET,  "PTP_MM_CURRENT_DATA_SET"},
  {PTP_MM_GET_PARENT_DATA_SET,  "PTP_MM_GET_PARENT_DATA_SET"},
  {PTP_MM_PARENT_DATA_SET,  "PTP_MM_PARENT_DATA_SET"},
  {PTP_MM_GET_PORT_DATA_SET,  "PTP_MM_GET_PORT_DATA_SET"},
  {PTP_MM_PORT_DATA_SET,  "PTP_MM_PORT_DATA_SET"},
  {PTP_MM_GET_GLOBAL_TIME_DATA_SET,  "PTP_MM_GET_GLOBAL_TIME_DATA_SET"},
  {PTP_MM_GLOBAL_TIME_DATA_SET,  "PTP_MM_GLOBAL_TIME_DATA_SET"},
  {PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES,  "PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES"},
  {PTP_MM_GOTO_FAULTY_STATE,  "PTP_MM_GOTO_FAULTY_STATE"},
  {PTP_MM_GET_FOREIGN_DATA_SET,  "PTP_MM_GET_FOREIGN_DATA_SET"},
  {PTP_MM_FOREIGN_DATA_SET,  "PTP_MM_FOREIGN_DATA_SET"},
  {PTP_MM_SET_SYNC_INTERVAL,  "PTP_MM_SET_SYNC_INTERVAL"},
  {PTP_MM_DISABLE_PORT,  "PTP_MM_DISABLE_PORT"},
  {PTP_MM_ENABLE_PORT,  "PTP_MM_ENABLE_PORT"},
  {PTP_MM_DISABLE_BURST,  "PTP_MM_DISABLE_BURST"},
  {PTP_MM_ENABLE_BURST,  "PTP_MM_ENABLE_BURST"},
  {PTP_MM_SET_TIME,  "PTP_MM_SET_TIME"},
  {0,              NULL          } };
	/*same again but better readable text for info column*/
  static const value_string ptp_managementMessageKey_infocolumn_vals[] = {
  {PTP_MM_NULL,  "Null"},
  {PTP_MM_OBTAIN_IDENTITY,  "Obtain Identity"},
  {PTP_MM_CLOCK_IDENTITY,  "Clock Identity"},
  {PTP_MM_INITIALIZE_CLOCK,  "Initialize Clock"},
  {PTP_MM_SET_SUBDOMAIN,  "Set Subdomain"},
  {PTP_MM_CLEAR_DESIGNATED_PREFERRED_MASTER,  "Clear Designated Preferred Master"},
  {PTP_MM_SET_DESIGNATED_PREFERRED_MASTER,  "Set Designated Preferred Master"},
  {PTP_MM_GET_DEFAULT_DATA_SET,  "Get Default Data Set"},
  {PTP_MM_DEFAULT_DATA_SET,  "Default Data Set"},
  {PTP_MM_UPDATE_DEFAULT_DATA_SET,  "Update Default Data Set"},
  {PTP_MM_GET_CURRENT_DATA_SET,  "Get Current Data Set"},
  {PTP_MM_CURRENT_DATA_SET,  "Current Data Set"},
  {PTP_MM_GET_PARENT_DATA_SET,  "Get Parent Data Set"},
  {PTP_MM_PARENT_DATA_SET,  "Parent Data Set"},
  {PTP_MM_GET_PORT_DATA_SET,  "Get Port Data Set"},
  {PTP_MM_PORT_DATA_SET,  "Port Data Set"},
  {PTP_MM_GET_GLOBAL_TIME_DATA_SET,  "Get Global Time Data Set"},
  {PTP_MM_GLOBAL_TIME_DATA_SET,  "Global Time Data Set"},
  {PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES,  "Update Global Time Properties"},
  {PTP_MM_GOTO_FAULTY_STATE,  "Goto Faulty State"},
  {PTP_MM_GET_FOREIGN_DATA_SET,  "Get Foreign Data Set"},
  {PTP_MM_FOREIGN_DATA_SET,  "Foreign Data Set"},
  {PTP_MM_SET_SYNC_INTERVAL,  "Set Sync Interval"},
  {PTP_MM_DISABLE_PORT,  "Disable Port"},
  {PTP_MM_ENABLE_PORT,  "Enable Port"},
  {PTP_MM_DISABLE_BURST,  "Disable Burst"},
  {PTP_MM_ENABLE_BURST,  "Enable Burst"},
  {PTP_MM_SET_TIME,  "Set Time"},
  {0,              NULL          } };

/*END managementMessage definitions*/

/**********************************************************/
/* CommunicationId definitions 							  */
/**********************************************************/
#define	PTP_CLOSED				0
#define	PTP_ETHER				1
#define	PTP_FFBUS				4
#define	PTP_PROFIBUS			5
#define	PTP_LON					6
#define	PTP_DNET				7
#define	PTP_SDS					8
#define	PTP_CONTROLNET			9
#define	PTP_CANOPEN				10
#define	PTP_IEEE1394			243
#define PTP_IEEE802_11A			244
#define	PTP_IEEE_WIRELESS		245
#define	PTP_INFINIBAND			246
#define	PTP_BLUETOOTH			247
#define	PTP_IEEE802_15_1		248
#define	PTP_IEEE1451_3			249
#define	PTP_IEEE1451_5			250
#define	PTP_USB					251
#define	PTP_ISA					252
#define	PTP_PCI					253
#define	PTP_VXI					254
#define	PTP_DEFAULT				255

static const value_string ptp_communicationid_vals[] = {
  {PTP_CLOSED,  "Closed system outside the scope of this standard."},
  {PTP_ETHER,  "IEEE 802.3 (Ethernet)"},
  {PTP_FFBUS,  "FoundationFieldbus"},
  {PTP_PROFIBUS,  "PROFIBUS"},
  {PTP_LON,  "LonTalk"},
  {PTP_DNET,  "DeviceNet"},
  {PTP_SDS,  "SmartDistributedSystem"},
  {PTP_CONTROLNET,  "ControlNet"},
  {PTP_CANOPEN,  "CANopen"},
  {PTP_IEEE1394,  "IEEE 1394"},
  {PTP_IEEE802_11A,  "IEEE 802.11a"},
  {PTP_IEEE_WIRELESS,  "IEEE 802.11b"},
  {PTP_INFINIBAND,  "InfiniBand"},
  {PTP_BLUETOOTH,  "Bluetooth wireless"},
  {PTP_IEEE802_15_1,  "IEEE 802.15.1"},
  {PTP_IEEE1451_3,  "IEEE 1451.3"},
  {PTP_IEEE1451_5,  "IEEE 1451.5"},
  {PTP_USB,  "USB bus"},
  {PTP_ISA,  "ISA bus"},
  {PTP_PCI,  "PCI bus"},
  {PTP_VXI,  "VXI bus"},
  {PTP_DEFAULT,  "Default value"},
  {0,              NULL          } };

/*END CommunicationId definitions*/

/**********************************************************/
/* PTP message types	(PTP_CONTROL field)				  */
/**********************************************************/
#define	PTP_SYNC_MESSAGE		0x00
#define	PTP_DELAY_REQ_MESSAGE	0x01
#define	PTP_FOLLOWUP_MESSAGE	0x02
#define	PTP_DELAY_RESP_MESSAGE	0x03
#define	PTP_MANAGEMENT_MESSAGE	0x04

static const value_string ptp_control_vals[] = {
  {PTP_SYNC_MESSAGE,  "Sync Message"},
  {PTP_DELAY_REQ_MESSAGE,  "Delay_Req Message"},
  {PTP_FOLLOWUP_MESSAGE,    "Follow_Up Message"},
  {PTP_DELAY_RESP_MESSAGE, "Delay_Resp Message"},
  {PTP_MANAGEMENT_MESSAGE,   "Management Message"},
  {0,              NULL          } };

/*END PTP message types*/

/**********************************************************/
/* Channel values for the PTP_MESSAGETYPE field			  */
/**********************************************************/
#define	PTP_MESSAGETYPE_EVENT	0x01
#define	PTP_MESSAGETYPE_GENERAL	0x02

static const value_string ptp_messagetype_vals[] = {
  {PTP_MESSAGETYPE_EVENT, "Event Message"},
  {PTP_MESSAGETYPE_GENERAL, "General Message"},
  {0,              NULL          } };

/*END channel values for the PTP_MESSAGETYPE field*/

/* Channel values for boolean vals (FLAGS)*/

static const value_string ptp_bool_vals[] = {
  {1, "True"},
  {0, "False"},
  {0,              NULL          }};

/**********************************************************/
/* Initialize the protocol and registered fields		  */
/**********************************************************/

static int proto_ptp = -1;
static int hf_ptp_versionptp = -1;
static int hf_ptp_versionnetwork = -1;
static int hf_ptp_subdomain = -1;
static int hf_ptp_messagetype = -1;
static int hf_ptp_sourcecommunicationtechnology = -1;
static int hf_ptp_sourceuuid = -1;
static int hf_ptp_sourceportid = -1;
static int hf_ptp_sequenceid = -1;
static int hf_ptp_control = -1;
static int hf_ptp_flags = -1;
static int hf_ptp_flags_li61 = -1;
static int hf_ptp_flags_li59 = -1;
static int hf_ptp_flags_boundary_clock = -1;
static int hf_ptp_flags_assist = -1;
static int hf_ptp_flags_ext_sync = -1;
static int hf_ptp_flags_parent = -1;
static int hf_ptp_flags_sync_burst = -1;

/*offsets for ptp_sync and delay_req (=sdr) messages*/
static int hf_ptp_origintimestamp = -1;	/*Field for seconds & nanoseconds*/
static int hf_ptp_sdr_origintimestamp_seconds = -1;
static int hf_ptp_sdr_origintimestamp_nanoseconds = -1;
static int hf_ptp_sdr_epochnumber = -1;
static int hf_ptp_sdr_currentutcoffset = -1;
static int hf_ptp_sdr_grandmastercommunicationtechnology = -1;
static int hf_ptp_sdr_grandmasterclockuuid = -1;
static int hf_ptp_sdr_grandmasterportid = -1;
static int hf_ptp_sdr_grandmastersequenceid = -1;
static int hf_ptp_sdr_grandmasterclockstratum = -1;
static int hf_ptp_sdr_grandmasterclockidentifier = -1;
static int hf_ptp_sdr_grandmasterclockvariance = -1;
static int hf_ptp_sdr_grandmasterpreferred = -1;
static int hf_ptp_sdr_grandmasterisboundaryclock = -1;
static int hf_ptp_sdr_syncinterval = -1;
static int hf_ptp_sdr_localclockvariance = -1;
static int hf_ptp_sdr_localstepsremoved = -1;
static int hf_ptp_sdr_localclockstratum = -1;
static int hf_ptp_sdr_localclockidentifier = -1;
static int hf_ptp_sdr_parentcommunicationtechnology = -1;
static int hf_ptp_sdr_parentuuid = -1;
static int hf_ptp_sdr_parentportfield = -1;
static int hf_ptp_sdr_estimatedmastervariance = -1;
static int hf_ptp_sdr_estimatedmasterdrift = -1;
static int hf_ptp_sdr_utcreasonable = -1;

/*offsets for follow_up (=fu) messages*/
static int hf_ptp_fu_associatedsequenceid = -1;
static int hf_ptp_fu_preciseorigintimestamp = -1;
static int hf_ptp_fu_preciseorigintimestamp_seconds = -1;
static int hf_ptp_fu_preciseorigintimestamp_nanoseconds = -1;

/*offsets for delay_resp (=dr) messages*/
static int hf_ptp_dr_delayreceipttimestamp = -1;
static int hf_ptp_dr_delayreceipttimestamp_seconds = -1;
static int hf_ptp_dr_delayreceipttimestamp_nanoseconds = -1;
static int hf_ptp_dr_requestingsourcecommunicationtechnology = -1;
static int hf_ptp_dr_requestingsourceuuid = -1;
static int hf_ptp_dr_requestingsourceportid = -1;
static int hf_ptp_dr_requestingsourcesequenceid = -1;

/*offsets for management (=mm) messages*/
static int hf_ptp_mm_targetcommunicationtechnology = -1;
static int hf_ptp_mm_targetuuid = -1;
static int hf_ptp_mm_targetportid = -1;
static int hf_ptp_mm_startingboundaryhops = -1;
static int hf_ptp_mm_boundaryhops = -1;
static int hf_ptp_mm_managementmessagekey = -1;
static int hf_ptp_mm_parameterlength = -1;
	/*parameterlength > 0*/
static int hf_ptp_mm_messageparameters = -1;
	/*ptp_mm_clock_identity (parameterlength = 64)*/
static int hf_ptp_mm_clock_identity_clockcommunicationtechnology = -1;
static int hf_ptp_mm_clock_identity_clockuuidfield = -1;
static int hf_ptp_mm_clock_identity_clockportfield = -1;
static int hf_ptp_mm_clock_identity_manufactureridentity = -1;

	/*ptp_mm_initialize_clock (parameterlength = 4)*/
static int hf_ptp_mm_initialize_clock_initialisationkey = -1;

	/*ptp_mm_set_subdomain (parameterlength = 16)*/
static int hf_ptp_mm_set_subdomain_subdomainname = -1;

	/*ptp_mm_default_data_set (parameterlength = 76)*/
static int hf_ptp_mm_default_data_set_clockcommunicationtechnology = -1;
static int hf_ptp_mm_default_data_set_clockuuidfield = -1;
static int hf_ptp_mm_default_data_set_clockportfield = -1;
static int hf_ptp_mm_default_data_set_clockstratum = -1;
static int hf_ptp_mm_default_data_set_clockidentifier = -1;
static int hf_ptp_mm_default_data_set_clockvariance = -1;
static int hf_ptp_mm_default_data_set_clockfollowupcapable = -1;
static int hf_ptp_mm_default_data_set_preferred = -1;
static int hf_ptp_mm_default_data_set_initializable = -1;
static int hf_ptp_mm_default_data_set_externaltiming = -1;
static int hf_ptp_mm_default_data_set_isboundaryclock = -1;
static int hf_ptp_mm_default_data_set_syncinterval = -1;
static int hf_ptp_mm_default_data_set_subdomainname = -1;
static int hf_ptp_mm_default_data_set_numberports = -1;
static int hf_ptp_mm_default_data_set_numberforeignrecords = -1;

	/*ptp_mm_update_default_data_set (parameterlength = 36)*/
static int hf_ptp_mm_update_default_data_set_clockstratum = -1;
static int hf_ptp_mm_update_default_data_set_clockidentifier = -1;
static int hf_ptp_mm_update_default_data_set_clockvariance = -1;
static int hf_ptp_mm_update_default_data_set_preferred = -1;
static int hf_ptp_mm_update_default_data_set_syncinterval = -1;
static int hf_ptp_mm_update_default_data_set_subdomainname = -1;

	/*ptp_mm_current_data_set (parameterlength = 20)*/
static int hf_ptp_mm_current_data_set_stepsremoved = -1;
static int hf_ptp_mm_current_data_set_offsetfrommaster = -1;
static int hf_ptp_mm_current_data_set_offsetfrommasterseconds = -1;
static int hf_ptp_mm_current_data_set_offsetfrommasternanoseconds = -1;
static int hf_ptp_mm_current_data_set_onewaydelay = -1;
static int hf_ptp_mm_current_data_set_onewaydelayseconds = -1;
static int hf_ptp_mm_current_data_set_onewaydelaynanoseconds = -1;

	/*ptp_mm_parent_data_set (parameterlength = 90)*/
static int hf_ptp_mm_parent_data_set_parentcommunicationtechnology = -1;
static int hf_ptp_mm_parent_data_set_parentuuid = -1;
static int hf_ptp_mm_parent_data_set_parentportid = -1;
static int hf_ptp_mm_parent_data_set_parentlastsyncsequencenumber = -1;
static int hf_ptp_mm_parent_data_set_parentfollowupcapable = -1;
static int hf_ptp_mm_parent_data_set_parentexternaltiming = -1;
static int hf_ptp_mm_parent_data_set_parentvariance = -1;
static int hf_ptp_mm_parent_data_set_parentstats = -1;
static int hf_ptp_mm_parent_data_set_observedvariance = -1;
static int hf_ptp_mm_parent_data_set_observeddrift = -1;
static int hf_ptp_mm_parent_data_set_utcreasonable = -1;
static int hf_ptp_mm_parent_data_set_grandmastercommunicationtechnology = -1;
static int hf_ptp_mm_parent_data_set_grandmasteruuidfield = -1;
static int hf_ptp_mm_parent_data_set_grandmasterportidfield = -1;
static int hf_ptp_mm_parent_data_set_grandmasterstratum = -1;
static int hf_ptp_mm_parent_data_set_grandmasteridentifier = -1;
static int hf_ptp_mm_parent_data_set_grandmastervariance = -1;
static int hf_ptp_mm_parent_data_set_grandmasterpreferred = -1;
static int hf_ptp_mm_parent_data_set_grandmasterisboundaryclock = -1;
static int hf_ptp_mm_parent_data_set_grandmastersequencenumber = -1;

	/*ptp_mm_port_data_set (parameterlength = 52)*/
static int hf_ptp_mm_port_data_set_returnedportnumber = -1;
static int hf_ptp_mm_port_data_set_portstate = -1;
static int hf_ptp_mm_port_data_set_lastsynceventsequencenumber = -1;
static int hf_ptp_mm_port_data_set_lastgeneraleventsequencenumber = -1;
static int hf_ptp_mm_port_data_set_portcommunicationtechnology = -1;
static int hf_ptp_mm_port_data_set_portuuidfield = -1;
static int hf_ptp_mm_port_data_set_portidfield = -1;
static int hf_ptp_mm_port_data_set_burstenabled = -1;
static int hf_ptp_mm_port_data_set_subdomainaddressoctets = -1;
static int hf_ptp_mm_port_data_set_eventportaddressoctets = -1;
static int hf_ptp_mm_port_data_set_generalportaddressoctets = -1;
static int hf_ptp_mm_port_data_set_subdomainaddress = -1;
static int hf_ptp_mm_port_data_set_eventportaddress = -1;
static int hf_ptp_mm_port_data_set_generalportaddress = -1;

	/*ptp_mm_global_time_data_set (parameterlength = 24)*/
static int hf_ptp_mm_global_time_data_set_localtime = -1;
static int hf_ptp_mm_global_time_data_set_localtimeseconds = -1;
static int hf_ptp_mm_global_time_data_set_localtimenanoseconds = -1;
static int hf_ptp_mm_global_time_data_set_currentutcoffset = -1;
static int hf_ptp_mm_global_time_data_set_leap59 = -1;
static int hf_ptp_mm_global_time_data_set_leap61 = -1;
static int hf_ptp_mm_global_time_data_set_epochnumber = -1;

	/*ptp_mm_update_global_time_properties (parameterlength = 16)*/
static int hf_ptp_mm_update_global_time_properties_currentutcoffset = -1;
static int hf_ptp_mm_update_global_time_properties_leap59 = -1;
static int hf_ptp_mm_update_global_time_properties_leap61 = -1;
static int hf_ptp_mm_update_global_time_properties_epochnumber = -1;

	/*ptp_mm_get_foreign_data_set (parameterlength = 4)*/
static int hf_ptp_mm_get_foreign_data_set_recordkey = -1;

	/*ptp_mm_foreign_data_set (parameterlength = 28)*/
static int hf_ptp_mm_foreign_data_set_returnedportnumber = -1;
static int hf_ptp_mm_foreign_data_set_returnedrecordnumber = -1;
static int hf_ptp_mm_foreign_data_set_foreignmastercommunicationtechnology = -1;
static int hf_ptp_mm_foreign_data_set_foreignmasteruuidfield = -1;
static int hf_ptp_mm_foreign_data_set_foreignmasterportidfield = -1;
static int hf_ptp_mm_foreign_data_set_foreignmastersyncs = -1;

	/*ptp_mm_set_sync_interval (parameterlength = 4)*/
static int hf_ptp_mm_set_sync_interval_syncinterval = -1;

	/*ptp_mm_set_time (parameterlength = 8)*/
static int hf_ptp_mm_set_time_localtime = -1;
static int hf_ptp_mm_set_time_localtimeseconds = -1;
static int hf_ptp_mm_set_time_localtimenanoseconds = -1;

/*END Initialize the protocol and registered fields */

/* Initialize the subtree pointers */
static gint ett_ptp = -1;
static gint ett_ptp_flags = -1;
static gint ett_ptp_time = -1;
static gint ett_ptp_time2 = -1;


/* Code to actually dissect the packets */
static void
dissect_ptp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8	ptp_control, ptp_mm_messagekey = 0;
	nstime_t ts;	/*time structure with seconds and nanoseconds*/

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti, *flags_ti, *time_ti, *time2_ti;
	proto_tree *ptp_tree, *ptp_flags_tree, *ptp_time_tree, *ptp_time2_tree;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "PTP");


/* Get control field (what kind of message is this? (Sync, DelayReq, ...) */

	ptp_control = tvb_get_guint8 (tvb, PTP_CONTROL_OFFSET);
	/* MGMT packet? */
	if ( ptp_control == PTP_MANAGEMENT_MESSAGE ){
		/* Get the managementMessageKey */
			ptp_mm_messagekey = tvb_get_guint8(tvb, PTP_MM_MANAGEMENTMESSAGEKEY_OFFSET);
	}

/* Create and set the string for "Info" column */
	switch(ptp_control){
		case PTP_SYNC_MESSAGE:{
			if (check_col(pinfo->cinfo, COL_INFO))
				col_set_str(pinfo->cinfo, COL_INFO, "Sync Message");
			break;
		}
		case PTP_DELAY_REQ_MESSAGE:{
			if (check_col(pinfo->cinfo, COL_INFO))
				col_set_str(pinfo->cinfo, COL_INFO, "Delay_Request Message");
			break;
		}
		case PTP_FOLLOWUP_MESSAGE:{
			if (check_col(pinfo->cinfo, COL_INFO))
				col_set_str(pinfo->cinfo, COL_INFO, "Follow_Up Message");
			break;
		}
		case PTP_DELAY_RESP_MESSAGE:{
			if (check_col(pinfo->cinfo, COL_INFO))
				col_set_str(pinfo->cinfo, COL_INFO, "Delay_Response Message");
			break;
		}
		case PTP_MANAGEMENT_MESSAGE:{
			if (check_col(pinfo->cinfo, COL_INFO)){
				col_add_fstr(pinfo->cinfo, COL_INFO, "Management Message (%s)",
				    val_to_str(ptp_mm_messagekey,
				        ptp_managementMessageKey_infocolumn_vals,
				        "Unknown message key %u"));
			}
			break;
		}
		default:{
			if (check_col(pinfo->cinfo, COL_INFO))
				col_add_str(pinfo->cinfo, COL_INFO, "Unknown Message");
			break;
		}
	}

	if (tree) {

		/* create display subtree for the protocol */
		ti = proto_tree_add_item(tree, proto_ptp, tvb, 0, -1, FALSE);

		ptp_tree = proto_item_add_subtree(ti, ett_ptp);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_versionptp, tvb, PTP_VERSIONPTP_OFFSET, 2, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_versionnetwork, tvb, PTP_VERSIONNETWORK_OFFSET, 2, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_subdomain, tvb, PTP_SUBDOMAIN_OFFSET, 16, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_messagetype, tvb, PTP_MESSAGETYPE_OFFSET, 1, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_sourcecommunicationtechnology, tvb, PTP_SOURCECOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_sourceuuid, tvb, PTP_SOURCEUUID_OFFSET, 6, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_sourceportid, tvb, PTP_SOURCEPORTID_OFFSET, 2, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_sequenceid, tvb, PTP_SEQUENCEID_OFFSET, 2, FALSE);

		proto_tree_add_item(ptp_tree,
		    hf_ptp_control, tvb, PTP_CONTROL_OFFSET, 1, FALSE);

		/*Subtree for the flag-field*/
		if(tree){
			flags_ti = proto_tree_add_item(ptp_tree,
		    	hf_ptp_flags, tvb, PTP_FLAGS_OFFSET, 2, FALSE);

			ptp_flags_tree = proto_item_add_subtree(flags_ti, ett_ptp_flags);

			proto_tree_add_item(ptp_flags_tree,
		    	hf_ptp_flags_li61, tvb, PTP_FLAGS_LI61_OFFSET, 2, FALSE);

			proto_tree_add_item(ptp_flags_tree,
		    	hf_ptp_flags_li59, tvb, PTP_FLAGS_LI59_OFFSET, 2, FALSE);

			proto_tree_add_item(ptp_flags_tree,
		    	hf_ptp_flags_boundary_clock, tvb, PTP_FLAGS_BOUNDARY_CLOCK_OFFSET, 2, FALSE);

			proto_tree_add_item(ptp_flags_tree,
		    	hf_ptp_flags_assist, tvb, PTP_FLAGS_ASSIST_OFFSET, 2, FALSE);

			proto_tree_add_item(ptp_flags_tree,
				hf_ptp_flags_ext_sync, tvb, PTP_FLAGS_EXT_SYNC_OFFSET, 2, FALSE);

			proto_tree_add_item(ptp_flags_tree,
		    	hf_ptp_flags_parent, tvb, PTP_FLAGS_PARENT_STATS_OFFSET, 2, FALSE);

			proto_tree_add_item(ptp_flags_tree,
		    	hf_ptp_flags_sync_burst, tvb, PTP_FLAGS_SYNC_BURST_OFFSET, 2, FALSE);
		}

		/* The rest of the ptp-dissector depends on the control-field  */

		switch(ptp_control){
			case PTP_SYNC_MESSAGE:
			case PTP_DELAY_REQ_MESSAGE:{

			/*Subtree for the timestamp-field*/
			ts.secs = tvb_get_ntohl(tvb, PTP_SDR_ORIGINTIMESTAMP_SECONDS_OFFSET);
			ts.nsecs =  tvb_get_ntohl(tvb, PTP_SDR_ORIGINTIMESTAMP_NANOSECONDS_OFFSET);
			if(tree){
				time_ti = proto_tree_add_time(ptp_tree,
			    	hf_ptp_origintimestamp, tvb, PTP_SDR_ORIGINTIMESTAMP_OFFSET, 8, &ts);

				ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

				proto_tree_add_item(ptp_time_tree,
						hf_ptp_sdr_origintimestamp_seconds, tvb,
						PTP_SDR_ORIGINTIMESTAMP_SECONDS_OFFSET, 4, FALSE);

					proto_tree_add_item(ptp_time_tree, hf_ptp_sdr_origintimestamp_nanoseconds, tvb,
							PTP_SDR_ORIGINTIMESTAMP_NANOSECONDS_OFFSET, 4, FALSE);
				}

				proto_tree_add_item(ptp_tree,
						hf_ptp_sdr_epochnumber, tvb, PTP_SDR_EPOCHNUMBER_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_currentutcoffset, tvb, PTP_SDR_CURRENTUTCOFFSET_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree, hf_ptp_sdr_grandmastercommunicationtechnology, tvb,
						PTP_SDR_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_grandmasterclockuuid, tvb, PTP_SDR_GRANDMASTERCLOCKUUID_OFFSET, 6, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_grandmasterportid, tvb, PTP_SDR_GRANDMASTERPORTID_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_grandmastersequenceid, tvb, PTP_SDR_GRANDMASTERSEQUENCEID_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_grandmasterclockstratum, tvb,
						PTP_SDR_GRANDMASTERCLOCKSTRATUM_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree, hf_ptp_sdr_grandmasterclockidentifier, tvb,
						PTP_SDR_GRANDMASTERCLOCKIDENTIFIER_OFFSET, 4, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_grandmasterclockvariance, tvb,
						PTP_SDR_GRANDMASTERCLOCKVARIANCE_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_grandmasterpreferred, tvb, PTP_SDR_GRANDMASTERPREFERRED_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree, hf_ptp_sdr_grandmasterisboundaryclock, tvb,
						PTP_SDR_GRANDMASTERISBOUNDARYCLOCK_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_syncinterval, tvb, PTP_SDR_SYNCINTERVAL_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_localclockvariance, tvb, PTP_SDR_LOCALCLOCKVARIANCE_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_localstepsremoved, tvb, PTP_SDR_LOCALSTEPSREMOVED_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_localclockstratum, tvb, PTP_SDR_LOCALCLOCKSTRATUM_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_localclockidentifier, tvb, PTP_SDR_LOCALCLOCKIDENTIFIER_OFFSET, 4, FALSE);

				proto_tree_add_item(ptp_tree, hf_ptp_sdr_parentcommunicationtechnology, tvb,
						PTP_SDR_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_parentuuid, tvb, PTP_SDR_PARENTUUID_OFFSET, 6, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_parentportfield, tvb, PTP_SDR_PARENTPORTFIELD_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_estimatedmastervariance, tvb,
						PTP_SDR_ESTIMATEDMASTERVARIANCE_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_estimatedmasterdrift, tvb, PTP_SDR_ESTIMATEDMASTERDRIFT_OFFSET, 4, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_sdr_utcreasonable, tvb, PTP_SDR_UTCREASONABLE_OFFSET, 1, FALSE);
				break;
			}
			case PTP_FOLLOWUP_MESSAGE:{
				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_fu_associatedsequenceid, tvb, PTP_FU_ASSOCIATEDSEQUENCEID_OFFSET, 2, FALSE);

				/*Subtree for the timestamp-field*/
				ts.secs = tvb_get_ntohl(tvb, PTP_FU_PRECISEORIGINTIMESTAMP_SECONDS_OFFSET);
				ts.nsecs = tvb_get_ntohl(tvb, PTP_FU_PRECISEORIGINTIMESTAMP_NANOSECONDS_OFFSET);
				if(tree){
					time_ti = proto_tree_add_time(ptp_tree,
			    			hf_ptp_fu_preciseorigintimestamp, tvb,
							PTP_FU_PRECISEORIGINTIMESTAMP_OFFSET, 8, &ts);

					ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

					proto_tree_add_item(ptp_time_tree, hf_ptp_fu_preciseorigintimestamp_seconds, tvb,
							PTP_FU_PRECISEORIGINTIMESTAMP_SECONDS_OFFSET, 4, FALSE);

					proto_tree_add_item(ptp_time_tree, hf_ptp_fu_preciseorigintimestamp_nanoseconds, tvb,
							PTP_FU_PRECISEORIGINTIMESTAMP_NANOSECONDS_OFFSET, 4, FALSE);
				}
				break;
			}
			case PTP_DELAY_RESP_MESSAGE:{
				/*Subtree for the timestamp-field*/
				ts.secs = tvb_get_ntohl(tvb, PTP_DR_DELAYRECEIPTTIMESTAMP_SECONDS_OFFSET);
				ts.nsecs = tvb_get_ntohl(tvb, PTP_DR_DELAYRECEIPTTIMESTAMP_NANOSECONDS_OFFSET);
				if(tree){
					time_ti = proto_tree_add_time(ptp_tree,
			    			hf_ptp_dr_delayreceipttimestamp, tvb,
							PTP_DR_DELAYRECEIPTTIMESTAMP_OFFSET, 8, &ts);

					ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

					proto_tree_add_item(ptp_time_tree, hf_ptp_dr_delayreceipttimestamp_seconds, tvb,
							PTP_DR_DELAYRECEIPTTIMESTAMP_SECONDS_OFFSET, 4, FALSE);

					proto_tree_add_item(ptp_time_tree, hf_ptp_dr_delayreceipttimestamp_nanoseconds, tvb,
							PTP_DR_DELAYRECEIPTTIMESTAMP_NANOSECONDS_OFFSET, 4, FALSE);
				}

				proto_tree_add_item(ptp_tree, hf_ptp_dr_requestingsourcecommunicationtechnology, tvb,
					PTP_DR_REQUESTINGSOURCECOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_dr_requestingsourceuuid, tvb, PTP_DR_REQUESTINGSOURCEUUID_OFFSET, 6, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_dr_requestingsourceportid, tvb, PTP_DR_REQUESTINGSOURCEPORTID_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_dr_requestingsourcesequenceid, tvb,
						PTP_DR_REQUESTINGSOURCESEQUENCEID_OFFSET, 2, FALSE);
				break;
			}
			case PTP_MANAGEMENT_MESSAGE:{
				proto_tree_add_item(ptp_tree, hf_ptp_mm_targetcommunicationtechnology, tvb,
						PTP_MM_TARGETCOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_mm_targetuuid, tvb, PTP_MM_TARGETUUID_OFFSET, 6, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_mm_targetportid, tvb, PTP_MM_TARGETPORTID_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_mm_startingboundaryhops, tvb, PTP_MM_STARTINGBOUNDARYHOPS_OFFSET, 2, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_mm_boundaryhops, tvb, PTP_MM_BOUNDARYHOPS_OFFSET, 2, FALSE);


				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_mm_managementmessagekey, tvb, PTP_MM_MANAGEMENTMESSAGEKEY_OFFSET, 1, FALSE);

				proto_tree_add_item(ptp_tree,
		    		    hf_ptp_mm_parameterlength, tvb, PTP_MM_PARAMETERLENGTH_OFFSET, 2, FALSE);

				switch(ptp_mm_messagekey){
					case PTP_MM_CLOCK_IDENTITY:{
						proto_tree_add_item(ptp_tree,
								hf_ptp_mm_clock_identity_clockcommunicationtechnology, tvb,
								PTP_MM_CLOCK_IDENTITY_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_clock_identity_clockuuidfield, tvb,
								PTP_MM_CLOCK_IDENTITY_CLOCKUUIDFIELD_OFFSET, 6, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_clock_identity_clockportfield, tvb,
								PTP_MM_CLOCK_IDENTITY_CLOCKPORTFIELD_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_clock_identity_manufactureridentity, tvb,
								PTP_MM_CLOCK_IDENTITY_MANUFACTURERIDENTITY_OFFSET, 48, FALSE);
						break;
					}
					case PTP_MM_INITIALIZE_CLOCK:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_initialize_clock_initialisationkey, tvb,
							PTP_MM_INITIALIZE_CLOCK_INITIALISATIONKEY_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_SET_SUBDOMAIN:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_set_subdomain_subdomainname, tvb,
								PTP_MM_SET_SUBDOMAIN_SUBDOMAINNAME_OFFSET, 16, FALSE);
						break;
					}
					case PTP_MM_DEFAULT_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockcommunicationtechnology,
								tvb, PTP_MM_DEFAULT_DATA_SET_CLOCKCOMMUNICATIONTECHNOLOGY_OFFSET,
								 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockuuidfield, tvb,
								PTP_MM_DEFAULT_DATA_SET_CLOCKUUIDFIELD_OFFSET, 6, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockportfield, tvb,
								PTP_MM_DEFAULT_DATA_SET_CLOCKPORTFIELD_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockstratum, tvb,
								PTP_MM_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockidentifier, tvb,
								PTP_MM_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET, 4, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockvariance, tvb,
								PTP_MM_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_clockfollowupcapable, tvb,
								PTP_MM_DEFAULT_DATA_SET_CLOCKFOLLOWUPCAPABLE_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_preferred, tvb,
								PTP_MM_DEFAULT_DATA_SET_PREFERRED_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_initializable, tvb,
								PTP_MM_DEFAULT_DATA_SET_INITIALIZABLE_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_externaltiming, tvb,
								PTP_MM_DEFAULT_DATA_SET_EXTERNALTIMING_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_isboundaryclock, tvb,
								PTP_MM_DEFAULT_DATA_SET_ISBOUNDARYCLOCK_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_syncinterval, tvb,
								PTP_MM_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_subdomainname, tvb,
								PTP_MM_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET, 16, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_numberports, tvb,
								PTP_MM_DEFAULT_DATA_SET_NUMBERPORTS_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_default_data_set_numberforeignrecords, tvb,
								PTP_MM_DEFAULT_DATA_SET_NUMBERFOREIGNRECORDS_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_UPDATE_DEFAULT_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_clockstratum, tvb,
								PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKSTRATUM_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_clockidentifier, tvb,
								PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKIDENTIFIER_OFFSET, 4, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_clockvariance, tvb,
								PTP_MM_UPDATE_DEFAULT_DATA_SET_CLOCKVARIANCE_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_preferred, tvb,
								PTP_MM_UPDATE_DEFAULT_DATA_SET_PREFERRED_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_syncinterval, tvb,
								PTP_MM_UPDATE_DEFAULT_DATA_SET_SYNCINTERVAL_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_default_data_set_subdomainname, tvb,
								PTP_MM_UPDATE_DEFAULT_DATA_SET_SUBDOMAINNAME_OFFSET, 16, FALSE);
						break;
					}
					case PTP_MM_CURRENT_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_current_data_set_stepsremoved, tvb,
								PTP_MM_CURRENT_DATA_SET_STEPSREMOVED_OFFSET, 2, FALSE);

						/* Subtree for offset from master*/
						ts.secs = tvb_get_ntohl(tvb, PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERSECONDS_OFFSET);

						ts.nsecs = tvb_get_ntohl(tvb,
								PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERNANOSECONDS_OFFSET);

						if(tree){
							time_ti = proto_tree_add_time(ptp_tree,
									hf_ptp_mm_current_data_set_offsetfrommaster, tvb,
									PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTER_OFFSET, 8, &ts);

							ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

							proto_tree_add_item(ptp_time_tree,
									hf_ptp_mm_current_data_set_offsetfrommasterseconds, tvb,
									PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERSECONDS_OFFSET, 4, FALSE);

							proto_tree_add_item(ptp_time_tree,
									hf_ptp_mm_current_data_set_offsetfrommasternanoseconds, tvb,
									PTP_MM_CURRENT_DATA_SET_OFFSETFROMMASTERNANOSECONDS_OFFSET, 4, FALSE);
						}

						/* Subtree for offset from master*/
						ts.secs = tvb_get_ntohl(tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYSECONDS_OFFSET);

						ts.nsecs = tvb_get_ntohl(tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYNANOSECONDS_OFFSET);

						if(tree){
							time2_ti = proto_tree_add_time(ptp_tree,
									hf_ptp_mm_current_data_set_onewaydelay, tvb,
									PTP_MM_CURRENT_DATA_SET_ONEWAYDELAY_OFFSET, 8, &ts);

							ptp_time2_tree = proto_item_add_subtree(time2_ti, ett_ptp_time2);

							proto_tree_add_item(ptp_time2_tree, hf_ptp_mm_current_data_set_onewaydelayseconds,
									tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYSECONDS_OFFSET, 4, FALSE);

							proto_tree_add_item(ptp_time2_tree,
									hf_ptp_mm_current_data_set_onewaydelaynanoseconds,
									tvb, PTP_MM_CURRENT_DATA_SET_ONEWAYDELAYNANOSECONDS_OFFSET, 4, FALSE);
						}
						break;
					}
					case PTP_MM_PARENT_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentcommunicationtechnology,
								tvb, PTP_MM_PARENT_DATA_SET_PARENTCOMMUNICATIONTECHNOLOGY_OFFSET,
								1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentuuid, tvb,
								PTP_MM_PARENT_DATA_SET_PARENTUUID_OFFSET, 6, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentportid, tvb,
								PTP_MM_PARENT_DATA_SET_PARENTPORTID_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentlastsyncsequencenumber,
								tvb, PTP_MM_PARENT_DATA_SET_PARENTLASTSYNCSEQUENCENUMBER_OFFSET,
								2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentfollowupcapable, tvb,
								PTP_MM_PARENT_DATA_SET_PARENTFOLLOWUPCAPABLE_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentexternaltiming, tvb,
								PTP_MM_PARENT_DATA_SET_PARENTEXTERNALTIMING_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentvariance, tvb,
								PTP_MM_PARENT_DATA_SET_PARENTVARIANCE_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_parentstats, tvb,
								PTP_MM_PARENT_DATA_SET_PARENTSTATS_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_observedvariance, tvb,
								PTP_MM_PARENT_DATA_SET_OBSERVEDVARIANCE_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_observeddrift, tvb,
								PTP_MM_PARENT_DATA_SET_OBSERVEDDRIFT_OFFSET, 4, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_utcreasonable, tvb,
								PTP_MM_PARENT_DATA_SET_UTCREASONABLE_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree,
								hf_ptp_mm_parent_data_set_grandmastercommunicationtechnology,
								tvb, PTP_MM_PARENT_DATA_SET_GRANDMASTERCOMMUNICATIONTECHNOLOGY_OFFSET, 1,
								FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasteruuidfield, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERUUIDFIELD_OFFSET, 6, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterportidfield, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERPORTIDFIELD_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterstratum, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERSTRATUM_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasteridentifier, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERIDENTIFIER_OFFSET, 4, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmastervariance, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERVARIANCE_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterpreferred, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERPREFERRED_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmasterisboundaryclock, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERISBOUNDARYCLOCK_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_parent_data_set_grandmastersequencenumber, tvb,
								PTP_MM_PARENT_DATA_SET_GRANDMASTERSEQUENCENUMBER_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_PORT_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_returnedportnumber, tvb,
								PTP_MM_PORT_DATA_SET_RETURNEDPORTNUMBER_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portstate, tvb,
								PTP_MM_PORT_DATA_SET_PORTSTATE_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_lastsynceventsequencenumber, tvb,
								PTP_MM_PORT_DATA_SET_LASTSYNCEVENTSEQUENCENUMBER_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_lastgeneraleventsequencenumber,
								tvb, PTP_MM_PORT_DATA_SET_LASTGENERALEVENTSEQUENCENUMBER_OFFSET,
								2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portcommunicationtechnology, tvb,
								PTP_MM_PORT_DATA_SET_PORTCOMMUNICATIONTECHNOLOGY_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portuuidfield, tvb,
								PTP_MM_PORT_DATA_SET_PORTUUIDFIELD_OFFSET, 6, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_portidfield, tvb,
								PTP_MM_PORT_DATA_SET_PORTIDFIELD_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_burstenabled, tvb,
								PTP_MM_PORT_DATA_SET_BURSTENABLED_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_subdomainaddressoctets, tvb,
								PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESSOCTETS_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_eventportaddressoctets, tvb,
								PTP_MM_PORT_DATA_SET_EVENTPORTADDRESSOCTETS_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_generalportaddressoctets, tvb,
								PTP_MM_PORT_DATA_SET_GENERALPORTADDRESSOCTETS_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_subdomainaddress, tvb,
								PTP_MM_PORT_DATA_SET_SUBDOMAINADDRESS_OFFSET, 4, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_eventportaddress, tvb,
								PTP_MM_PORT_DATA_SET_EVENTPORTADDRESS_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_port_data_set_generalportaddress, tvb,
								PTP_MM_PORT_DATA_SET_GENERALPORTADDRESS_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_GLOBAL_TIME_DATA_SET:{
						/* Subtree for local time*/
						ts.secs = tvb_get_ntohl(tvb, PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMESECONDS_OFFSET);

						ts.nsecs = tvb_get_ntohl(tvb,
								PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMENANOSECONDS_OFFSET);

						if(tree){
							time_ti = proto_tree_add_time(ptp_tree,
									hf_ptp_mm_global_time_data_set_localtime, tvb,
									PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIME_OFFSET, 8, &ts);

							ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

							proto_tree_add_item(ptp_time_tree,
									hf_ptp_mm_global_time_data_set_localtimeseconds, tvb,
									PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMESECONDS_OFFSET, 4, FALSE);

							proto_tree_add_item(ptp_time_tree,
									hf_ptp_mm_global_time_data_set_localtimenanoseconds,
									tvb, PTP_MM_GLOBAL_TIME_DATA_SET_LOCALTIMENANOSECONDS_OFFSET, 4, FALSE);
						}

						proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_currentutcoffset, tvb,
								PTP_MM_GLOBAL_TIME_DATA_SET_CURRENTUTCOFFSET_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_leap59, tvb,
								PTP_MM_GLOBAL_TIME_DATA_SET_LEAP59_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_leap61, tvb,
								PTP_MM_GLOBAL_TIME_DATA_SET_LEAP61_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_global_time_data_set_epochnumber, tvb,
								PTP_MM_GLOBAL_TIME_DATA_SET_EPOCHNUMBER_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_global_time_properties_currentutcoffset,
								tvb, PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_CURRENTUTCOFFSET_OFFSET,
								2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_global_time_properties_leap59, tvb,
								PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP59_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_update_global_time_properties_leap61, tvb,
								PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_LEAP61_OFFSET, 1, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_get_foreign_data_set_recordkey, tvb,
								PTP_MM_UPDATE_GLOBAL_TIME_PROPERTIES_EPOCHNUMBER_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_GET_FOREIGN_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_get_foreign_data_set_recordkey, tvb,
								PTP_MM_GET_FOREIGN_DATA_SET_RECORDKEY_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_FOREIGN_DATA_SET:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_returnedportnumber, tvb,
								PTP_MM_FOREIGN_DATA_SET_RETURNEDPORTNUMBER_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_returnedrecordnumber, tvb,
								PTP_MM_FOREIGN_DATA_SET_RETURNEDRECORDNUMBER_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree,
								hf_ptp_mm_foreign_data_set_foreignmastercommunicationtechnology,
								tvb, PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERCOMMUNICATIONTECHNOLOGY_OFFSET, 1,
								FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_foreignmasteruuidfield, tvb,
								PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERUUIDFIELD_OFFSET, 6, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_foreignmasterportidfield, tvb,
								PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERPORTIDFIELD_OFFSET, 2, FALSE);

						proto_tree_add_item(ptp_tree, hf_ptp_mm_foreign_data_set_foreignmastersyncs, tvb,
								PTP_MM_FOREIGN_DATA_SET_FOREIGNMASTERSYNCS_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_SET_SYNC_INTERVAL:{
						proto_tree_add_item(ptp_tree, hf_ptp_mm_set_sync_interval_syncinterval, tvb,
								PTP_MM_SET_SYNC_INTERVAL_SYNCINTERVAL_OFFSET, 2, FALSE);
						break;
					}
					case PTP_MM_SET_TIME:{
						/* Subtree for local time*/
						ts.secs = tvb_get_ntohl(tvb, PTP_MM_SET_TIME_LOCALTIMESECONDS_OFFSET);

						ts.nsecs = tvb_get_ntohl(tvb, PTP_MM_SET_TIME_LOCALTIMENANOSECONDS_OFFSET);

						if(tree){
							time_ti = proto_tree_add_time(ptp_tree, hf_ptp_mm_set_time_localtime, tvb,
									PTP_MM_SET_TIME_LOCALTIME_OFFSET, 8, &ts);

							ptp_time_tree = proto_item_add_subtree(time_ti, ett_ptp_time);

							proto_tree_add_item(ptp_time_tree, hf_ptp_mm_set_time_localtimeseconds, tvb,
									PTP_MM_SET_TIME_LOCALTIMESECONDS_OFFSET, 4, FALSE);

							proto_tree_add_item(ptp_time_tree, hf_ptp_mm_set_time_localtimenanoseconds,
									tvb, PTP_MM_SET_TIME_LOCALTIMENANOSECONDS_OFFSET, 4, FALSE);
						}
						break;
					}
					default :{
						/*- don't dissect any further. */
						break;
					}
				}
				break;
			}
			default :{
				/* Not a valid MessageType - can't dissect. */
				break;
			}
		}
	}
}


/* Register the protocol with Ethereal */

void
proto_register_ptp(void)
{
	static hf_register_info hf[] = {
		/*Common Fields for all frames*/
		{ &hf_ptp_versionptp,
			{ "versionPTP",           "ptp.versionptp",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_versionnetwork,
			{ "versionNetwork",           "ptp.versionnetwork",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_subdomain,
			{ "subdomain",           "ptp.subdomain",
			FT_STRING, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_messagetype,
			{ "messageType",           "ptp.messagetype",
			FT_UINT8, BASE_DEC, VALS(ptp_messagetype_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sourcecommunicationtechnology,
			{ "sourceCommunicationTechnology",           "ptp.sourcecommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sourceuuid,
			{ "sourceUuid",           "ptp.sourceuuid",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sourceportid,
			{ "sourcePortId",           "ptp.sourceportid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sequenceid,
			{ "sequenceId",           "ptp.sequenceid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_control,
			{ "control",           "ptp.control",
			FT_UINT8, BASE_DEC, VALS(ptp_control_vals), 0x00,
			"", HFILL }
		},
		/*THE FLAGS-FIELD*/
		{ &hf_ptp_flags,
			{ "flags",           "ptp.flags",
			FT_UINT16, BASE_HEX, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_flags_li61,
			{ "PTP_LI61",           "ptp.flags.li61",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_LI61_BITMASK,
			"", HFILL }
		},
		{ &hf_ptp_flags_li59,
			{ "PTP_LI59",           "ptp.flags.li59",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_LI59_BITMASK,
			"", HFILL }
		},
		{ &hf_ptp_flags_boundary_clock,
			{ "PTP_BOUNDARY_CLOCK",           "ptp.flags.boundary_clock",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_BOUNDARY_CLOCK_BITMASK,
			"", HFILL }
		},
		{ &hf_ptp_flags_assist,
			{ "PTP_ASSIST",           "ptp.flags.assist",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_ASSIST_BITMASK,
			"", HFILL }
		},
		{ &hf_ptp_flags_ext_sync,
			{ "PTP_EXT_SYNC",           "ptp.flags.ext_sync",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_EXT_SYNC_BITMASK,
			"", HFILL }
		},
		{ &hf_ptp_flags_parent,
			{ "PTP_PARENT_STATS",           "ptp.flags.parent_stats",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_PARENT_STATS_BITMASK,
			"", HFILL }
		},
		{ &hf_ptp_flags_sync_burst,
			{ "PTP_SYNC_BURST",           "ptp.flags.sync_burst",
			FT_UINT16, BASE_DEC, VALS(ptp_bool_vals), PTP_FLAGS_SYNC_BURST_BITMASK,
			"", HFILL }
		},
		/*END OF THE FLAG-FIELD*/

		/*offsets for ptp_sync and delay_req (=sdr) messages*/
		{ &hf_ptp_origintimestamp,
			{ "originTimestamp",           "ptp.sdr.origintimestamp",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_origintimestamp_seconds,
			{ "originTimestamp (seconds)",           "ptp.sdr.origintimestamp_seconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_origintimestamp_nanoseconds,
			{ "originTimestamp (nanoseconds)",           "ptp.sdr.origintimestamp_nanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_epochnumber,
			{ "epochNumber",           "ptp.sdr.epochnumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_currentutcoffset,
			{ "currentUTCOffset",           "ptp.sdr.currentutcoffset",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmastercommunicationtechnology,
			{ "grandmasterCommunicationTechnology",           "ptp.sdr.grandmastercommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterclockuuid,
			{ "grandMasterClockUuid",           "ptp.sdr.grandmasterclockuuid",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterportid,
			{ "grandmasterPortId",           "ptp.sdr.grandmasterportid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmastersequenceid,
			{ "grandmasterSequenceId",           "ptp.sdr.grandmastersequenceid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterclockstratum,
			{ "grandmasterClockStratum",           "ptp.sdr.grandmasterclockstratum",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterclockidentifier,
			{ "grandmasterClockIdentifier",           "ptp.sdr.grandmasterclockidentifier",
			FT_STRING, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterclockvariance,
			{ "grandmasterClockVariance",           "ptp.sdr.grandmasterclockvariance",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterpreferred,
			{ "grandmasterPreferred",           "ptp.sdr.grandmasterpreferred",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_grandmasterisboundaryclock,
			{ "grandmasterIsBoundaryClock",           "ptp.sdr.grandmasterisboundaryclock",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_syncinterval,
			{ "syncInterval",           "ptp.sdr.syncinterval",
			FT_INT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_localclockvariance,
			{ "localClockVariance",           "ptp.sdr.localclockvariance",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_localstepsremoved,
			{ "localStepsRemoved",           "ptp.sdr.localstepsremoved",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_localclockstratum,
			{ "localClockStratum",           "ptp.sdr.localclockstratum",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_localclockidentifier,
			{ "localClockIdentifier",           "ptp.sdr.localclockidentifier",
			FT_STRING, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_parentcommunicationtechnology,
			{ "parentCommunicationTechnology",           "ptp.sdr.parentcommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_parentuuid,
			{ "parentUuid",           "ptp.sdr.parentuuid",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_parentportfield,
			{ "parentPortField",           "ptp.sdr.parentportfield",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_estimatedmastervariance,
			{ "estimatedMasterVariance",           "ptp.sdr.estimatedmastervariance",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_estimatedmasterdrift,
			{ "estimatedMasterDrift",           "ptp.sdr.estimatedmasterdrift",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_sdr_utcreasonable,
			{ "utcReasonable",           "ptp.sdr.utcreasonable",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*offsets for follow_up (=fu) messages*/
		{ &hf_ptp_fu_associatedsequenceid,
			{ "associatedSequenceId",           "ptp.fu.associatedsequenceid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_fu_preciseorigintimestamp,
			{ "preciseOriginTimestamp",	"ptp.fu.hf_ptp_fu_preciseorigintimestamp",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_fu_preciseorigintimestamp_seconds,
			{ "preciseOriginTimestamp (seconds)",	"ptp.fu.hf_ptp_fu_preciseorigintimestamp_seconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_fu_preciseorigintimestamp_nanoseconds,
			{ "preciseOriginTimestamp (nanoseconds)",           "ptp.fu.preciseorigintimestamp_nanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*offsets for delay_resp (=dr) messages*/
		{ &hf_ptp_dr_delayreceipttimestamp,
			{ "delayReceiptTimestamp",           "ptp.dr.delayreceipttimestamp",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_dr_delayreceipttimestamp_seconds,
			{ "delayReceiptTimestamp (Seconds)",           "ptp.dr.delayreceipttimestamp_seconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_dr_delayreceipttimestamp_nanoseconds,
			{ "delayReceiptTimestamp (nanoseconds)",           "ptp.dr.delayreceipttimestamp_nanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_dr_requestingsourcecommunicationtechnology,
			{ "requestingSourceCommunicationTechnology",	"ptp.dr.requestingsourcecommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_dr_requestingsourceuuid,
			{ "requestingSourceUuid",           "ptp.dr.requestingsourceuuid",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_dr_requestingsourceportid,
			{ "requestingSourcePortId",           "ptp.dr.requestingsourceportid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_dr_requestingsourcesequenceid,
			{ "requestingSourceSequenceId",           "ptp.dr.requestingsourcesequenceid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*offsets for management (=mm) messages*/
		{ &hf_ptp_mm_targetcommunicationtechnology,
			{ "targetCommunicationTechnology",           "ptp.mm.targetcommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_targetuuid,
			{ "targetUuid",           "ptp.mm.targetuuid",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_targetportid,
			{ "targetPortId",           "ptp.mm.targetportid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_startingboundaryhops,
			{ "startingBoundaryHops",           "ptp.mm.startingboundaryhops",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_boundaryhops,
			{ "boundaryHops",           "ptp.mm.boundaryhops",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_managementmessagekey,
			{ "managementMessageKey",           "ptp.mm.managementmessagekey",
			FT_UINT8, BASE_DEC, VALS(ptp_managementMessageKey_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parameterlength,
			{ "parameterLength",           "ptp.mm.parameterlength",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*parameterlength > 0*/
		{ &hf_ptp_mm_messageparameters,
			{ "messageParameters",           "ptp.mm.messageparameters",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_clock_identity (parameterlength = 64)*/
		{ &hf_ptp_mm_clock_identity_clockcommunicationtechnology,
			{ "clockCommunicationTechnology",           "ptp.mm.clock.identity.clockcommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_clock_identity_clockuuidfield,
			{ "clockUuidField",           "ptp.mm.clock.identity.clockuuidfield",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_clock_identity_clockportfield,
			{ "clockPortField",           "ptp.mm.clock.identity.clockportfield",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_clock_identity_manufactureridentity,
			{ "manufacturerIdentity",           "ptp.mm.clock.identity.manufactureridentity",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},

		/*ptp_mm_initialize_clock (parameterlength = 4)*/
		{ &hf_ptp_mm_initialize_clock_initialisationkey,
			{ "initialisationKey",           "ptp.mm.initialize.clock.initialisationkey",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_set_subdomain (parameterlength = 16)*/
		{ &hf_ptp_mm_set_subdomain_subdomainname,
			{ "subdomainName",           "ptp.mm.set.subdomain.subdomainname",
			FT_STRING, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_default_data_set (parameterlength = 76)*/
		{ &hf_ptp_mm_default_data_set_clockcommunicationtechnology,
			{ "clockCommunicationTechnology",           "ptp.mm.default.data.set.clockcommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_clockuuidfield,
			{ "clockUuidField",           "ptp.mm.default.data.set.clockuuidfield",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_clockportfield,
			{ "clockPortField",           "ptp.mm.default.data.set.clockportfield",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_clockstratum,
			{ "clockStratum",           "ptp.mm.default.data.set.clockstratum",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_clockidentifier,
			{ "clockIdentifier",           "ptp.mm.default.data.set.clockidentifier",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_clockvariance,
			{ "clockVariance",           "ptp.mm.default.data.set.clockvariance",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_clockfollowupcapable,
			{ "clockFollowupCapable",           "ptp.mm.default.data.set.clockfollowupcapable",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_preferred,
			{ "preferred",           "ptp.mm.default.data.set.preferred",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_initializable,
			{ "initializable",           "ptp.mm.default.data.set.initializable",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_externaltiming,
			{ "externalTiming",           "ptp.mm.default.data.set.externaltiming",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_isboundaryclock,
			{ "isBoundaryClock",           "ptp.mm.default.data.set.isboundaryclock",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_syncinterval,
			{ "syncInterval",           "ptp.mm.default.data.set.syncinterval",
			FT_INT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_subdomainname,
			{ "subDomainName",           "ptp.mm.default.data.set.subdomainname",
			FT_STRING, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_numberports,
			{ "numberPorts",           "ptp.mm.default.data.set.numberports",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_default_data_set_numberforeignrecords,
			{ "numberForeignRecords",           "ptp.mm.default.data.set.numberforeignrecords",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_update_default_data_set (parameterlength = 36)*/
		{ &hf_ptp_mm_update_default_data_set_clockstratum,
			{ "clockStratum",           "ptp.mm.update.default.data.set.clockstratum",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_default_data_set_clockidentifier,
			{ "clockIdentifier",           "ptp.mm.update.default.data.set.clockidentifier",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_default_data_set_clockvariance,
			{ "clockVariance",           "ptp.mm.update.default.data.set.clockvariance",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_default_data_set_preferred,
			{ "preferred",           "ptp.mm.update.default.data.set.preferred",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_default_data_set_syncinterval,
			{ "syncInterval",           "ptp.mm.update.default.data.set.syncinterval",
			FT_INT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_default_data_set_subdomainname,
			{ "subdomainName",           "ptp.mm.update.default.data.set.subdomainname",
			FT_STRING, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_current_data_set (parameterlength = 20)*/
		{ &hf_ptp_mm_current_data_set_stepsremoved,
			{ "stepsRemoved",           "ptp.mm.current.data.set.stepsremoved",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_current_data_set_offsetfrommaster,
			{ "offsetFromMaster",           "ptp.mm.current.data.set.offsetfrommaster",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_current_data_set_offsetfrommasterseconds,
			{ "offsetFromMasterSeconds",           "ptp.mm.current.data.set.offsetfrommasterseconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_current_data_set_offsetfrommasternanoseconds,
			{ "offsetFromMasterNanoseconds",           "ptp.mm.current.data.set.offsetfrommasternanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_current_data_set_onewaydelay,
			{ "oneWayDelay",           "ptp.mm.current.data.set.onewaydelay",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_current_data_set_onewaydelayseconds,
			{ "oneWayDelaySeconds",           "ptp.mm.current.data.set.onewaydelayseconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_current_data_set_onewaydelaynanoseconds,
			{ "oneWayDelayNanoseconds",           "ptp.mm.current.data.set.onewaydelaynanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_parent_data_set (parameterlength = 90)*/
		{ &hf_ptp_mm_parent_data_set_parentcommunicationtechnology,
			{ "parentCommunicationTechnology",           "ptp.mm.parent.data.set.parentcommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentuuid,
			{ "parentUuid",           "ptp.mm.parent.data.set.parentuuid",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentportid,
			{ "parentPortId",           "ptp.mm.parent.data.set.parentportid",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentlastsyncsequencenumber,
			{ "parentLastSyncSequenceNumber",           "ptp.mm.parent.data.set.parentlastsyncsequencenumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentfollowupcapable,
			{ "parentFollowupCapable",           "ptp.mm.parent.data.set.parentfollowupcapable",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentexternaltiming,
			{ "parentExternalTiming",           "ptp.mm.parent.data.set.parentexternaltiming",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentvariance,
			{ "parentVariance",           "ptp.mm.parent.data.set.parentvariance",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_parentstats,
			{ "parentStats",           "ptp.mm.parent.data.set.parentstats",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_observedvariance,
			{ "observedVariance",           "ptp.mm.parent.data.set.observedvariance",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_observeddrift,
			{ "observedDrift",           "ptp.mm.parent.data.set.observeddrift",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_utcreasonable,
			{ "utcReasonable",           "ptp.mm.parent.data.set.utcreasonable",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmastercommunicationtechnology,
			{ "grandmasterCommunicationTechnology",	"ptp.mm.parent.data.set.grandmastercommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmasteruuidfield,
			{ "grandmasterUuidField",           "ptp.mm.parent.data.set.grandmasteruuidfield",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmasterportidfield,
			{ "grandmasterPortIdField",           "ptp.mm.parent.data.set.grandmasterportidfield",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmasterstratum,
			{ "grandmasterStratum",           "ptp.mm.parent.data.set.grandmasterstratum",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmasteridentifier,
			{ "grandmasterIdentifier",           "ptp.mm.parent.data.set.grandmasteridentifier",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmastervariance,
			{ "grandmasterVariance",           "ptp.mm.parent.data.set.grandmastervariance",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmasterpreferred,
			{ "grandmasterPreferred",           "ptp.mm.parent.data.set.grandmasterpreferred",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmasterisboundaryclock,
			{ "grandmasterIsBoundaryClock",           "ptp.mm.parent.data.set.grandmasterisboundaryclock",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_parent_data_set_grandmastersequencenumber,
			{ "grandmasterSequenceNumber",           "ptp.mm.parent.data.set.grandmastersequencenumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_port_data_set (parameterlength = 52)*/
		{ &hf_ptp_mm_port_data_set_returnedportnumber,
			{ "returnedPortNumber",           "ptp.mm.port.data.set.returnedportnumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_portstate,
			{ "portState",           "ptp.mm.port.data.set.portstate",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_lastsynceventsequencenumber,
			{ "lastSyncEventSequenceNumber",           "ptp.mm.port.data.set.lastsynceventsequencenumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_lastgeneraleventsequencenumber,
			{ "lastGeneralEventSequenceNumber",           "ptp.mm.port.data.set.lastgeneraleventsequencenumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_portcommunicationtechnology,
			{ "portCommunicationTechnology",           "ptp.mm.port.data.set.portcommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_portuuidfield,
			{ "portUuidField",           "ptp.mm.port.data.set.portuuidfield",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_portidfield,
			{ "portIdField",           "ptp.mm.port.data.set.portidfield",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_burstenabled,
			{ "burstEnabled",           "ptp.mm.port.data.set.burstenabled",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_subdomainaddressoctets,
			{ "subdomainAddressOctets",           "ptp.mm.port.data.set.subdomainaddressoctets",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_eventportaddressoctets,
			{ "eventPortAddressOctets",           "ptp.mm.port.data.set.eventportaddressoctets",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_generalportaddressoctets,
			{ "generalPortAddressOctets",           "ptp.mm.port.data.set.generalportaddressoctets",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_subdomainaddress,
			{ "subdomainAddress",           "ptp.mm.port.data.set.subdomainaddress",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_eventportaddress,
			{ "eventPortAddress",           "ptp.mm.port.data.set.eventportaddress",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_port_data_set_generalportaddress,
			{ "generalPortAddress",           "ptp.mm.port.data.set.generalportaddress",
			FT_BYTES, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_global_time_data_set (parameterlength = 24)*/
		{ &hf_ptp_mm_global_time_data_set_localtime,
			{ "localTime",           "ptp.mm.global.time.data.set.localtime",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_global_time_data_set_localtimeseconds,
			{ "localTimeSeconds",           "ptp.mm.global.time.data.set.localtimeseconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_global_time_data_set_localtimenanoseconds,
			{ "localTimeNanoseconds",           "ptp.mm.global.time.data.set.localtimenanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_global_time_data_set_currentutcoffset,
			{ "currentUtcOffset",           "ptp.mm.global.time.data.set.currentutcoffset",
			FT_INT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_global_time_data_set_leap59,
			{ "leap59",           "ptp.mm.global.time.data.set.leap59",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_global_time_data_set_leap61,
			{ "leap61",           "ptp.mm.global.time.data.set.leap61",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_global_time_data_set_epochnumber,
			{ "epochNumber",           "ptp.mm.global.time.data.set.epochnumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_update_global_time_properties (parameterlength = 16)*/
		{ &hf_ptp_mm_update_global_time_properties_currentutcoffset,
			{ "currentUtcOffset",           "ptp.mm.update.global.time.properties.currentutcoffset",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_global_time_properties_leap59,
			{ "leap59",           "ptp.mm.update.global.time.properties.leap59",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_global_time_properties_leap61,
			{ "leap61",           "ptp.mm.update.global.time.properties.leap61",
			FT_BOOLEAN, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_update_global_time_properties_epochnumber,
			{ "epochNumber",           "ptp.mm.update.global.time.properties.epochnumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_get_foreign_data_set (parameterlength = 4)*/
		{ &hf_ptp_mm_get_foreign_data_set_recordkey,
			{ "recordKey",           "ptp.mm.get.foreign.data.set.recordkey",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_foreign_data_set (parameterlength = 28)*/
		{ &hf_ptp_mm_foreign_data_set_returnedportnumber,
			{ "returnedPortNumber",           "ptp.mm.foreign.data.set.returnedportnumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_foreign_data_set_returnedrecordnumber,
			{ "returnedRecordNumber",           "ptp.mm.foreign.data.set.returnedrecordnumber",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_foreign_data_set_foreignmastercommunicationtechnology,
			{ "foreignMasterCommunicationTechnology",
			  "ptp.mm.foreign.data.set.foreignmastercommunicationtechnology",
			FT_UINT8, BASE_DEC, VALS(ptp_communicationid_vals), 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_foreign_data_set_foreignmasteruuidfield,
			{ "foreignMasterUuidField",           "ptp.mm.foreign.data.set.foreignmasteruuidfield",
			FT_ETHER, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_foreign_data_set_foreignmasterportidfield,
			{ "foreignMasterPortIdField",           "ptp.mm.foreign.data.set.foreignmasterportidfield",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_foreign_data_set_foreignmastersyncs,
			{ "foreignMasterSyncs",           "ptp.mm.foreign.data.set.foreignmastersyncs",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_set_sync_interval (parameterlength = 4)*/
		{ &hf_ptp_mm_set_sync_interval_syncinterval,
			{ "syncInterval",           "ptp.mm.set.sync.interval.syncinterval",
			FT_UINT16, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		/*ptp_mm_set_time (parameterlength = 8)*/
		{ &hf_ptp_mm_set_time_localtime,
			{ "localtime",           "ptp.mm.set.time.localtime",
			FT_RELATIVE_TIME, BASE_NONE, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_set_time_localtimeseconds,
			{ "localtimeSeconds",           "ptp.mm.set.time.localtimeseconds",
			FT_UINT32, BASE_DEC, NULL, 0x00,
			"", HFILL }
		},
		{ &hf_ptp_mm_set_time_localtimenanoseconds,
			{ "localTimeNanoseconds",           "ptp.mm.set.time.localtimenanoseconds",
			FT_INT32, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ptp,
		&ett_ptp_flags,
		&ett_ptp_time,
		&ett_ptp_time2,
	};

/* Register the protocol name and description */
	proto_ptp = proto_register_protocol("Precision Time Protocol (IEEE1588)",
	    "PTP", "ptp");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ptp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_ptp(void)
{
	dissector_handle_t event_port_ptp_handle;
    dissector_handle_t general_port_ptp_handle;

	event_port_ptp_handle = create_dissector_handle(dissect_ptp,
	    proto_ptp);
	general_port_ptp_handle = create_dissector_handle(dissect_ptp,
	    proto_ptp);

	dissector_add("udp.port", EVENT_PORT_PTP, event_port_ptp_handle);
	dissector_add("udp.port", GENERAL_PORT_PTP, general_port_ptp_handle);
}

