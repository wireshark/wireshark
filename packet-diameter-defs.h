/*
 * Filename: packet-diameter-defs.h
 *
 * This file contains the static definitions of the Diameter base protocol
 * AVPs.  If libxml is in the LD_LIBRARY_PATH, and dictionary.xml exists,
 * then it will not be used.
 *
 * $Id: packet-diameter-defs.h,v 1.7 2002/03/05 00:21:02 guy Exp $
 * Generated: Fri Feb 23 13:04:15 2001
 */

#ifndef _PACKET_DIAMETER_DEFS_H
#define _PACKET_DIAMETER_DEFS_H


/* Type to string table */

/* Attribute to String tables */
static value_string diameter_service_type_vals[]={
   {5, "Outbound"},
   {7, "NAS-Prompt"},
   {3, "Callback-Login"},
   {6, "Administrative"},
   {1, "Login"},
   {4, "Callback-Framed"},
   {9, "Callback-NAS-Prompt"},
   {8, "Authenticate-Only"},
   {2, "Framed"},
   {0, (char *)NULL}
};

static value_string diameter_framed_protocol_vals[]={
   {1, "PPP"},
   {260, "COMB"},
   {5, "Xylogics"},
   {257, "EURAW"},
   {3, "ARA"},
   {261, "FR"},
   {2, "SLIP"},
   {258, "EUUI"},
   {4, "Gandalf"},
   {256, "MPP"},
   {255, "Ascend-ARA"},
   {259, "X25"},
   {0, (char *)NULL}
};

static value_string diameter_framed_routing_vals[]={
   {0, "None"},
   {1, "Broadcast"},
   {3, "Broadcast-Listen"},
   {2, "Listen"},
   {0, (char *)NULL}
};

static value_string diameter_framed_compression_vals[]={
   {0, "None"},
   {1, "Van-Jacobson-TCP-IP"},
   {2, "IPX-Header-Compression"},
   {0, (char *)NULL}
};

static value_string diameter_login_service_vals[]={
   {0, "Telnet"},
   {1, "Rlogin"},
   {2, "TCP-Clear"},
   {3, "PortMaster"},
   {4, "LAT"},
   {5, "X25-PAD"},
   {6, "X25-T3POS"},
   {0, (char *)NULL}
};

static value_string diameter_vendor_specific_vendors[]= {
	{0, "None"},
	{5, "ACC"},
	{9, "Cisco"},
	{42, "Sun Microsystems"},
	{166, "Shiva"},
	{307, "Livingston"},
	{429, "3Com"},
	{529, "Ascend"},
	{1584, "Bay Networks"},
	{2636, "Juniper Networks"},
        {5925, "ipUnplugged"},
	{0,NULL}
};

static value_string diameter_termination_action_vals[]={
   {0, "Default"},
   {1, "RADIUS-Request"},
   {0, (char *)NULL}
};

static value_string diameter_acct_status_type_vals[]={
   {1, "Start"},
   {2, "Stop"},
   {3, "Alive"},
   {4, "Modem-Start"},
   {5, "Modem-Stop"},
   {6, "Cancel"},
   {7, "Accounting-On"},
   {8, "Accounting-Off"},
   {0, (char *)NULL}
};

static value_string diameter_acct_authentic_vals[]={
   {1, "RADIUS"},
   {0, "None"},
   {2, "Local"},
   {0, (char *)NULL}
};

static value_string diameter_acct_terminate_cause_vals[]={
   {1, "User-Request"},
   {2, "Lost-Carrier"},
   {3, "Lost-Service"},
   {4, "Idle-Timeout"},
   {5, "Session-Timeout"},
   {6, "Admin-Reset"},
   {7, "Admin-Reboot"},
   {8, "Port-Error"},
   {9, "NAS-Error"},
   {10, "NAS-Request"},
   {11, "NAS-Reboot"},
   {12, "Port-Unneeded"},
   {13, "Port-Preempted"},
   {14, "Port-Suspended"},
   {15, "Service-Unavailable"},
   {16, "Callback"},
   {17, "User-Error"},
   {18, "Host-Request"},
   {0, (char *)NULL}
};
static value_string diameter_nas_port_type_vals[]={
   {6, "PIAFS"},
   {9, "X75"},
   {7, "HDLC-Clear-Channel"},
   {5, "Virtual"},
   {2, "ISDN-Sync"},
   {1, "Sync"},
   {0, "Async"},
   {4, "ISDN-Async-v110"},
   {3, "ISDN-Async-v120"},
   {8, "X25"},
   {0, (char *)NULL}
};

static value_string diameter_tunnel_type_vals[]= {
	{1,"PPTP"},
	{2,"L2F"},
	{3,"L2TP"},
	{4,"ATMP"},
	{5,"VTP"},
	{6,"AH"},
	{7,"IP-IP-Encap"},
	{8,"MIN-IP-IP"},
	{9,"ESP"},
	{10,"GRE"},
	{11,"DVS"},
	{12,"IP-IP"},
	{0,NULL}
};

static value_string diameter_tunnel_medium_type_vals[]= {
	{1,"IPv4"}, 
	{2,"IPv6"},
	{3,"NSAP"},
	{4,"HDLC"},
	{5,"BBN"},
	{6,"IEEE-802"},
	{7,"E-163"},
	{8,"E-164"},
	{9,"F-69"},
	{10,"X-121"},
	{11,"IPX"},
	{12,"Appletalk"},
	{13,"Decnet4"},
	{14,"Vines"},
	{15,"E-164-NSAP"},
	{0,NULL}
};

static value_string diameter_accounting_record_type_vals[]= {
	{1, "Event Record"},
	{2, "Start Record"},
	{3, "Interim Record"},
	{4, "Stop Record"},
	{0,NULL}
};

static value_string diameter_auth_request_type_vals[]= {
	{1, "Authenticate Only"},
	{2, "Authorize Only"},
	{3, "Authorize Authenticate"},
	{0,NULL}
};

static value_string diameter_auth_session_state_vals[]= {
	{0, "State Maintained"},
	{1, "No State Maintained"},
	{0,NULL}
};

static value_string diameter_re_auth_request_type_vals[]= {
	{0, "Authorize Only"},
	{1, "Authorize Authenticate"},
	{0,NULL}
};

static value_string diameter_disconnect_cause_vals[]= {
	{0, "Rebooting"},
	{1, "Busy"},
	{2, "Do Not Want To Talk To You"},
	{0,NULL}
};

static value_string diameter_redirect_host_usage_vals[]= {
	{0, "Don't Cache"},
	{1, "All Session"},
	{2, "All Realm"},
	{3, "Realm and Application"},
	{4, "All Application"},
	{5, "All Host"},
	{0,NULL}
};

static value_string diameter_session_server_failover_vals[]= {
	{0, "Refuse Service"},
	{1, "Try Again"},
	{2, "Allow Service"},
	{3, "Try Again / Allow Service"},
	{0,NULL}
};

static value_string diameter_termination_cause_vals[]= {
	{1, "Logout"},
	{2, "Service Not Provided"},
	{3, "Bad Answer"},
	{4, "Administrative"},
	{5, "Link Broken"},
	{0,NULL}
};

static value_string diameter_mip_algorithm_type[] = {
	{1, "MD5 Prefix/Suffix"},
	{2, "HMAC-MD5"},
	{3, "HMAC-SHA1"},
	{0, NULL}
};

static value_string diameter_mip_replay_type[] = {
	{1, "None"},
	{2, "Nonce"},
	{3, "Timestamp"},
	{0, NULL}
};



static struct old_avp_info old_diameter_avps[] = {
	/* Radius Attributes */
	{  1, "User-Name",                DIAMETER_UTF8STRING,   (value_string *)NULL},
	{  2, "User-Password",            DIAMETER_OCTET_STRING, (value_string *)NULL},
	{  3, "CHAP-Password",            DIAMETER_OCTET_STRING, (value_string *)NULL},
	{  4, "NAS-IP-Address",           DIAMETER_IP_ADDRESS,   (value_string *)NULL},
	{  5, "NAS-Port",                 DIAMETER_INTEGER32,    (value_string *)NULL},
	{  6, "Service-Type",             DIAMETER_ENUMERATED,   diameter_service_type_vals},
	{  7, "Framed-Protocol",          DIAMETER_ENUMERATED,   diameter_framed_protocol_vals},
	{  8, "Framed-IP-Address",        DIAMETER_IP_ADDRESS,   (value_string *)NULL},
	{  9, "Framed-IP-Netmask",        DIAMETER_IP_ADDRESS,   (value_string *)NULL},
	{ 10, "Framed-Routing",           DIAMETER_ENUMERATED,   diameter_framed_routing_vals},
	{ 11, "Filter-Id",                DIAMETER_UTF8STRING,   (value_string *)NULL},
	{ 12, "Framed-MTU",               DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 13, "Framed-Compression",       DIAMETER_ENUMERATED,   diameter_framed_compression_vals},
	{ 14, "Login-IP-Host",            DIAMETER_IP_ADDRESS,   (value_string *)NULL},
	{ 15, "Login-Service",            DIAMETER_ENUMERATED,   diameter_login_service_vals},
	{ 16, "Login-TCP-Port",           DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 17, "Old-Password",             DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 18, "Reply-Message",            DIAMETER_UTF8STRING,   (value_string *)NULL},
	{ 19, "Callback-Number",          DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 20, "Callback-Id",              DIAMETER_OCTET_STRING, (value_string *)NULL},
	/* 21 is Unassigned */
	{ 22, "Framed-Route",             DIAMETER_UTF8STRING,   (value_string *)NULL},
	{ 23, "Framed-IPX-Network",       DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 24, "State",                    DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 25, "Class",                    DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 26, "Vendor-Specific",          DIAMETER_ENUMERATED,   diameter_vendor_specific_vendors},
	{ 27, "Session-Timeout",          DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 28, "Idle-Timeout",             DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 29, "Termination-Action",       DIAMETER_ENUMERATED,   diameter_termination_action_vals},
	{ 30, "Called-Station-Id",        DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 31, "Calling-Station-Id",       DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 32, "NAS-Identifier",           DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 33, "Proxy-State",              DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 34, "Login-LAT-Service",        DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 35, "Login-LAT-Node",           DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 36, "Login-LAT-Group",          DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 37, "Framed-AppleTalk-Link",    DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 38, "Framed-AppleTalk-Network", DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 39, "Framed-AppleTalk-Zone",    DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 40, "Acct-Status-Type",         DIAMETER_ENUMERATED,   diameter_acct_status_type_vals},
	{ 41, "Acct-Delay-Time",          DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 42, "Acct-Input-Octets",        DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 43, "Acct-Output-Octets",       DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 44, "Acct-Session-Id",          DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 45, "Acct-Authentic",           DIAMETER_ENUMERATED,   diameter_acct_authentic_vals},
	{ 46, "Acct-Session-Time",        DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 47, "Acct-Input-Packets",       DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 48, "Acct-Output-Packets",      DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 49, "Acct-Terminate-Cause",     DIAMETER_ENUMERATED,   diameter_acct_terminate_cause_vals},
	{ 50, "Acct-Multi-Session-Id",    DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 51, "Acct-Link-Count",          DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 60, "CHAP-Challenge",           DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 61, "NAS-Port-Type",            DIAMETER_ENUMERATED,   diameter_nas_port_type_vals},
	{ 62, "Port-Limit",               DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 63, "Login-LAT-Port",           DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 64, "Tunnel-Type",              DIAMETER_ENUMERATED,   diameter_tunnel_type_vals},
	{ 65, "Tunnel-Medium-Type",       DIAMETER_ENUMERATED,   diameter_tunnel_medium_type_vals},
	{ 66, "Tunnel-Client-Endpoint",   DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 67, "Tunnel-Server-Endpoint",   DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 68, "Tunnel-Connection-ID",     DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 69, "Tunnel-Password",          DIAMETER_OCTET_STRING, (value_string *)NULL},
    { 82, "Tunnel-Assignment-Id",     DIAMETER_OCTET_STRING, (value_string *)NULL},

	/* Diameter AVPs */
    { 482, "Accounting-Interim-Interval", DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 485, "Accounting-Record-Number",    DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 480, "Accounting-Record-Type",      DIAMETER_ENUMERATED,  diameter_accounting_record_type_vals},
    { 259, "Acct-Application-Id",         DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 275, "Alternate-Peer",              DIAMETER_IDENTITY,    (value_string *)NULL},
    { 258, "Auth-Aplication-Id",          DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 274, "Auth-Request-Type",           DIAMETER_ENUMERATED,  diameter_auth_request_type_vals},
    { 291, "Authorization-Lifetime",      DIAMETER_INTEGER32,   (value_string *)NULL},
    { 276, "Auth-Grace-Period",           DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 277, "Auth-Session-State",          DIAMETER_ENUMERATED,  diameter_auth_session_state_vals},
    { 285, "Re-Auth-Request-Type",        DIAMETER_ENUMERATED,  diameter_re_auth_request_type_vals},
    { 293, "Destination-Host",            DIAMETER_IDENTITY,    (value_string *)NULL},
    { 283, "Desintation-Realm",           DIAMETER_UTF8STRING,  (value_string *)NULL},
    { 273, "Disconnect-Cause",            DIAMETER_ENUMERATED,  diameter_disconnect_cause_vals},
    { 281, "Error-Message",               DIAMETER_UTF8STRING,  (value_string *)NULL},
    { 294, "Error-Reporting-Host",        DIAMETER_IDENTITY,    (value_string *)NULL},
    { 279, "Failed-AVP",                  DIAMETER_OCTET_STRING,(value_string *)NULL},
    { 267, "Firmware-Revision",           DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 257, "Host-IP-Address",             DIAMETER_IP_ADDRESS,  (value_string *)NULL},
    { 272, "Multi-Round-Time-Out",        DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 264, "Origin-Host",                 DIAMETER_IDENTITY,    (value_string *)NULL},
    { 296, "Origin-Realm",                DIAMETER_UTF8STRING,  (value_string *)NULL},
    { 278, "Origin-State-Id",             DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 269, "Product-Name",                DIAMETER_UTF8STRING,  (value_string *)NULL},
    { 280, "Proxy-Host",                  DIAMETER_IDENTITY,    (value_string *)NULL},
    { 284, "Proxy-Info",                  DIAMETER_GROUPED,     (value_string *)NULL},
    { 292, "Redirect-Host",               DIAMETER_IDENTITY,    (value_string *)NULL},
    { 261, "Redirect-Host-Usage",         DIAMETER_ENUMERATED,  diameter_redirect_host_usage_vals}, 
    { 262, "Redirect-Max-Cache-Time",     DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 268, "Result-Code",                 DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 282, "Route-Record",                DIAMETER_IDENTITY,    (value_string *)NULL},
    { 263, "Session-Id",                  DIAMETER_UTF8STRING,  (value_string *)NULL},
    { 270, "Session-Binding",             DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 271, "Session-Server-Failover",     DIAMETER_ENUMERATED,  diameter_session_server_failover_vals},
    { 286, "Source-Route",                DIAMETER_IDENTITY,    (value_string *)NULL},
    { 265, "Supported-Vendor-Id",         DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 295, "Termination-Cause",           DIAMETER_ENUMERATED,  diameter_termination_cause_vals},
    { 266, "Vendor-Id",                   DIAMETER_ENUMERATED,  diameter_vendor_specific_vendors},
    { 260, "Vendor-Specific-Application-Id", DIAMETER_GROUPED, (value_string *)NULL},
/* Diameter Mobile IP AVPs */
    { 318, "MIP-FA-to-HA-SPI",            DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 319, "MIP-FA-to-MN-SPI",            DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 320, "MIP-Reg-Request",             DIAMETER_MIP_REG_REQ,    (value_string *)NULL},
    { 321, "MIP-Reg-Reply",               DIAMETER_OCTET_STRING,   (value_string *)NULL},
    { 322, "MIP-MN-AAA-Auth",             DIAMETER_GROUPED,        (value_string *)NULL},
    { 325, "MIP-MN-to-FA-KEY",            DIAMETER_GROUPED,        (value_string *)NULL},
    { 326, "MIP-FA-to-MN-KEY",            DIAMETER_GROUPED,        (value_string *)NULL},
    { 328, "MIP-FA-to-HA-KEY",            DIAMETER_GROUPED,        (value_string *)NULL},
    { 329, "MIP-HA-to-FA-KEY",            DIAMETER_GROUPED,        (value_string *)NULL},
    { 330, "MIP-Foreign-Agent-Host",      DIAMETER_IDENTITY,       (value_string *)NULL},
    { 331, "MIP-MN-to-HA-KEY",            DIAMETER_GROUPED,        (value_string *)NULL},
    { 333, "MIP-Mobile-Node-Address",     DIAMETER_IP_ADDRESS,     (value_string *)NULL},
    { 334, "MIP-Home-Agent-Address",      DIAMETER_IP_ADDRESS,     (value_string *)NULL},
    { 335, "MIP-Key-Material",            DIAMETER_OCTET_STRING,   (value_string *)NULL},
    { 337, "MIP-Feature-Vector",          DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 338, "MIP-Auth-Input-Data-Length",  DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 339, "MIP-Authenticator-Length",    DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 340, "MIP-Authenticator-Offset",    DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 341, "MIP-MN-AAA-SPI",              DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 342, "MIP-PEER-SPI",                DIAMETER_UNSIGNED32,     (value_string *)NULL},
    { 343, "MIP-Session-Key",             DIAMETER_OCTET_STRING,   (value_string *)NULL},
    { 344, "MIP-FA-Challenge",            DIAMETER_OCTET_STRING,   (value_string *)NULL},
    { 345, "MIP-Algorithm-Type",          DIAMETER_ENUMERATED,     diameter_mip_algorithm_type},
    { 346, "MIP-Algorithm-Type",          DIAMETER_ENUMERATED,     diameter_mip_replay_type},
    { 347, "MIP-Filter-Rule",             DIAMETER_IP_FILTER_RULE, (value_string *)NULL},
    { 398, "MIP-Key-Lifetime",            DIAMETER_UNSIGNED32,    (value_string *)NULL},
{0, (char *)NULL, 0, (value_string*)NULL}
};



static value_string diameter_command_code_vals[] = {

	/* Base Protocol */
	{274, "Abort-Session"},
	{271, "Accounting"},
	{257, "Capabilities-Exchange"},
	{280, "Device-Watchdog"},
	{282, "Disconnect-Peer"},
	{258, "Re-Auth"},
	{275, "Session-Termination"},
	/* Mip Protocol */
	{262, "Home-Agent-MIP"},
	{260, "AA-Mobile-Node"},
	/* Nasreq Protocol */
	{265, "AA"},
	{268, "Diameter-EAP"},
	{0, (char *)NULL}
};




#endif /* _PACKET_DIAMETER_H */
