/*
 * Filename: packet-diameter-defs.h
 *
 * This file contains the static definitions of the Diameter base protocol
 * AVPs.  If libxml is in the LD_LIBRARY_PATH, and dictionary.xml exists,
 * then it will not be used.
 *
 * $Id$
 * Generated: Fri Feb 23 13:04:15 2001
 * References:
 * http://www.ietf.org/rfc/rfc3588.txt
 * http://www.iana.org/assignments/radius-types
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-cc-06.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-nasreq-17.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-mobileip-20.txt
 * http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-sip-app-03.txt
 * http://www.ietf.org/html.charters/aaa-charter.html
 * http://www.iana.org/assignments/aaa-parameters
 */

#ifndef _PACKET_DIAMETER_DEFS_H
#define _PACKET_DIAMETER_DEFS_H


/* Type to string table */

/* Attribute to String tables */
static const value_string diameter_service_type_vals[]={
   {1, "Login"},
   {2, "Framed"},
   {3, "Callback-Login"},
   {4, "Callback-Framed"},
   {5, "Outbound"},
   {6, "Administrative"},
   {7, "NAS-Prompt"},
   {8, "Authenticate-Only"},
   {9, "Callback-NAS-Prompt"},
   {10,"Call Check"},
   {11,"Callback Administrative"},
   {12,"Voice"},					/*[Chiba]				*/
   {13,"Fax"},						/*[Chiba]				*/
   {14,"Modem Relay"},				/*[Chiba]				*/
   {15,"IAPP-Register"},			/*[IEEE 802.11f][Kerry]	*/
   {16,"IAPP-AP-Check"},			/*[IEEE 802.11f][Kerry]	*/
   {17,"Authorize Only"},			/*[RFC3576]				*/
   {0, (char *)NULL}
};

static const value_string diameter_framed_protocol_vals[]={
   {1,	"PPP"},
   {2,	"SLIP"},
   {3,	"AppleTalk Remote Access Protocol (ARAP)"},
   {4,	"Gandalf proprietary SingleLink/MultiLink protocol"},
   {5,	"Xylogics proprietary IPX/SLIP"},
   {6,	"X.75 Synchronous"},
   {7,	"GPRS PDP Context"},
   {261,"FR"},
   {258,"EUUI"},
   {255,"Ascend-ARA"},
   {259,"X25"},
   {256,"MPP"},
   {257,"EURAW"},
   {260,"COMB"},
   {0, (char *)NULL}
};

static const value_string diameter_framed_routing_vals[]={
   {0, "None"},
   {1, "Send routing packets"},
   {2, "Listen for routing packets"},
   {3, "Send and Listen"},
   {0, (char *)NULL}
};

static const value_string diameter_framed_compression_vals[]={
   {0,	"None"},
   {1,	"VJ TCP/IP header compression"},
   {2,	"IPX-Header-Compression"},
   {3,	"Stac-LZS compression"},
   {0, (char *)NULL}
};

static const value_string diameter_login_service_vals[]={
   {0, "Telnet"},
   {1, "Rlogin"},
   {2, "TCP-Clear"},
   {3, "PortMaster"},
   {4, "LAT"},
   {5, "X25-PAD"},
   {6, "X25-T3POS"},
   {7, "(unassigned)"},
   {8, "TCP Clear Quiet (suppresses any NAS-generated connect string)"},
   {0, (char *)NULL}
};

static const value_string diameter_termination_action_vals[]={
   {0, "Default"},
   {1, "RADIUS-Request"},
   {0, (char *)NULL}
};

static const value_string diameter_acct_status_type_vals[]={
   {1,	"Start"},
   {2,	"Stop"},
   {3,	"Alive"},
   {4,	"Modem-Start"},
   {5,	"Modem-Stop"},
   {6,	"Cancel"},
   {7,	"Accounting-On"},
   {8,	"Accounting-Off"},
   {9,	"Tunnel-Start"},		/*[RFC 2867]*/
   {10,	"Tunnel-Stop"},			/*[RFC 2867]*/
   {11,	"Tunnel-Reject"},		/*[RFC 2867]*/
   {12,	"Tunnel-Link-Start"},	/*[RFC 2867]*/
   {13,	"Tunnel-Link-Stop"},	/*[RFC 2867]*/
   {14,	"Tunnel-Link-Reject"},	/*[RFC 2867]*/
   {15,	"Failed"},				/*[RFC 2866]*/


   {0, (char *)NULL}
};

static const value_string diameter_acct_authentic_vals[]={
   {1, "RADIUS"},
   {0, "None"},
   {2, "Local"},
   {3, "Remote"},
   {4, "Diameter"},
   {0, (char *)NULL}
};

static const value_string diameter_acct_terminate_cause_vals[]={
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
   {19,	"Supplicant Restart"},					/*[RFC3580]*/
   {20,	"Reauthentication Failure"},			/*[RFC3580]*/
   {21,	"Port Reinitialized"},					/*[RFC3580]*/
   {22,	"Port Administratively Disabled"},		/*[RFC3580]*/
   {0, (char *)NULL}
};
static const value_string diameter_nas_port_type_vals[]={
   {0, "Async"},
   {1, "Sync"},
   {2, "ISDN Sync"},
   {3, "ISDN Async V.120"},
   {4, "ISDN Async V.110"},
   {5, "Virtual"},
   {6, "PIAFS"},
   {7, "HDLC-Clear-Channel"},
   {8, "X.25"},
   {9, "X.75"},
   {10,"G.3 Fax"},
   {11,"SDSL - Symmetric DSL"},
   {12,"ADSL-CAP - Asymmetric DSL, Carrierless Amplitude Phase Modulation"},
   {13,"ADSL-DMT - Asymmetric DSL, Discrete Multi-Tone"},
   {14,"IDSL - ISDN Digital Subscriber Line"},
   {15,"Ethernet"},
   {16,"xDSL - Digital Subscriber Line of unknown type"},
   {17,"Cable"},
   {18,"Wireless - Other"},
   {19,"Wireless - IEEE 802.11"},
   {20,"Token-Ring"},                                 
   {21,"FDDI"},                                       
   {22,"Wireless - CDMA2000"},                           
   {23,"Wireless - UMTS"},                               
   {24,"Wireless - 1X-EV"},                              
   {25,"IAPP"},
   {26,"FTTP - Fiber to the Premises"},
   {0, (char *)NULL}
};

static const value_string diameter_tunnel_type_vals[]= {
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
	{13,"VLAN"},
	{0,NULL}
};

static const value_string diameter_tunnel_medium_type_vals[]= {
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

static const value_string diameter_avp_data_addrfamily_vals[]= {
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
	{16,"DNS"},
	{17,"DistinguishedName"},
	{18,"AS"},
	{19,"XTPoIPv4"},
	{20,"XTPoIPv6"},
	{21,"XTPNative"},
	{22,"FibrePortName"},
	{23,"FibreNodeName"},
	{24,"GWID"},
	{0,NULL}
};
/*
 *Values for RADIUS Attribute 101, Error-Cause Attribute [RFC3576]:
 */
static const value_string diameter_error_cause_attribute_vals[]= {
	{201,"Residual Session Context Removed"},
	{202,"Invalid EAP Packet (Ignored)"},
	{401,"Unsupported Attribute"},
	{402,"Missing Attribute"},
	{403,"NAS Identification Mismatch"},
	{404,"Invalid Request"},
	{405,"Unsupported Service"},
	{406,"Unsupported Extension"},
	{501,"Administratively Prohibited"},
	{502,"Request Not Routable (Proxy)"},
	{503,"Session Context Not Found"},
	{504,"Session Context Not Removable"},
	{505,"Other Proxy Processing Error"},
	{506,"Resources Unavailable"},
	{507,"Request Initiated"},
	{0,NULL}
};

static const value_string diameter_accounting_record_type_vals[]= {
	{1, "Event Record"},
	{2, "Start Record"},
	{3, "Interim Record"},
	{4, "Stop Record"},
	{0,NULL}
};

static const value_string diameter_auth_request_type_vals[]= {
	{1, "Authenticate Only"},
	{2, "Authorize Only"},
	{3, "Authorize Authenticate"},
	{0,NULL}
};

static const value_string diameter_auth_session_state_vals[]= {
	{0, "State Maintained"},
	{1, "No State Maintained"},
	{0,NULL}
};

static const value_string diameter_re_auth_request_type_vals[]= {
	{0, "Authorize Only"},
	{1, "Authorize Authenticate"},
	{0,NULL}
};

static const value_string diameter_disconnect_cause_vals[]= {
	{0, "Rebooting"},
	{1, "Busy"},
	{2, "Do Not Want To Talk To You"},
	{0,NULL}
};

static const value_string diameter_redirect_host_usage_vals[]= {
	{0, "Don't Cache"},
	{1, "All Session"},
	{2, "All Realm"},
	{3, "Realm and Application"},
	{4, "All Application"},
	{5, "All Host"},
	{0,NULL}
};

static const value_string diameter_session_server_failover_vals[]= {
	{0, "Refuse Service"},
	{1, "Try Again"},
	{2, "Allow Service"},
	{3, "Try Again / Allow Service"},
	{0,NULL}
};

static const value_string diameter_termination_cause_vals[]= {
	{1, "Logout"},
	{2, "Service Not Provided"},
	{3, "Bad Answer"},
	{4, "Administrative"},
	{5, "Link Broken"},
	{0,NULL}
};

static const value_string diameter_mip_algorithm_type[] = {
	{1, "MD5 Prefix/Suffix"},
	{2, "HMAC-MD5"},
	{3, "HMAC-SHA1"},
	{0, NULL}
};

static const value_string diameter_mip_replay_type[] = {
	{1, "None"},
	{2, "Nonce"},
	{3, "Timestamp"},
	{0, NULL}
};

static const value_string diameter_application_id_vals[] = {
	{0, "Diameter Common Messages"},
	{1, "Diameter NASREQ Application"},
	{2, "Diameter Mobile IPv4 Application"},
	{3, "Diameter Base Accounting"},
	{4, "Diameter Credit-Control Application"},	/* draft-ietf-aaa-diameter-cc-06 */
	{16777216, "3GPP Cx"},		/* 3GPP TS 29.228 and 29.229 */
	{16777217, "3GPP Sh"},		/* 3GPP TS 29.328 and 29.329 */
	{16777218, "3GPP Rf/Ro"},	/* 3GPP TS 32.225 */
	{4294967295U, "Relay Application"},
	
	{0, NULL}

};
/* Diameter Session Initiation Protocol (SIP) Application value strings */
/* Remove comment when IANA assigned values are avalable 
static const value_string SIP_user_data_request_type[] = {
	{0, "COMPLETE_PROFILE"},
	{1, "REGISTERED_PROFILE"},
	{2, "UNREGISTERED_PROFILE"},
	{0, NULL}

};
static const value_string SIP_user_authorization_type[] = {
	{0, "REGISTRATION"},
	{1, "DE_REGISTRATION"},
	{2, "REGISTRATION_AND_CAPABILITIES"},
	{0, NULL}

};

static const value_string SIP_reason_code_vals[] = {
	{0, "PERMANENT_TERMINATION"},
	{1, "NEW_SIP_SERVER_ASSIGNED "},
	{2, "SIP_SERVER_CHANGE"},
	{3, "REMOVE_SIP_SERVER"},
	{0, NULL}

};
static const value_string SIP_user_data_already_available_vals[] = {
	{0, "USER_DATA_NOT_AVAILABLE"},
	{1, "USER_DATA_ALREADY_AVAILABLE"},
	{0, NULL}

};

static const value_string SIP_server_assignment_type[] ={
	{0, "NO_ASSIGNMENT"},
	{1, "REGISTRATION"},
	{2, "RE_REGISTRATION"},
	{3, "UNREGISTERED_USER"},
	{4, "TIMEOUT_DEREGISTRATION"},
	{5, "USER_DEREGISTRATION"},
	{6, "TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME"},
	{7, "USER_DEREGISTRATION_STORE_SERVER_NAME"},
	{8, "ADMINISTRATIVE_DEREGISTRATION"},
	{9, "AUTHENTICATION_FAILURE"},
	{10, "AUTHENTICATION_TIMEOUT"},
	{11, "DEREGISTRATION_TOO_MUCH_DATA"},
	{0, NULL}

};

 Remove comment when IANA assigned values are avalable */ 

/*
 * The Result-Code data field contains an IANA-managed 32-bit address
 * space representing errors (see Section 11.4(RFC3588)).  Diameter provides the
 * following classes of errors, all identified by the thousands digit in
 * the decimal notation:
 *
 *    -  1xxx (Informational)
 *    -  2xxx (Success)
 *    -  3xxx (Protocol Errors)
 *    -  4xxx (Transient Failures)
 *    -  5xxx (Permanent Failure)
 */

static const value_string diameter_result_code_vals[] = {
	/* Informational
	 * Errors that fall within this category are used to inform the
	 * requester that a request could not be satisfied, and additional
	 * action is required on its part before access is granted.
	 */
	{1001, "DIAMETER_MULTI_ROUND_AUTH "},
	/* Errors that fall within the Success category are used to inform a peer 
	 *that a request has been successfully completed
	 */
	{2001, "DIAMETER_SUCCESS"},
	{2002, "DIAMETER_LIMITED_SUCCESS"},
	/* draft-ietf-aaa-diameter-sip-app-01.txt numbers not yet allocated by IANA 
	{2xx1, "DIAMETER_FIRST_REGISTRATION"},
	{2xx2, "DIAMETER_SUBSEQUENT_REGISTRATION "},
	{2xx3, "DIAMETER_UNREGISTERED_SERVICE "},
	{2xx4, "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED "},
	{2xx5, "DIAMETER_SERVER_SELECTION"},
	{2xx6, "DIAMETER_SUCCESS_AUTH_SENT_SERVER_NOT_STORED"},
	{2xx7, "DIAMETER_SUCCESS_SERVER_NOT_STORED"},
	
	  */

	/* Protocol errors */
	{3001, "DIAMETER_COMMAND_UNSUPPORTED"},
	{3002, "DIAMETER_UNABLE_TO_DELIVER"},
	{3003, "DIAMETER_REALM_NOT_SERVED"},
	{3004, "DIAMETER_TOO_BUSY"},
	{3005, "DIAMETER_LOOP_DETECTED"},
	{3006, "DIAMETER_REDIRECT_INDICATION"},
	{3007, "DIAMETER_APPLICATION_UNSUPPORTED"},
	{3008, "DIAMETER_INVALID_HDR_BITS"},
	{3009, "DIAMETER_INVALID_AVP_BITS"},
	{3010, "DIAMETER_UNKNOWN_PEER"},
	/* Transient Failures */
	{4001, "DIAMETER_AUTHENTICATION_REJECTED"},
	{4002, "DIAMETER_OUT_OF_SPACE"},
	{4003, "ELECTION_LOST"},
	/* draft-ietf-aaa-diameter-mobileip-16 */
	{4005, "DIAMETER_ERROR_MIP_REPLY_FAILURE"},
	{4006, "DIAMETER_ERROR_HA_NOT_AVAILABLE"},
	{4007, "DIAMETER_ERROR_BAD_KEY"},
	{4008, "DIAMETER_ERROR_MIP_FILTER_NOT_SUPPORTED"},
	/* draft-ietf-aaa-diameter-cc-03.txt */
	{4010, "DIAMETER_END_USER_SERVICE_DENIED"},
	{4011, "DIAMETER_CREDIT_CONTROL_NOT_APPLICABLE"},
	{4012, "DIAMETER_CREDIT_LIMIT_REACHED"},
	/* draft-ietf-aaa-diameter-sip-app-01.txt numbers not yet allocated by IANA 
	 
	{4xx1, "DIAMETER_USER_NAME_REQUIRED"},
	*/
	/* Permanent Failures */
	{5001, "DIAMETER_AVP_UNSUPPORTED"}, 
	{5002, "DIAMETER_UNKNOWN_SESSION_ID"}, 
	{5003, "DIAMETER_AUTHORIZATION_REJECTED"}, 
	{5004, "DIAMETER_INVALID_AVP_VALUE"}, 
	{5005, "DIAMETER_MISSING_AVP"}, 
	{5006, "DIAMETER_RESOURCES_EXCEEDED"}, 
	{5007, "DIAMETER_CONTRADICTING_AVPS"}, 
	{5008, "DIAMETER_AVP_NOT_ALLOWED"}, 
	{5009, "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES"}, 
	{5010, "DIAMETER_NO_COMMON_APPLICATION"}, 
	{5011, "DIAMETER_UNSUPPORTED_VERSION"}, 
	{5012, "DIAMETER_UNABLE_TO_COMPLY"}, 
	{5013, "DIAMETER_INVALID_BIT_IN_HEADER"}, 
	{5014, "DIAMETER_INVALID_AVP_LENGTH"}, 
	{5015, "DIAMETER_INVALID_MESSAGE_LENGTH"}, 
	{5016, "DIAMETER_INVALID_AVP_BIT_COMBO"}, 
	{5017, "DIAMETER_NO_COMMON_SECURITY"}, 
	{5018, "DIAMETER_AVP_NOT_ALLOWED"}, 
	{5019, "DIAMETER_AVP_OCCURS_TOO_MANY_TIMES"}, 
	/* draft-ietf-aaa-diameter-mobileip-16 */
	{5024, "DIAMETER_ERROR_NO_FOREIGN_HA_SERVICE"}, 
	{5025, "DIAMETER_ERROR_END_TO_END_MIP_KEY_ENCRYPTION"}, 
	/* draft-ietf-aaa-diameter-cc-03.txt */
	{5030, "DIAMETER_USER_UNKNOWN"},
	{5031, "DIAMETER_RATING_FAILED"},
	{5032, "DIAMETER_CREDIT_LIMIT_REACHED"},

	/* draft-ietf-aaa-diameter-sip-app-01.txt numbers not yet allocated by IANA 

	{5xx1, "DIAMETER_ERROR_USER_UNKNOWN"}, 
	{5xx2, "DIAMETER_ERROR_IDENTITIES_DONT_MATCH"}, 
	{5xx3, "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED"}, 
	{5xx4, "DIAMETER_ERROR_ROAMING_NOT_ALLOWED"}, 
	{5xx5, "DIAMETER_ERROR_IDENTITY_ALREADY_REGISTERED"}, 
	{5xx6, "DIAMETER_ERROR_USER_UNKNOWN"}, 
	{5xx7, "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE"}, 
	{5xx8, "DIAMETER_ERROR_TOO_MUCH_DATA"}, 
	{5xx9, "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA"},
	*/
	{0, NULL}
};

static const value_string diameter_exp_result_code_vals[] = {
        {2001, "DIAMETER_FIRST_REGISTRATION"},
        {2002, "DIAMETER_SUBSEQUENT_REGISTRATION"},
        {2003, "DIAMETER_UNREGISTERED_SERVICE"},
        {2004, "DIAMETER_SUCCESS_SERVER_NAME_NOT_STORED"},
        {2005, "DIAMETER_SERVER_SELECTION"},
        {5001, "DIAMETER_ERROR_USER_UNKNOWN"},
        {5002, "DIAMETER_ERROR_IDENTITIES_DONT_MATCH"},
        {5003, "DIAMETER_ERROR_IDENTITY_NOT_REGISTERED"},
        {5004, "DIAMETER_ERROR_ROAMING_NOT_ALLOWED"},
        {5005, "DIAMETER_ERROR_ROAMING_IDENTITY_ALREADY_REGISTERED"},
        {5006, "DIAMETER_ERROR_ROAMING_AUTH_SCHEME_NOT_SUPPORTED"},
        {5007, "DIAMETER_ERROR_IN_ASSIGNMENT_TYPE"},
        {5008, "DIAMETER_ERROR_TOO_MUCH_DATA"},
        {5009, "DIAMETER_ERROR_NOT_SUPPORTED_USER_DATA"},

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
	{ 26, "Vendor-Specific",          DIAMETER_ENUMERATED,   sminmpec_values},
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
	{ 42, "Acct-Input-Octets",				DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 43, "Acct-Output-Octets",				DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 44, "Acct-Session-Id",				DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 45, "Acct-Authentic",					DIAMETER_ENUMERATED,   diameter_acct_authentic_vals},
	{ 46, "Acct-Session-Time",				DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 47, "Acct-Input-Packets",				DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 48, "Acct-Output-Packets",			DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 49, "Acct-Terminate-Cause",			DIAMETER_ENUMERATED,   diameter_acct_terminate_cause_vals},
	{ 50, "Acct-Multi-Session-Id",			DIAMETER_OCTET_STRING, (value_string *)NULL},
	{ 51, "Acct-Link-Count",				DIAMETER_INTEGER32,    (value_string *)NULL},
	{ 52, "Acct-Input-Gigawords",			DIAMETER_INTEGER32,		(value_string *)NULL},/*[RFC2869]*/
	{ 53, "Acct-Output-Gigawords",			DIAMETER_INTEGER32,		(value_string *)NULL},/*[RFC2869]*/
	{ 54, "(unassigned)",					DIAMETER_INTEGER32,		(value_string *)NULL},
	{ 55, "Event-Timestamp",				DIAMETER_TIME,			(value_string *)NULL},/*[RFC2869]*/
	/*
	 * 56-59	(unassigned)
	 *
	 */
	{ 60,	"CHAP-Challenge",				DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 61,	"NAS-Port-Type",				DIAMETER_ENUMERATED,	diameter_nas_port_type_vals},
	{ 62,	"Port-Limit",					DIAMETER_INTEGER32,		(value_string *)NULL},
	{ 63,	"Login-LAT-Port",				DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 64,	"Tunnel-Type",					DIAMETER_ENUMERATED,	diameter_tunnel_type_vals},
	{ 65,	"Tunnel-Medium-Type",			DIAMETER_ENUMERATED,	diameter_tunnel_medium_type_vals},
	{ 66,	"Tunnel-Client-Endpoint",		DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 67,	"Tunnel-Server-Endpoint",		DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 68,	"Tunnel-Connection-ID",			DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 69,	"Tunnel-Password",				DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 70,	"ARAP-Password",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 71,	"ARAP-Features",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 72,	"ARAP-Zone-Access",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 73,	"ARAP-Security",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 74,	"ARAP-Security-Data",			DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 75,	"Password-Retry",				DIAMETER_INTEGER32,		(value_string *)NULL},/*[RFC2869]*/
	{ 76,	"Prompt",						DIAMETER_ENUMERATED,	(value_string *)NULL},/*[RFC2869]*/
	{ 77,	"Connect-Info",					DIAMETER_UTF8STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 78,	"Configuration-Token",			DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 79,	"EAP-Message",					DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 80,	"Message-Authenticator",		DIAMETER_INTEGER64,		(value_string *)NULL},/*[RFC2869]*/
	{ 81,	"Tunnel-Private-Group-ID",		DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2868]*/
    { 82,	"Tunnel-Assignment-Id",			DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 83,	"Tunnel-Preference",			DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2868]*/
	{ 84,	"ARAP-Challenge-Response",		DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 85,	"Acct-Interim-Interval",		DIAMETER_INTEGER32,		(value_string *)NULL},/*[RFC2869]*/
	{ 86,	"Acct-Tunnel-Packets-Lost",		DIAMETER_INTEGER32,		(value_string *)NULL},/*[RFC2867]*/
	{ 87,	"NAS-Port-Id",					DIAMETER_UTF8STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 88,	"Framed-Pool",					DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2869]*/
	{ 89,	"(unassigned)",					DIAMETER_OCTET_STRING,	(value_string *)NULL},
	{ 90,	"Tunnel-Client-Auth-ID",		DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2868]*/
	{ 91,	"Tunnel-Server-Auth-ID",		DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC2868]*/
	/*
	 * 92-93      (Unassigned)
	 */
	{ 94,	"Originating-Line-Info",		DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[Trifunovic]*/ 
	{ 95,	"NAS-IPv6-Address",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC3162]*/
	{ 96,	"Framed-Interface-Id",			DIAMETER_INTEGER64,		(value_string *)NULL},/*[RFC3162]*/
	{ 97,	"Framed-IPv6-Prefix",			DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC3162]*/
	{ 98,	"Login-IPv6-Host",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC3162]*/
	{ 99,	"Framed-IPv6-Route",			DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC3162]*/
	{ 100,	"Framed-IPv6-Pool",				DIAMETER_OCTET_STRING,	(value_string *)NULL},/*[RFC3162]*/
	{ 101,	"Error-Cause Attribute",		DIAMETER_ENUMERATED,	diameter_error_cause_attribute_vals},/*[RFC3576]*/ 
/*
   192-223	Experimental Use			 [RFC2058]
   224-240	Implementation Specific			 [RFC2058]
   241-255	Reserved				 [RFC2058]   
*/
	/* Diameter AVPs */
    { 482, "Accounting-Interim-Interval", DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 483, "Accounting-Realtime-Required",DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 485, "Accounting-Record-Number",    DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 480, "Accounting-Record-Type",      DIAMETER_ENUMERATED,  diameter_accounting_record_type_vals},
    { 287, "Accounting-Sub-Session-Id",   DIAMETER_UNSIGNED64,  (value_string *)NULL},
    { 259, "Acct-Application-Id",         DIAMETER_UNSIGNED32,  diameter_application_id_vals},
    { 275, "Alternate-Peer",              DIAMETER_IDENTITY,    (value_string *)NULL},
    { 258, "Auth-Application-Id",         DIAMETER_UNSIGNED32,  diameter_application_id_vals},
    { 274, "Auth-Request-Type",           DIAMETER_ENUMERATED,  diameter_auth_request_type_vals},
    { 291, "Authorization-Lifetime",      DIAMETER_INTEGER32,   (value_string *)NULL},
    { 276, "Auth-Grace-Period",           DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 277, "Auth-Session-State",          DIAMETER_ENUMERATED,  diameter_auth_session_state_vals},
    { 285, "Re-Auth-Request-Type",        DIAMETER_ENUMERATED,  diameter_re_auth_request_type_vals},
    { 293, "Destination-Host",            DIAMETER_IDENTITY,    (value_string *)NULL},
    { 283, "Destination-Realm",           DIAMETER_UTF8STRING,  (value_string *)NULL},
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
    { 268, "Result-Code",                 DIAMETER_ENUMERATED,  diameter_result_code_vals},
    { 282, "Route-Record",                DIAMETER_IDENTITY,    (value_string *)NULL},
    { 263, "Session-Id",                  DIAMETER_SESSION_ID,  (value_string *)NULL},
    { 270, "Session-Binding",             DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 271, "Session-Server-Failover",     DIAMETER_ENUMERATED,  diameter_session_server_failover_vals},
    { 286, "Source-Route",                DIAMETER_IDENTITY,    (value_string *)NULL},
    { 265, "Supported-Vendor-Id",         DIAMETER_UNSIGNED32,  (value_string *)NULL},
    { 295, "Termination-Cause",           DIAMETER_ENUMERATED,  diameter_termination_cause_vals},
    { 266, "Vendor-Id",                   DIAMETER_ENUMERATED,  sminmpec_values},
    { 260, "Vendor-Specific-Application-Id", DIAMETER_GROUPED, (value_string *)NULL},
    { 297, "Experimental-Result",          DIAMETER_GROUPED,     (value_string *)NULL},
    { 298, "Experimental-Result-Code",     DIAMETER_ENUMERATED,  diameter_exp_result_code_vals},

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
    { 336, "MIP-Candidate-Home-Agent-Host",		DIAMETER_IDENTITY,			(value_string *)NULL},
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
    { 348, "MIP-Home-Agent-Host",			DIAMETER_IDENTITY,			(value_string *)NULL},
    { 398, "MIP-Key-Lifetime",            DIAMETER_UNSIGNED32,    (value_string *)NULL},
/* http://www.ietf.org/internet-drafts/draft-ietf-aaa-diameter-cc-03.txt */
	{ 411, "CC-Correlation-Id",                 DIAMETER_OCTET_STRING,		(value_string *)NULL}, 
	{ 412, "CC-Input-Octets",                   DIAMETER_UNSIGNED64 ,		(value_string *)NULL}, 
	{ 413, "CC-Money",                          DIAMETER_GROUPED    ,		(value_string *)NULL}, 
	{ 414, "CC-Output-Octets",                  DIAMETER_UNSIGNED64 ,		(value_string *)NULL}, 
	{ 415, "CC-Request-Number",                 DIAMETER_UNSIGNED32 ,		(value_string *)NULL}, 
	{ 416, "CC-Request-Type",                   DIAMETER_ENUMERATED ,		(value_string *)NULL}, 
	{ 417, "CC-Service-Specific-Units",         DIAMETER_UNSIGNED64 ,		(value_string *)NULL},  
	{ 418, "CC-Session-Failover",				DIAMETER_ENUMERATED ,		(value_string *)NULL}, 
	{ 419, "CC-Sub-Session-Id",                 DIAMETER_UNSIGNED64 ,		(value_string *)NULL},
	{ 420, "CC-Time",                           DIAMETER_UNSIGNED32 ,		(value_string *)NULL},
	{ 421, "CC-Total-Octets",                   DIAMETER_UNSIGNED64 ,		(value_string *)NULL},
	{ 454, "CC-Unit-Type",                      DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 422, "Check-Balance-Result",              DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 423, "Cost-Information",                  DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 424, "Cost-Unit",                         DIAMETER_UTF8STRING ,		(value_string *)NULL},
	{ 426, "Credit-Control",                    DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 427, "Credit-Control-Failure-Handling",   DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 425, "Currency-Code",                     DIAMETER_UNSIGNED32 ,		(value_string *)NULL},
	{ 428, "Direct-Debiting-Failure-Handling",  DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 429, "Exponent",                          DIAMETER_INTEGER32  ,		(value_string *)NULL},
	{ 449, "Final-Unit-Action",                 DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 430, "Final-Unit-Indication",             DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 431, "Granted-Service-Unit",              DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 453, "G-S-U-Pool-Identifier",             DIAMETER_UNSIGNED32 ,		(value_string *)NULL},
	{ 457, "G-S-U-Pool-Reference",              DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 456, "Multiple-Services-Credit-Control",  DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 455, "Multiple-Services-Indicator",       DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 432, "Rating-Group",                      DIAMETER_UNSIGNED32 ,		(value_string *)NULL},
	{ 433, "Redirect-Address-Type",             DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 434, "Redirect-Server",                   DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 435, "Redirect-Server-Address",           DIAMETER_UTF8STRING ,		(value_string *)NULL},
	{ 436, "Requested-Action",                  DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 437, "Requested-Service-Unit",            DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 438, "Restriction-Filter-Rule",           DIAMETER_IP_FILTER_RULE,	(value_string *)NULL},
	{ 439, "Service-Identifier",                DIAMETER_UTF8STRING ,		(value_string *)NULL},
	{ 440, "Service-Parameter-Info",            DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 441, "Service-Parameter-Type",            DIAMETER_UNSIGNED32 ,		(value_string *)NULL},
	{ 442, "Service-Parameter-Value",           DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ 443, "Subscription-Id",                   DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 444, "Subscription-Id-Data",              DIAMETER_UTF8STRING ,		(value_string *)NULL},
	{ 450, "Subscription-Id-Type",              DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 452, "Tariff-Change-Usage",               DIAMETER_ENUMERATED ,		(value_string *)NULL},
	{ 451, "Tariff-Time-Change",                DIAMETER_TIME,				(value_string *)NULL},
	{ 445, "Unit-Value",                        DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 446, "Used-Service-Unit",                 DIAMETER_GROUPED    ,		(value_string *)NULL},
	{ 447, "Value-Digits",                      DIAMETER_INTEGER64  ,		(value_string *)NULL},
	{ 448, "Validity-Time",                     DIAMETER_UNSIGNED32 ,		(value_string *)NULL},


/* draft-ietf-aaa-diameter-sip-app-01.txt AVP codes to be allocated
	{ xx01, "SIP-Visited-Network-Id",			DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx02, "SIP-AOR",							DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx03, "SIP-Server-URI",					DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx04, "SIP-Server-Capabilities",			DIAMETER_GROUPED,			(value_string *)NULL},
	{ xx05, "SIP-Mandatory-Capability",			DIAMETER_UNSIGNED32,		(value_string *)NULL},
	{ xx06, "SIP-Optional-Capability",			DIAMETER_UNSIGNED32,		(value_string *)NULL},
	{ xx07, "SIP-User-Data",					DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx08, "SIP-Number-Auth-Items",			DIAMETER_UNSIGNED32,		(value_string *)NULL},
	{ xx09, "SIP-Auth-Data-Item",				DIAMETER_GROUPED,			(value_string *)NULL},
	{ xx10, "SIP-Item-Number",					DIAMETER_UNSIGNED32,		(value_string *)NULL},
	{ xx11, "SIP-Authentication-Scheme",		DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx12, "SIP-Authenticate",					DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx13, "SIP-Authorization",				DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx14, "SIP-Authentication-Info",			DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx15, "SIP-Authentication-Context",		DIAMETER_GROUPED,			(value_string *)NULL},
	{ xx16, "SIP-Confidentiality-Key",			DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx17, "SIP-Integrity-Key",				DIAMETER_OCTET_STRING,		(value_string *)NULL},
	{ xx18, "SIP-Server-Assignment-Type",		DIAMETER_ENUMERATED,		SIP_server_assignment_type},
	{ xx19, "SIP-Deregistration-Reason",		DIAMETER_GROUPED,			(value_string *)NULL},
	{ xx20, "SIP-Reason-Code",					DIAMETER_ENUMERATED,		SIP_reason_code_vals},
	{ xx21, "SIP-Reason-Info",					DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx22, "SIP-Accouting-Information",		DIAMETER_GROUPED,			(value_string *)NULL},
	{ xx23, "SIP-Accounting-Server-URI",		DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx24, "SIP-Credit-Control-Server-URI",	DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx25, "SIP-User-Authorization-Type",		DIAMETER_ENUMERATED,		SIP_user_authorization_type},
	{ xx26, "SIP-User-Data-Request-Type",		DIAMETER_ENUMERATED,		SIP_user_data_request_type},
	{ xx27, "SIP-User-Data-Already-Available",	DIAMETER_ENUMERATED,		SIP_user_data_already_available_vals},
	{ xx28, "SIP-Method",						DIAMETER_UTF8STRING,		(value_string *)NULL},
	{ xx29, "SIP-Entity-Body-Hash",				DIAMETER_OCTET_STRING,		(value_string *)NULL},
	*/
	{0, (char *)NULL, 0, (value_string*)NULL}
};



static const value_string diameter_command_code_vals[] = {

	/* Base Protocol */
	{257, "Capabilities-Exchange"},
	{258, "Re-Auth"},
	{271, "Accounting"},
	{274, "Abort-Session"},
	{275, "Session-Termination"},
	{280, "Device-Watchdog"},
	{282, "Disconnect-Peer"},
	{300, "Test-Auth"},
	/* Mip Protocol */
	{260, "AA-Mobile-Node"},
	{262, "Home-Agent-MIP"},
	/* Nasreq Protocol */
	{265, "AA"},
	{268, "Diameter-EAP"},
	/* Credit-Control Application */
	{272, "Credit-Control"},
	/* draft-ietf-aaa-diameter-cms-sec-04 */
	{304,  "Diameter-Security-Association"},
	{305,  "Proxy-Diameter-Security-Association"},
	/* Session Initiation Protocol (SIP) Application, numbers not yet assigned by IANA 
	{aaa, "User-Authorization"},
	{bbb, "Server-Assignment"},
	{ccc, "Location-Info"},
	{ddd, "Multimedia-Auth"},
	{eee, "Registration-Termination"},
	{fff, "Push-Profile"},
	*/	

	{0, (char *)NULL}
};

/* stuff for supporting multiple versions */
typedef enum {
  DIAMETER_V16,
  DIAMETER_RFC
} Version_Type;

static const enum_val_t options[] = {
  { "draft-16", "Diameter base draft version 16 and below",  DIAMETER_V16  },
  { "rfc3588", "Diameter base RFC 3588 ",                    DIAMETER_RFC  },
  { NULL, NULL, 0 }
};



#endif /* _PACKET_DIAMETER_H */
