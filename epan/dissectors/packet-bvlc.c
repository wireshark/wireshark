/* packet-bvlc.c
 * Routines for BACnet/IP (BVLL, BVLC) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-bacnet.h"

void proto_register_bvlc(void);
void proto_reg_handoff_bvlc(void);

#define BVLC_UDP_PORT 0xBAC0

/* Network Layer Wrapper Control Information */
#define BAC_WRAPPER_CONTROL_NET		0x80
#define BAC_WRAPPER_MSG_ENCRYPED	0x40
#define BAC_WRAPPER_RESERVED		0x20
#define BAC_WRAPPER_AUTHD_PRESENT	0x10
#define BAC_WRAPPER_DO_NOT_UNWRAP	0x08
#define BAC_WRAPPER_DO_NOT_DECRPT	0x04
#define BAC_WRAPPER_NO_TRUST_SRC	0x02
#define BAC_WRAPPER_SECURE_BY_RTR	0x01

static int proto_bvlc;
static int proto_bscvlc;
static int hf_bvlc_type;
static int hf_bvlc_function;
static int hf_bvlc_ipv6_function;
static int hf_bvlc_length;
static int hf_bvlc_result_ip4;
static int hf_bvlc_result_ip6;
static int hf_bvlc_bdt_ip;
static int hf_bvlc_bdt_mask;
static int hf_bvlc_bdt_port;
static int hf_bvlc_reg_ttl;
static int hf_bvlc_fdt_ip;
static int hf_bvlc_fdt_ipv6;
static int hf_bvlc_fdt_port;
static int hf_bvlc_fdt_ttl;
static int hf_bvlc_fdt_timeout;
static int hf_bvlc_fwd_ip;
static int hf_bvlc_fwd_port;
static int hf_bvlc_virt_source;
static int hf_bvlc_virt_dest;
static int hf_bvlc_orig_source_addr;
static int hf_bvlc_orig_source_port;
static int hf_bscvlc_control;
static int hf_bscvlc_control_data_option;
static int hf_bscvlc_control_destination_option;
static int hf_bscvlc_control_destination_address;
static int hf_bscvlc_control_origin_address;
static int hf_bscvlc_control_reserved;
static int hf_bscvlc_header;
static int hf_bscvlc_header_marker;
static int hf_bscvlc_header_length;
static int hf_bscvlc_header_data;
static int hf_bscvlc_header_opt_type;
static int hf_bscvlc_header_opt_data;
static int hf_bscvlc_header_opt_must_understand;
static int hf_bscvlc_header_opt_more;
static int hf_bscvlc_vendor_id;
static int hf_bscvlc_proprietary_opt_type;
static int hf_bscvlc_proprietary_data;
static int hf_bscvlc_hub_conn_state;
static int hf_bscvlc_accept_conns;
static int hf_bscvlc_max_bvlc_length;
static int hf_bscvlc_max_npdu_length;
static int hf_bscvlc_function;
static int hf_bscvlc_result;
static int hf_bscvlc_error_class;
static int hf_bscvlc_error_code;
static int hf_bscvlc_result_data;
static int hf_bscvlc_uris;
static int hf_bscvlc_msg_id;
static int hf_bscvlc_orig_vmac;
static int hf_bscvlc_dest_vmac;
static int hf_bscvlc_connect_vmac;
static int hf_bscvlc_connect_uuid;

static dissector_table_t bvlc_dissector_table;
static dissector_table_t bscvlc_dissector_table;
static dissector_table_t bvlc_ipv6_dissector_table;
static dissector_handle_t bvlc_handle;
static dissector_handle_t bscvlc_handle;

static const value_string bvlc_function_names[] = {
	{ 0x00, "BVLC-Result" },
	{ 0x01, "Write-Broadcast-Distribution-Table" },
	{ 0x02, "Read-Broadcast-Distribution-Table" },
	{ 0x03, "Read-Broadcast-Distribution-Table-Ack" },
	{ 0x04, "Forwarded-NPDU" },
	{ 0x05, "Register-Foreign-Device" },
	{ 0x06, "Read-Foreign-Device-Table" },
	{ 0x07, "Read-Foreign-Device-Table-Ack" },
	{ 0x08, "Delete-Foreign-Device-Table-Entry" },
	{ 0x09, "Distribute-Broadcast-To-Network" },
	{ 0x0a, "Original-Unicast-NPDU" },
	{ 0x0b, "Original-Broadcast-NPDU" },
	{ 0x0c, "Secured-BVLL" },
	{ 0, NULL }
};

static const value_string bscvlc_function_names[] = {
	{ 0x00, "BVLC-Result" },
	{ 0x01, "Encapsulated-NPDU" },
	{ 0x02, "Address-Resolution" },
	{ 0x03, "Address-Resolution-ACK" },
	{ 0x04, "Advertisement" },
	{ 0x05, "Advertisement-Solicitation" },
	{ 0x06, "Connect-Request" },
	{ 0x07, "Connect-Accept" },
	{ 0x08, "Disconnect-Request" },
	{ 0x09, "Disconnect-ACK" },
	{ 0x0A, "Heartbeat-Request" },
	{ 0x0B, "Heartbeat-ACK" },
	{ 0x0C, "Proprietary-Message" },
	{ 0, NULL }
};

static const value_string bvlc_result_names[] = {
	{ 0x00, "Successful completion" },
	{ 0x10, "Write-Broadcast-Distribution-Table NAK" },
	{ 0x20, "Read-Broadcast-Distribution-Table NAK" },
	{ 0x30, "Register-Foreign-Device NAK" },
	{ 0x40, "Read-Foreign-Device-Table NAK" },
	{ 0x50, "Delete-Foreign-Device-Table-Entry NAK" },
	{ 0x60, "Distribute-Broadcast-To-Network NAK" },
	{ 0,    NULL }
};

static const value_string bscvlc_result_names[] = {
	{ 0x00, "Successful completion (ACK)" },
	{ 0x01, "Completion failed (NAK)" },
	{ 0,    NULL }
};

static const value_string bvlc_ipv6_function_names[] = {
	{ 0x00, "BVLC-Result", },
	{ 0x01, "Original-Unicast-NPDU", },
	{ 0x02, "Original-Broadcast-NPDU", },
	{ 0x03, "Address-Resolution", },
	{ 0x04, "Forwarded-Address-Resolution", },
	{ 0x05, "Address-Resolution-ACK", },
	{ 0x06, "Virtual-Address-Resolution", },
	{ 0x07, "Virtual-Address-Resolution-ACK", },
	{ 0x08, "Forwarded-NPDU", },
	{ 0x09, "Register-Foreign-Device", },
	{ 0x0A, "Delete-Foreign-Device-Table-Entry", },
	{ 0x0B, "Secure-BVLL", },
	{ 0x0C, "Distribute-Broadcast-To-Network", },
	{ 0, NULL }
};

static const value_string bvlc_ipv6_result_names[] = {
	{ 0x00, "Successful completion" },
	{ 0x30, "Address-Resolution NAK" },
	{ 0x60, "Virtual-Address-Resolution NAK" },
	{ 0x90, "Register-Foreign-Device NAK" },
	{ 0xA0, "Delete-Foreign-Device-Table-Entry NAK" },
	{ 0xC0, "Distribute-Broadcast-To-Network NAK" },
	{ 0, NULL }
};

static const value_string bscvlc_header_type_names[] = {
	{ 0x01, "Secure Path" },
	{ 0x1F, "Proprietary Header Option" },
	{ 0,    NULL }
};

static const value_string bscvlc_hub_conn_state_names[] = {
	{ 0x00, "No hub connection" },
	{ 0x01, "Connected to primary hub" },
	{ 0x02, "Connected to failover hub" },
	{ 0,    NULL }
};

static const value_string bscvlc_hub_accept_conns_names[] = {
	{ 0x00, "The node does not support accepting direct connections" },
	{ 0x01, "The node supports accepting direct connections" },
	{ 0,    NULL }
};

static int ett_bvlc;
static int ett_bscvlc;
static int ett_bscvlc_ctrl;
static int ett_bscvlc_hdr;
static int ett_bdt;
static int ett_fdt;

#define BACNET_IP_ANNEX_J		0x81
#define BACNET_IPV6_ANNEX_U		0x82

static const value_string bvlc_types[] = {
	{ BACNET_IP_ANNEX_J,	"BACnet/IP (Annex J)" },
	{ BACNET_IPV6_ANNEX_U,	"BACnet/IPV6 (Annex U)" },
	{ 0, NULL }
};

#define BSCVLC_CONTROL_DATA_OPTION		0x01
#define BSCVLC_CONTROL_DEST_OPTION		0x02
#define BSCVLC_CONTROL_DEST_ADDRESS		0x04
#define BSCVLC_CONTROL_ORIG_ADDRESS		0x08
#define BSCVLC_CONTROL_RESERVED			0xF0

static const true_false_string control_data_option_set_high = {
	"Data Options field is present.",
	"Data Options field is absent."
};

static const true_false_string control_destination_option_set_high = {
	"Destination Options field is present.",
	"Destination Options field is absent."
};

static const true_false_string control_destination_address_set_high = {
	"Destination Virtual Address is present.",
	"Destination Virtual Address is absent."
};

static const true_false_string control_orig_address_set_high = {
	"Originating Virtual Address is present.",
	"Originating Virtual Address is absent."
};

static const true_false_string control_reserved_set_high = {
	"Shall be zero, but is not.",
	"Shall be zero and is zero."
};

#define BSCVLC_HEADER_OPTION_TYPE		0x1F
#define BSCVLC_HEADER_OPTION_DATA		0x20
#define BSCVLC_HEADER_OPTION_MUST_UNDERSTAND	0x40
#define BSCVLC_HEADER_OPTION_MORE_OPTIONS	0x80

#define BSCVLC_HEADER_TYPE_SECURE_PATH		0x01
#define BSCVLC_HEADER_TYPE_PROPRIETARY		0x1F


static const true_false_string header_opt_data_set_high = {
	"The 'Header Length' and 'Header Data' fields are present.",
	"The 'Header Length' and 'Header Data' fields are absent."
};

static const true_false_string header_opt_must_understand_set_high = {
	"This header option must be understood for consuming the message.",
	"This header option can be ignored if not understood."
};

static const true_false_string header_opt_more_set_high = {
	"Another header option follows in the current header option list.",
	"This is the last header option in the current header option list."
};

static const value_string
BACnetErrorClass [] = {
    { 0, "device" },
    { 1, "object" },
    { 2, "property" },
    { 3, "resources" },
    { 4, "security" },
    { 5, "services" },
    { 6, "vt" },
    { 7, "communication" },
    { 0, NULL }
/* Enumerated values 0-63 are reserved for definition by ASHRAE.
   Enumerated values64-65535 may be used by others subject to
   the procedures and constraints described in Clause 23. */
};

static const value_string
BACnetErrorCode[] = {
    {   0, "other"},
    {   1, "authentication-failed"},
    {   2, "configuration-in-progress"},
    {   3, "device-busy"},
    {   4, "dynamic-creation-not-supported"},
    {   5, "file-access-denied"},
    {   6, "incompatible-security-levels"},
    {   7, "inconsistent-parameters"},
    {   8, "inconsistent-selection-criterion"},
    {   9, "invalid-data-type"},
    {  10, "invalid-file-access-method"},
    {  11, "invalid-file-start-position"},
    {  12, "invalid-operator-name"},
    {  13, "invalid-parameter-data-type"},
    {  14, "invalid-time-stamp"},
    {  15, "key-generation-error"},
    {  16, "missing-required-parameter"},
    {  17, "no-objects-of-specified-type"},
    {  18, "no-space-for-object"},
    {  19, "no-space-to-add-list-element"},
    {  20, "no-space-to-write-property"},
    {  21, "no-vt-sessions-available"},
    {  22, "property-is-not-a-list"},
    {  23, "object-deletion-not-permitted"},
    {  24, "object-identifier-already-exists"},
    {  25, "operational-problem"},
    {  26, "password-failure"},
    {  27, "read-access-denied"},
    {  28, "security-not-supported"},
    {  29, "service-request-denied"},
    {  30, "timeout"},
    {  31, "unknown-object"},
    {  32, "unknown-property"},
    {  33, "removed enumeration"},
    {  34, "unknown-vt-class"},
    {  35, "unknown-vt-session"},
    {  36, "unsupported-object-type"},
    {  37, "value-out-of-range"},
    {  38, "vt-session-already-closed"},
    {  39, "vt-session-termination-failure"},
    {  40, "write-access-denied"},
    {  41, "character-set-not-supported"},
    {  42, "invalid-array-index"},
    {  43, "cov-subscription-failed"},
    {  44, "not-cov-property"},
    {  45, "optional-functionality-not-supported"},
    {  46, "invalid-configuration-data"},
    {  47, "datatype-not-supported"},
    {  48, "duplicate-name"},
    {  49, "duplicate-object-id"},
    {  50, "property-is-not-an-array"},
    {  51, "abort - buffer - overflow" },
    {  52, "abort - invalid - apdu - in - this - state" },
    {  53, "abort - preempted - by - higher - priority - task" },
    {  54, "abort - segmentation - not - supported" },
    {  55, "abort - proprietary" },
    {  56, "abort - other" },
    {  57, "reject - invalid - tag" },
    {  58, "reject - network - down" },
    {  59, "reject - buffer - overflow" },
    {  60, "reject - inconsistent - parameters" },
    {  61, "reject - invalid - parameter - data - type" },
    {  62, "reject - invalid - tag" },
    {  63, "reject - missing - required - parameter" },
    {  64, "reject - parameter - out - of - range" },
    {  65, "reject - too - many - arguments" },
    {  66, "reject - undefined - enumeration" },
    {  67, "reject - unrecognized - service" },
    {  68, "reject - proprietary" },
    {  69, "reject - other" },
    {  70, "unknown - device" },
    {  71, "unknown - route" },
    {  72, "value - not - initialized" },
    {  73, "invalid-event-state"},
    {  74, "no-alarm-configured"},
    {  75, "log-buffer-full"},
    {  76, "logged-value-purged"},
    {  77, "no-property-specified"},
    {  78, "not-configured-for-triggered-logging"},
    {  79, "unknown-subscription"},
    {  80, "parameter-out-of-range"},
    {  81, "list-element-not-found"},
    {  82, "busy"},
    {  83, "communication-disabled"},
    {  84, "success"},
    {  85, "access-denied"},
    {  86, "bad-destination-address"},
    {  87, "bad-destination-device-id"},
    {  88, "bad-signature"},
    {  89, "bad-source-address"},
    {  90, "bad-timestamp"},
    {  91, "cannot-use-key"},
    {  92, "cannot-verify-message-id"},
    {  93, "correct-key-revision"},
    {  94, "destination-device-id-required"},
    {  95, "duplicate-message"},
    {  96, "encryption-not-configured"},
    {  97, "encryption-required"},
    {  98, "incorrect-key"},
    {  99, "invalid-key-data"},
    { 100, "key-update-in-progress"},
    { 101, "malformed-message"},
    { 102, "not-key-server"},
    { 103, "security-not-configured"},
    { 104, "source-security-required"},
    { 105, "too-many-keys"},
    { 106, "unknown-authentication-type"},
    { 107, "unknown-key"},
    { 108, "unknown-key-revision"},
    { 109, "unknown-source-message"},
    { 110, "not-router-to-dnet"},
    { 111, "router-busy"},
    { 112, "unknown-network-message"},
    { 113, "message-too-long"},
    { 114, "security-error"},
    { 115, "addressing-error"},
    { 116, "write-bdt-failed"},
    { 117, "read-bdt-failed"},
    { 118, "register-foreign-device-failed"},
    { 119, "read-fdt-failed"},
    { 120, "delete-fdt-entry-failed"},
    { 121, "distribute-broadcast-failed"},
    { 122, "unknown-file-size"},
    { 123, "abort-apdu-too-long"},
    { 124, "abort-application-exceeded-reply-time"},
    { 125, "abort-out-of-resources"},
    { 126, "abort-tsm-timeout"},
    { 127, "abort-window-size-out-of-range"},
    { 128, "file-full"},
    { 129, "inconsistent-configuration"},
    { 130, "inconsistent-object-type"},
    { 131, "internal-error"},
    { 132, "not-configured"},
    { 133, "out-of-memory"},
    { 134, "value-too-long"},
    { 135, "abort-insufficient-security"},
    { 136, "abort-security-error"},
    { 137, "duplicate-entry"},
    { 138, "invalid-value-in-this-state"},
    { 139, "invalid-operation-in-this-state"},
    { 140, "list-item-not-numbered"},
    { 141, "list-item-not-timestamped"},
    { 142, "invalid-data-encoding"},
    { 143, "bvlc-function-unknown"},
    { 144, "bvlc-proprietary-function-unknown"},
    { 145, "header-encoding-error"},
    { 146, "header-not-understood"},
    { 147, "message-incomplete"},
    { 148, "not-a-bacnet-sc-hub"},
    { 149, "payload-expected"},
    { 150, "unexpected-data"},
    { 151, "node-duplicate-vmac"},
    { 152, "http-unexpected-response-code"},
    { 153, "http-no-upgrade"},
    { 154, "http-resource-not-local"},
    { 155, "http-proxy-authentication-failed"},
    { 156, "http-response-timeout"},
    { 157, "http-response-syntax-error"},
    { 158, "http-response-value-error"},
    { 159, "http-response-missing-header"},
    { 160, "http-websocket-header-error"},
    { 161, "http-upgrade-required"},
    { 162, "http-upgrade-error"},
    { 163, "http-temporary-unavailable"},
    { 164, "http-not-a-server"},
    { 165, "http-error"},
    { 166, "websocket-scheme-not-supported"},
    { 167, "websocket-unknown-control-message"},
    { 168, "websocket-close-error"},
    { 169, "websocket-closed-by-peer"},
    { 170, "websocket-endpoint-leaves"},
    { 171, "websocket-protocol-error"},
    { 172, "websocket-data-not-accepted"},
    { 173, "websocket-closed-abnormally"},
    { 174, "websocket-data-inconsistent"},
    { 175, "websocket-data-against-policy"},
    { 176, "websocket-frame-too-long"},
    { 177, "websocket-extension-missing"},
    { 178, "websocket-request-unavailable"},
    { 179, "websocket-error"},
    { 180, "tls-client-certificate-error"},
    { 181, "tls-server-certificate-error"},
    { 182, "tls-client-authentication-failed"},
    { 183, "tls-server-authentication-failed"},
    { 184, "tls-client-certificate-expired"},
    { 185, "tls-server-certificate-expired"},
    { 186, "tls-client-certificate-revoked"},
    { 187, "tls-server-certificate-revoked"},
    { 188, "tls-error"},
    { 189, "dns-unavailable"},
    { 190, "dns-name-resolution-failed"},
    { 191, "dns-resolver-failure"},
    { 192, "dns-error"},
    { 193, "tcp-connect-timeout"},
    { 194, "tcp-connection-refused"},
    { 195, "tcp-closed-by-local"},
    { 196, "tcp-closed-other"},
    { 197, "tcp-error"},
    { 198, "ip-address-not-reachable"},
    { 199, "ip-error"},
    { 0,   NULL}
/* Enumerated values 0-255 are reserved for definition by ASHRAE.
   Enumerated values 256-65535 may be used by others subject to the
   procedures and constraints described in Clause 23. */
};

static int * const bscvlc_control_flags[] = {
	&hf_bscvlc_control_data_option,
	&hf_bscvlc_control_destination_option,
	&hf_bscvlc_control_destination_address,
	&hf_bscvlc_control_origin_address,
	&hf_bscvlc_control_reserved,
	NULL
};

static int * const bscvlc_header_flags[] = {
	&hf_bscvlc_header_opt_type,
	&hf_bscvlc_header_opt_data,
	&hf_bscvlc_header_opt_must_understand,
	&hf_bscvlc_header_opt_more,
	NULL
};

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_ipv4_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	proto_item *ti;
	proto_item *ti_bdt;
	proto_item *ti_fdt;
	proto_tree *bvlc_tree;
	proto_tree *bdt_tree; /* Broadcast Distribution Table */
	proto_tree *fdt_tree; /* Foreign Device Table */

	int offset;
	uint8_t bvlc_type;
	uint8_t bvlc_function;
	uint16_t bvlc_length;
	uint16_t packet_length;
	unsigned npdu_length;
	unsigned length_remaining;
	tvbuff_t *next_tvb;

	offset = 0;

	bvlc_type = tvb_get_uint8(tvb, offset);
	bvlc_function = tvb_get_uint8(tvb, offset + 1);
	packet_length = tvb_get_ntohs(tvb, offset + 2);
	length_remaining = tvb_reported_length_remaining(tvb, offset);

	if (bvlc_function > 0x08) {
		/*  We have a constant header length of BVLC of 4 in every
		 *  BVLC-packet forewarding an NPDU. Beware: Changes in the
		 *  BACnet-IP-standard may break this.
		 */
		bvlc_length = 4;
	} else if (bvlc_function == 0x04) {
		/* 4 Bytes + 6 Bytes for B/IP Address of Originating Device */
		bvlc_length = 10;
	} else {
		/*  BVLC-packets with function below 0x09 contain
		 *  routing-level data (e.g. Broadcast Distribution)
		 *  but no NPDU for BACnet, so bvlc_length goes up to the end
		 *  of the captured frame.
		 */
		bvlc_length = packet_length;
	}

	if (bvlc_length < 4 || bvlc_length > packet_length) {
		return 0;	/* reject */
	}

	/* Put the BVLC Type in the info column */
	col_append_fstr(pinfo->cinfo, COL_INFO, " BVLC Function %s ",
                  val_to_str_const(bvlc_function, bvlc_function_names, "unknown"));

	ti = proto_tree_add_item(tree, proto_bvlc, tvb, 0, bvlc_length, ENC_NA);
	bvlc_tree = proto_item_add_subtree(ti, ett_bvlc);
	proto_tree_add_uint(bvlc_tree, hf_bvlc_type, tvb, offset, 1,
		bvlc_type);
	offset++;
	proto_tree_add_uint(bvlc_tree, hf_bvlc_function, tvb,
		offset, 1, bvlc_function);
	offset++;
	if (length_remaining != packet_length)
		proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
			2, bvlc_length,
			"%d of %d bytes (invalid length - expected %d bytes)",
			bvlc_length, packet_length, length_remaining);
	else
		proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
			2, bvlc_length, "%d of %d bytes BACnet packet length",
			bvlc_length, packet_length);
	offset += 2;
	switch (bvlc_function) {
	case 0x00: /* BVLC-Result */
		/* I don't know why the result code is encoded in 4 nibbles,
		 * but only using one: 0x00r0. Shifting left 4 bits.
		 */
		/* We should bitmask the result correctly when we have a
		 * packet to dissect, see README.developer, 1.6.2, FID */
		proto_tree_add_item(bvlc_tree, hf_bvlc_result_ip4, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		/*offset += 2;*/
		break;
	case 0x01: /* Write-Broadcast-Distribution-Table */
	case 0x03: /* Read-Broadcast-Distribution-Table-Ack */
		/* List of BDT Entries:	N*10-octet */
		ti_bdt = proto_tree_add_item(bvlc_tree, proto_bvlc, tvb,
			offset, bvlc_length-4, ENC_NA);
		bdt_tree = proto_item_add_subtree(ti_bdt, ett_bdt);
		/* List of BDT Entries:	N*10-octet */
		while ((bvlc_length - offset) > 9) {
			proto_tree_add_item(bdt_tree, hf_bvlc_bdt_ip,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(bdt_tree, hf_bvlc_bdt_port,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(bdt_tree,
				hf_bvlc_bdt_mask, tvb, offset, 4,
				ENC_NA);
			offset += 4;
		}
		/* We check this if we get a BDT-packet somewhere */
		break;
	case 0x02: /* Read-Broadcast-Distribution-Table */
		/* nothing to do here */
		break;
	case 0x05: /* Register-Foreign-Device */
		/* Time-to-Live	2-octets T, Time-to-Live T, in seconds */
		proto_tree_add_item(bvlc_tree, hf_bvlc_reg_ttl,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		/*offset += 2;*/
		break;
	case 0x06: /* Read-Foreign-Device-Table */
		/* nothing to do here */
		break;
	case 0x07: /* Read-Foreign-Device-Table-Ack */
		/* List of FDT Entries:	N*10-octet */
		/* N indicates the number of entries in the FDT whose
		 * contents are being returned. Each returned entry
		 * consists of the 6-octet B/IP address of the registrant;
		 * the 2-octet Time-to-Live value supplied at the time of
		 * registration; and a 2-octet value representing the
		 * number of seconds remaining before the BBMD will purge
		 * the registrant's FDT entry if no re-registration occurs.
		 */
		ti_fdt = proto_tree_add_item(bvlc_tree, proto_bvlc, tvb,
			offset, bvlc_length -4, ENC_NA);
		fdt_tree = proto_item_add_subtree(ti_fdt, ett_fdt);
		/* List of FDT Entries:	N*10-octet */
		while ((bvlc_length - offset) > 9) {
			proto_tree_add_item(fdt_tree, hf_bvlc_fdt_ip,
				tvb, offset, 4, ENC_BIG_ENDIAN);
			offset += 4;
			proto_tree_add_item(fdt_tree, hf_bvlc_fdt_port,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(fdt_tree,
				hf_bvlc_fdt_ttl, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(fdt_tree,
				hf_bvlc_fdt_timeout, tvb, offset, 2,
				ENC_BIG_ENDIAN);
			offset += 2;
		}
		/* We check this if we get a FDT-packet somewhere */
		break;
	case 0x08: /* Delete-Foreign-Device-Table-Entry */
		/* FDT Entry:	6-octets */
		proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_ip,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		/*offset += 2;*/
		break;
	case 0x0C: /* Secure-BVLL */
		offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
		if (offset < 0) {
			call_data_dissector(tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		}
		increment_dissection_depth(pinfo);
		dissect_ipv4_bvlc(tvb, pinfo, tree, data);
		decrement_dissection_depth(pinfo);
		break;
		/* We check this if we get a FDT-packet somewhere */
	case 0x04:	/* Forwarded-NPDU
			 * Why is this 0x04? It would have been a better
			 * idea to append all forewarded NPDUs at the
			 * end of the function table in the B/IP-standard!
			 */
		/* proto_tree_add_bytes_format(); */
		proto_tree_add_item(bvlc_tree, hf_bvlc_fwd_ip,
			tvb, offset, 4, ENC_BIG_ENDIAN);
		offset += 4;
		proto_tree_add_item(bvlc_tree, hf_bvlc_fwd_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		/*offset += 2;*/
		break;
	default:
		/* Distribute-Broadcast-To-Network
		 * Original-Unicast-NPDU
		 * Original-Broadcast-NPDU
		 * Going to the next dissector...
		 */
		break;
	}

	/* Ok, no routing information BVLC packet. Dissect as
	 * BACnet NPDU
	 */
	npdu_length = packet_length - bvlc_length;
	next_tvb = tvb_new_subset_length(tvb, bvlc_length, npdu_length);
	/* Code from Guy Harris */
	if (!dissector_try_uint(bvlc_dissector_table,
		bvlc_function, next_tvb, pinfo, tree)) {
		/* Unknown function - dissect the payload as data */
		call_data_dissector(next_tvb, pinfo, tree);
	}
	return tvb_reported_length(tvb);
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_ipv6_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *bvlc_tree;

	int offset;
	uint8_t bvlc_type;
	uint8_t bvlc_function;
	uint16_t bvlc_length = 0;
	uint16_t packet_length;
	unsigned npdu_length;
	unsigned length_remaining;
	tvbuff_t *next_tvb;

	offset = 0;

	bvlc_type = tvb_get_uint8(tvb, offset);
	bvlc_function = tvb_get_uint8(tvb, offset + 1);
	packet_length = tvb_get_ntohs(tvb, offset + 2);
	length_remaining = tvb_reported_length_remaining(tvb, offset);

	switch (bvlc_function) {
	case 0x00:
	case 0x09:
		bvlc_length = 9;
		break;
	case 0x01:
		bvlc_length = 10;
		break;
	case 0x02:
	case 0x06:
	case 0x0C:
		bvlc_length = 7;
		break;
	case 0x03:
	case 0x05:
	case 0x07:
		bvlc_length = 10;
		break;
	case 0x04:
		bvlc_length = 28;
		break;
	case 0x08:
	case 0x0A:
		bvlc_length = 25;
		break;
	case 0x0B:
		bvlc_length = 4;
		break;
	default:
		break;
	}

	if (bvlc_length > packet_length) {
		return 0;	/* reject */
	}

	/* Put the BVLC Type in the info column */
	col_append_fstr(pinfo->cinfo, COL_INFO, " BVLC Function %s ",
                  val_to_str_const(bvlc_function, bvlc_ipv6_function_names, "unknown"));

	ti = proto_tree_add_item(tree, proto_bvlc, tvb, 0,
		bvlc_length, ENC_NA);
	bvlc_tree = proto_item_add_subtree(ti, ett_bvlc);
	/* add the BVLC type */
	proto_tree_add_uint(bvlc_tree, hf_bvlc_type, tvb, offset, 1,
		bvlc_type);
	offset++;
	/* add the BVLC function */
	proto_tree_add_uint(bvlc_tree, hf_bvlc_ipv6_function, tvb,
		offset, 1, bvlc_function);
	offset++;
	/* add the length information */
	if (length_remaining != packet_length)
		proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
			2, bvlc_length,
			"%d of %d bytes (invalid length - expected %d bytes)",
			bvlc_length, packet_length, length_remaining);
	else
		proto_tree_add_uint_format_value(bvlc_tree, hf_bvlc_length, tvb, offset,
			2, bvlc_length,
			"%d of %d bytes BACnet packet length",
			bvlc_length, packet_length);
	offset += 2;

	/* add the optional present virtual source address */
	if (bvlc_function != 0x0B) {
		proto_tree_add_item(bvlc_tree, hf_bvlc_virt_source, tvb, offset,
			3, ENC_BIG_ENDIAN);
		offset += 3;
	}

	/* handle additional function parameters */
	switch (bvlc_function) {
	case 0x00: /* BVLC-Result */
		proto_tree_add_item(bvlc_tree, hf_bvlc_result_ip6, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x01: /* Original-Unicast-NPDU */
	case 0x03: /* Address-Resolution */
	case 0x05: /* Address-Resolution-ACK */
	case 0x07: /* Virtual-Address-Resolution-ACK */
		proto_tree_add_item(bvlc_tree, hf_bvlc_virt_dest, tvb, offset,
			3, ENC_BIG_ENDIAN);
		offset += 3;
		break;
	case 0x04: /* Forwarded-Address-Resolution */
		proto_tree_add_item(bvlc_tree, hf_bvlc_virt_dest, tvb, offset,
			3, ENC_BIG_ENDIAN);
		offset += 3;
		proto_tree_add_item(bvlc_tree, hf_bvlc_orig_source_addr,
			tvb, offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(bvlc_tree, hf_bvlc_orig_source_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x08: /* Forwarded-NPDU */
		proto_tree_add_item(bvlc_tree, hf_bvlc_orig_source_addr,
			tvb, offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(bvlc_tree, hf_bvlc_orig_source_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x06: /* Virtual-Address-Resolution */
		break;
	case 0x09: /* Register-Foreign-Device */
		proto_tree_add_item(bvlc_tree, hf_bvlc_reg_ttl,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x0A: /* Delete-Foreign-Device-Table-Entry */
		proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_ipv6,
			tvb, offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(bvlc_tree, hf_bvlc_fdt_port,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		break;
	case 0x0B: /* Secure-BVLL */
		offset = bacnet_dissect_sec_wrapper(tvb, pinfo, tree, offset, NULL);
		if (offset < 0) {
			call_data_dissector(tvb, pinfo, tree);
			return tvb_captured_length(tvb);
		}
		increment_dissection_depth(pinfo);
		dissect_ipv6_bvlc(tvb, pinfo, tree, data);
		decrement_dissection_depth(pinfo);
		break;
	case 0x02: /* Original-Broadcast-NPDU */
	case 0x0c: /* Distribute-Broadcast-To-Network */
	default:
		/*
		 * Going to the next dissector...
		 */
		break;
	}

	/* Ok, no routing information BVLC packet. Dissect as
	 * BACnet NPDU
	 */
	npdu_length = packet_length - offset;
	next_tvb = tvb_new_subset_length(tvb, offset, npdu_length);
	/* Code from Guy Harris */
	if ( ! dissector_try_uint(bvlc_ipv6_dissector_table,
		bvlc_function, next_tvb, pinfo, tree)) {
		/* Unknown function - dissect the payload as data */
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_reported_length(tvb);
}

static int
dissect_bvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	uint8_t bvlc_type;
	unsigned ret = 0;

	bvlc_type = tvb_get_uint8(tvb, 0);

	/*
	 * Simple sanity check - make sure the type is one we know about.
	 */
	if (try_val_to_str(bvlc_type, bvlc_types) == NULL)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BVLC");
	col_set_str(pinfo->cinfo, COL_INFO, "BACnet Virtual Link Control");

	switch (bvlc_type)
	{
	case BACNET_IP_ANNEX_J:
		ret = dissect_ipv4_bvlc(tvb, pinfo, tree, data);
		break;
	case BACNET_IPV6_ANNEX_U:
		ret = dissect_ipv6_bvlc(tvb, pinfo, tree, data);
		break;
	}

	return ret;
}

static int
dissect_bscvlc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *ti;
	proto_tree *bvlc_tree;
	tvbuff_t *next_tvb;
	int offset;
	int start;
	int bvlc_length;
	int packet_length;
	int npdu_length;
	uint8_t bvlc_function;
	uint8_t bvlc_control;
	uint8_t bvlc_result;
	uint8_t hdr_byte;
	int8_t mac_buffer[16];
	unsigned bvlc_message_id;
	unsigned idx;
	bool bMoreFlag;
	bool bDataFlag;
	proto_tree *subtree;

	/* Calculate length of BSCVLC block to get remaining payload length */
	offset = 0;

	packet_length = tvb_reported_length_remaining(tvb, offset);
	if(packet_length < 4)
		return 0; /* reject */

	/* Fix part of the header first */
	bvlc_function = tvb_get_uint8(tvb, offset++);
	bvlc_control = tvb_get_uint8(tvb, offset++);
	bvlc_message_id = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
	offset += 2;

	/* Variable part of the header next */
	bvlc_length = offset;

	if ((bvlc_control & BSCVLC_CONTROL_ORIG_ADDRESS) != 0)
		bvlc_length += 6;

	if ((bvlc_control & BSCVLC_CONTROL_DEST_ADDRESS) != 0)
		bvlc_length += 6;

	if ((bvlc_control & BSCVLC_CONTROL_DEST_OPTION) != 0)
	{
		bMoreFlag = true;

		while(tvb_reported_length_remaining(tvb, bvlc_length) > 0 &&
		      (hdr_byte = tvb_get_uint8(tvb, bvlc_length)) != 0 && bMoreFlag)
		{
			/* get flags and type... */
			bMoreFlag= (hdr_byte & BSCVLC_HEADER_OPTION_MORE_OPTIONS);
			bDataFlag= (hdr_byte & BSCVLC_HEADER_OPTION_DATA);
			bvlc_length++;

			if(bDataFlag)
			{
				npdu_length = (int)(tvb_get_uint8(tvb, bvlc_length++) << 8);
				npdu_length += (int)tvb_get_uint8(tvb, bvlc_length++);
				bvlc_length += npdu_length;
			}
		}
	}

	if ((bvlc_control & BSCVLC_CONTROL_DATA_OPTION) != 0)
	{
		bMoreFlag = true;

		while(tvb_reported_length_remaining(tvb, bvlc_length) > 0 &&
		      (hdr_byte = tvb_get_uint8(tvb, bvlc_length)) != 0 && bMoreFlag)
		{
			/* get flags and type... */
			bMoreFlag= (hdr_byte & BSCVLC_HEADER_OPTION_MORE_OPTIONS);
			bDataFlag= (hdr_byte & BSCVLC_HEADER_OPTION_DATA);
			bvlc_length++;

			if(bDataFlag)
			{
				npdu_length = (int)(tvb_get_uint8(tvb, bvlc_length++) << 8);
				npdu_length += (int)tvb_get_uint8(tvb, bvlc_length++);
				bvlc_length += npdu_length;
			}
		}
	}

	/* Now add the BSCVLC payload size for specified function */
	switch (bvlc_function)
	{
	case 0x00: /* BVLC-Result */
	case 0x03: /* Address-Resolution-ACK */
	case 0x0C: /* Proprietary-Message */
		/* complete packet length because of optional present variable length error data
		   but no length encoded for it in the structure of this frame */
		bvlc_length = packet_length;
		break;
	case 0x02: /* Address-Resolution */
	case 0x05: /* Advertisement-Solicitation */
	case 0x08: /* Disconnect-Request */
	case 0x09: /* Disconnect-ACK */
	case 0x0A: /* Heartbeat-Request */
	case 0x0B: /* Heartbeat-ACK */
		/* No additional payload here */
		break;
	case 0x04: /* Advertisement */
		bvlc_length += 6;
		break;
	case 0x06: /* Connect-Request */
	case 0x07: /* Connect-Accept */
		bvlc_length += 26;
		break;
	case 0x01: /* Encapsulated-NPDU */
	default:
		/* The additional payload will be decoded elsewhere */
		break;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BSCVLC");
	col_set_str(pinfo->cinfo, COL_INFO, "BACnet Secure Connect Virtual Link Control");

	/* Put the BSCVLC Type and Message ID in the info column */
	col_append_fstr(pinfo->cinfo, COL_INFO, " BSCVLC Function %s Message-ID %u",
                  val_to_str_const(bvlc_function, bscvlc_function_names, "unknown"), bvlc_message_id);

	/* Fill the tree... */
	offset = 0;
	ti = proto_tree_add_item(tree, proto_bscvlc, tvb, 0, bvlc_length, ENC_NA);
	bvlc_tree = proto_item_add_subtree(ti, ett_bvlc);

	proto_tree_add_uint(bvlc_tree, hf_bscvlc_function, tvb,
		offset, 1, bvlc_function);
	offset++;
	proto_tree_add_bitmask(bvlc_tree, tvb, offset, hf_bscvlc_control,
				ett_bscvlc_ctrl, bscvlc_control_flags, ENC_NA);
	offset ++;
	proto_tree_add_uint(bvlc_tree, hf_bscvlc_msg_id, tvb,
		offset, 2, bvlc_message_id);
	offset += 2;

	if ((bvlc_control & BSCVLC_CONTROL_ORIG_ADDRESS) != 0)
	{
		for(idx = 0; idx < 6; idx++)
			snprintf(&mac_buffer[idx * 2], sizeof(mac_buffer) - (idx * 2), "%02X", tvb_get_uint8(tvb, offset + idx));
		col_append_fstr(pinfo->cinfo, COL_INFO, " SMAC %s", mac_buffer);

		proto_tree_add_item(bvlc_tree, hf_bscvlc_orig_vmac, tvb, offset, 6, ENC_NA);
		offset += 6;
	}

	if ((bvlc_control & BSCVLC_CONTROL_DEST_ADDRESS) != 0)
	{
		for(idx = 0; idx < 6; idx++)
			snprintf(&mac_buffer[idx * 2],  sizeof(mac_buffer) - (idx * 2), "%02X", tvb_get_uint8(tvb, offset + idx));
		col_append_fstr(pinfo->cinfo, COL_INFO, " DMAC %s", mac_buffer);

		proto_tree_add_item(bvlc_tree, hf_bscvlc_dest_vmac, tvb, offset, 6, ENC_NA);
		offset += 6;
	}

	if ((bvlc_control & BSCVLC_CONTROL_DEST_OPTION) != 0)
	{
		bMoreFlag = true;

		while(tvb_reported_length_remaining(tvb, offset) > 0 &&
		      (hdr_byte = tvb_get_uint8(tvb, offset)) != 0 && bMoreFlag)
		{
			/* get flags and type... */
			bMoreFlag= (hdr_byte & BSCVLC_HEADER_OPTION_MORE_OPTIONS);
			bDataFlag= (hdr_byte & BSCVLC_HEADER_OPTION_DATA);
			start = offset;

			offset++;

			if(bDataFlag)
			{
				npdu_length = (int)(tvb_get_uint8(tvb, offset++) << 8);
				npdu_length += (int)tvb_get_uint8(tvb, offset++);
				offset += npdu_length;
			}

			subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, start, offset - start,
	                                ett_bscvlc_hdr, NULL, "%s", "Destination Options");
			proto_tree_add_bitmask_value(subtree, tvb, start, hf_bscvlc_header,
				ett_bscvlc_hdr, bscvlc_header_flags, hdr_byte);

			if(bDataFlag)
			{
				proto_tree_add_item(subtree, hf_bscvlc_header_length, tvb, start + 1, 2, ENC_NA);
				proto_tree_add_item(subtree, hf_bscvlc_header_data, tvb, start + 3, npdu_length, ENC_NA);
			}
		}
	}

	if ((bvlc_control & BSCVLC_CONTROL_DATA_OPTION) != 0)
	{
		bMoreFlag = true;

		while(tvb_reported_length_remaining(tvb, offset) > 0 &&
		      (hdr_byte = tvb_get_uint8(tvb, offset)) != 0 && bMoreFlag)
		{
			/* get flags and type... */
			bMoreFlag= (hdr_byte & BSCVLC_HEADER_OPTION_MORE_OPTIONS);
			bDataFlag= (hdr_byte & BSCVLC_HEADER_OPTION_DATA);
			start = offset;

			offset++;

			if(bDataFlag)
			{
				npdu_length = (int)(tvb_get_uint8(tvb, offset++) << 8);
				npdu_length += (int)tvb_get_uint8(tvb, offset++);
				offset += npdu_length;
			}

			subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, start, offset - start,
	                                ett_bscvlc_hdr, NULL, "%s", "Data Options");
			proto_tree_add_bitmask_value(subtree, tvb, start, hf_bscvlc_header,
				ett_bscvlc_hdr, bscvlc_header_flags, hdr_byte);

			if(bDataFlag)
			{
				proto_tree_add_item(subtree, hf_bscvlc_header_length, tvb, start + 1, 2, ENC_NA);
				proto_tree_add_item(subtree, hf_bscvlc_header_data, tvb, start + 3, npdu_length, ENC_NA);
			}
		}
	}

	switch (bvlc_function)
	{
	case 0x02: /* Address-Resolution */
	case 0x05: /* Advertisement-Solicitation */
	case 0x08: /* Disconnect-Request */
	case 0x09: /* Disconnect-ACK */
	case 0x0A: /* Heartbeat-Request */
	case 0x0B: /* Heartbeat-ACK */
		break;
	case 0x00: /* BVLC-Result */
		subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, offset, packet_length - offset,
	                        ett_bscvlc_hdr, NULL, "%s", "BVLC-Result");
		proto_tree_add_item(subtree, hf_bscvlc_function, tvb,
				offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(subtree, hf_bscvlc_result, tvb,
				offset, 1, ENC_NA);
		bvlc_result = tvb_get_uint8(tvb, offset);
		offset++;

		col_append_fstr(pinfo->cinfo, COL_INFO, " %s",
                    val_to_str_const(bvlc_result, bscvlc_result_names, "unknown"));

		if(bvlc_result)
		{
			proto_tree_add_item(subtree, hf_bscvlc_header_marker, tvb,
					offset, 1, ENC_NA);
			offset++;
			proto_tree_add_item(subtree, hf_bscvlc_error_class, tvb,
					offset, 2, ENC_NA);
			offset += 2;
			proto_tree_add_item(subtree, hf_bscvlc_error_code, tvb,
					offset, 2, ENC_NA);
			offset += 2;
			proto_tree_add_item(subtree, hf_bscvlc_result_data, tvb,
					offset, packet_length - offset, ENC_NA);
		}
		/* Force and of packet */
		offset = packet_length;
		break;
	case 0x03: /* Address-Resolution-ACK */
		subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, offset, packet_length - offset,
	                        ett_bscvlc_hdr, NULL, "%s", "Address-Resolution-ACK");
		proto_tree_add_item(subtree, hf_bscvlc_uris, tvb,
				offset, packet_length - offset, ENC_NA);
		/* Force and of packet */
		offset = packet_length;
		break;
	case 0x04: /* Advertisement */
		subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, offset, packet_length - offset,
	                        ett_bscvlc_hdr, NULL, "%s", "Advertisement");
		proto_tree_add_item(subtree, hf_bscvlc_hub_conn_state, tvb,
				offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(subtree, hf_bscvlc_accept_conns, tvb,
				offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(subtree, hf_bscvlc_max_bvlc_length, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(subtree, hf_bscvlc_max_npdu_length, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		break;
	case 0x06: /* Connect-Request */
		subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, offset, packet_length - offset,
	                        ett_bscvlc_hdr, NULL, "%s", "Connect-Request");
		proto_tree_add_item(subtree, hf_bscvlc_connect_vmac, tvb,
				offset, 6, ENC_NA);
		offset += 6;
		proto_tree_add_item(subtree, hf_bscvlc_connect_uuid, tvb,
				offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(subtree, hf_bscvlc_max_bvlc_length, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(subtree, hf_bscvlc_max_npdu_length, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		break;
	case 0x07: /* Connect-Accept */
		subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, offset, packet_length - offset,
	                        ett_bscvlc_hdr, NULL, "%s", "Connect-Accept");
		proto_tree_add_item(subtree, hf_bscvlc_connect_vmac, tvb,
				offset, 6, ENC_NA);
		offset += 6;
		proto_tree_add_item(subtree, hf_bscvlc_connect_uuid, tvb,
				offset, 16, ENC_NA);
		offset += 16;
		proto_tree_add_item(subtree, hf_bscvlc_max_bvlc_length, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(subtree, hf_bscvlc_max_npdu_length, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		break;
	case 0x0C: /* Proprietary-Message */
		subtree = proto_tree_add_subtree_format(bvlc_tree, tvb, offset, packet_length - offset,
	                        ett_bscvlc_hdr, NULL, "%s", "Proprietary-Message");
		proto_tree_add_item(subtree, hf_bscvlc_vendor_id, tvb,
				offset, 2, ENC_NA);
		offset += 2;
		proto_tree_add_item(subtree, hf_bscvlc_proprietary_opt_type, tvb,
				offset, 1, ENC_NA);
		offset++;
		proto_tree_add_item(subtree, hf_bscvlc_proprietary_data, tvb,
				offset, packet_length - offset, ENC_NA);
		/* Force and of packet */
		offset = packet_length;
		break;
	case 0x01: /* Encapsulated-NPDU */
	default:
		/* Here we assume additional payload belongs to upper layers and will be decoded later */
		break;
	}

	/* Let the remaining frame to be decoded elsewhere */
	npdu_length = packet_length - offset;
	next_tvb = tvb_new_subset_length(tvb, offset, npdu_length);
	/* Code from Guy Harris */
	if (!dissector_try_uint(bscvlc_dissector_table,
		bvlc_function, next_tvb, pinfo, tree)) {
		/* Unknown function - dissect the payload as data */
		call_data_dissector(next_tvb, pinfo, tree);
	}

	return tvb_reported_length(tvb);
}

void
proto_register_bvlc(void)
{
	static hf_register_info hf[] = {
		{ &hf_bvlc_type,
			{ "Type",           "bvlc.type",
			FT_UINT8, BASE_HEX, VALS(bvlc_types), 0,
			NULL, HFILL }
		},
		{ &hf_bvlc_function,
			{ "Function",           "bvlc.function",
			FT_UINT8, BASE_HEX, VALS(bvlc_function_names), 0,
			"BVLC Function", HFILL }
		},
		{ &hf_bvlc_ipv6_function,
			{ "Function",           "bvlc.function_ipv6",
			FT_UINT8, BASE_HEX, VALS(bvlc_ipv6_function_names), 0,
			"BVLC Function IPV6", HFILL }
		},
		{ &hf_bvlc_length,
			{ "BVLC-Length",        "bvlc.length",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Length of BVLC", HFILL }
		},
		{ &hf_bvlc_virt_source,
			{ "BVLC-Virtual-Source", "bvlc.virtual_source",
			FT_UINT24, BASE_DEC_HEX, NULL, 0,
			"Virtual source address of BVLC", HFILL }
		},
		{ &hf_bvlc_virt_dest,
			{ "BVLC-Virtual-Destination", "bvlc.virtual_dest",
			FT_UINT24, BASE_DEC_HEX, NULL, 0,
			"Virtual destination address of BVLC", HFILL }
		},
		{ &hf_bvlc_result_ip4,
			{ "Result",           "bvlc.result",
			FT_UINT16, BASE_HEX, VALS(bvlc_result_names), 0,
			"Result Code", HFILL }
		},
		{ &hf_bvlc_result_ip6,
			{ "Result",           "bvlc.result",
			FT_UINT16, BASE_HEX, VALS(bvlc_ipv6_result_names), 0,
			"Result Code", HFILL }
		},
		{ &hf_bvlc_bdt_ip,
			{ "IP",           "bvlc.bdt_ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"BDT IP", HFILL }
		},
		{ &hf_bvlc_bdt_port,
			{ "Port",           "bvlc.bdt_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"BDT Port", HFILL }
		},
		{ &hf_bvlc_bdt_mask,
			{ "Mask",           "bvlc.bdt_mask",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BDT Broadcast Distribution Mask", HFILL }
		},
		{ &hf_bvlc_reg_ttl,
			{ "TTL",           "bvlc.reg_ttl",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Foreign Device Time To Live", HFILL }
		},
		{ &hf_bvlc_fdt_ip,
			{ "IP",           "bvlc.fdt_ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"FDT IP", HFILL }
		},
		{ &hf_bvlc_fdt_ipv6,
			{ "IP",           "bvlc.fdt_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0,
			"FDT IP", HFILL }
		},
		{ &hf_bvlc_fdt_port,
			{ "Port",           "bvlc.fdt_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"FDT Port", HFILL }
		},
		{ &hf_bvlc_fdt_ttl,
			{ "TTL",           "bvlc.fdt_ttl",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Foreign Device Time To Live", HFILL }
		},
		{ &hf_bvlc_fdt_timeout,
			{ "Timeout",           "bvlc.fdt_timeout",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Foreign Device Timeout (seconds)", HFILL }
		},
		{ &hf_bvlc_fwd_ip,
			{ "IP",           "bvlc.fwd_ip",
			FT_IPv4, BASE_NONE, NULL, 0,
			"FWD IP", HFILL }
		},
		{ &hf_bvlc_fwd_port,
			{ "Port",           "bvlc.fwd_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"FWD Port", HFILL }
		},
		{ &hf_bvlc_orig_source_addr,
			{ "IP",             "bvlc.orig_source_addr",
			FT_IPv6, BASE_NONE, NULL, 0,
			"ORIG IP", HFILL }
		},
		{ &hf_bvlc_orig_source_port,
			{ "Port",           "bvlc.orig_source_port",
			FT_UINT16, BASE_DEC, NULL, 0,
			"ORIG Port", HFILL }
		},
	};

	static int *ett[] = {
		&ett_bvlc,
		&ett_bdt,
		&ett_fdt,
	};

	static hf_register_info bsc_hf[] = {
		{ &hf_bscvlc_control,
			{ "Control",		"bscvlc.control",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BSCVLC Control", HFILL }
		},
		{ &hf_bscvlc_control_data_option,
			{ "Data Option",	"bscvlc.control_data_option",
			FT_BOOLEAN, 8, TFS(&control_data_option_set_high),
			BSCVLC_CONTROL_DATA_OPTION, "BSCVLC Control", HFILL }
		},
		{ &hf_bscvlc_control_destination_option,
			{ "Destination Option",	"bscvlc.control_dest_option",
			FT_BOOLEAN, 8, TFS(&control_destination_option_set_high),
			BSCVLC_CONTROL_DEST_OPTION, "BSCVLC Control", HFILL }
		},
		{ &hf_bscvlc_control_destination_address,
			{ "Destination Address","bscvlc.control_dest_address",
			FT_BOOLEAN, 8, TFS(&control_destination_address_set_high),
			BSCVLC_CONTROL_DEST_ADDRESS, "BSCVLC Control", HFILL }
		},
		{ &hf_bscvlc_control_origin_address,
			{ "Origin Address",	"bscvlc.control_orig_address",
			FT_BOOLEAN, 8, TFS(&control_orig_address_set_high),
			BSCVLC_CONTROL_ORIG_ADDRESS, "BSCVLC Control", HFILL }
		},
		{ &hf_bscvlc_control_reserved,
			{ "Reserved",	"bscvlc.control_reserved",
			FT_BOOLEAN, 8, TFS(&control_reserved_set_high),
			BSCVLC_CONTROL_RESERVED, "BSCVLC Control", HFILL }
		},
		{ &hf_bscvlc_header,
			{ "Header Data Length",	"bscvlc.header",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BSCVLC Header Control Data", HFILL }
		},
		{ &hf_bscvlc_header_marker,
			{ "Header Error Marker","bscvlc.header_error_marker",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BSCVLC Header Error Marker", HFILL }
		},
		{ &hf_bscvlc_header_length,
			{ "Header Data Length",	"bscvlc.header_length",
			FT_UINT16, BASE_DEC, NULL, 0,
			"BSCVLC Header Data Length", HFILL }
		},
		{ &hf_bscvlc_header_data,
			{ "Header Data",	"bscvlc.header_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BSCVLC Header Option", HFILL }
		},
		{ &hf_bscvlc_header_opt_type,
			{ "Header Type",	"bscvlc.header_type",
			FT_UINT8, BASE_HEX, VALS(bscvlc_header_type_names),
			BSCVLC_HEADER_OPTION_TYPE, "BSCVLC Header Option", HFILL }
		},
		{ &hf_bscvlc_header_opt_data,
			{ "Header Data",	"bscvlc.header_data_present",
			FT_BOOLEAN, 8, TFS(&header_opt_data_set_high),
			BSCVLC_HEADER_OPTION_DATA, "BSCVLC Header Option", HFILL }
		},
		{ &hf_bscvlc_header_opt_must_understand,
			{ "Header Must Understand","bscvlc.header_understand",
			FT_BOOLEAN, 8, TFS(&header_opt_must_understand_set_high),
			BSCVLC_HEADER_OPTION_MUST_UNDERSTAND, "BSCVLC Header Option", HFILL }
		},
		{ &hf_bscvlc_header_opt_more,
			{ "Header More",	"bscvlc.header_more",
			FT_BOOLEAN, 8, TFS(&header_opt_more_set_high),
			BSCVLC_HEADER_OPTION_MORE_OPTIONS, "BSCVLC Header Option", HFILL }
		},
		{ &hf_bscvlc_vendor_id,
			{ "Vendor ID",          "bscvlc.vendor_id",
			FT_UINT16, BASE_HEX, NULL, 0,
			"BSCVLC Vendor ID", HFILL }
		},
		{ &hf_bscvlc_proprietary_opt_type,
			{ "Proprietary Type",	"bscvlc.proprietary_type",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BSCVLC Proprietary Type", HFILL }
		},
		{ &hf_bscvlc_proprietary_data,
			{ "Proprietary Data",	"bscvlc.proprietary_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BSCVLC Proprietary Data", HFILL }
		},
		{ &hf_bscvlc_hub_conn_state,
			{ "Hub Connection Status","bscvlc.hub_conn_state",
			FT_UINT8, BASE_HEX, VALS(bscvlc_hub_conn_state_names), 0,
			"BSCVLC Hub Connection Status", HFILL }
		},
		{ &hf_bscvlc_accept_conns,
			{ "Hub Accepts Connections","bscvlc.accept_conns",
			FT_UINT8, BASE_HEX, VALS(bscvlc_hub_accept_conns_names), 0,
			"BSCVLC Accepts Connections", HFILL }
		},
		{ &hf_bscvlc_max_bvlc_length,
			{ "Max. BVLC Length",	"bscvlc.max_bvlc_length",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Max Supported BVLC Length", HFILL }
		},
		{ &hf_bscvlc_max_npdu_length,
			{ "Max. NPDU Length",	"bscvlc.max_npdu_length",
			FT_UINT16, BASE_DEC, NULL, 0,
			"Max Supported NPDU Length", HFILL }
		},
		{ &hf_bscvlc_function,
			{ "Function",           "bscvlc.function",
			FT_UINT8, BASE_HEX, VALS(bscvlc_function_names), 0,
			"BSCVLC Function", HFILL }
		},
		{ &hf_bscvlc_result,
			{ "Result",             "bscvlc.result",
			FT_UINT8, BASE_HEX, VALS(bscvlc_result_names), 0,
			"Result Code", HFILL }
		},
		{ &hf_bscvlc_error_class,
			{ "Error Class",	"bscvlc.error_class",
			FT_UINT32, BASE_DEC, VALS(BACnetErrorClass), 0, NULL, HFILL }
		},
		{ &hf_bscvlc_error_code,
			{ "Error Code",		"bscvlc.error_code",
			FT_UINT32, BASE_DEC, VALS(BACnetErrorCode), 0, NULL, HFILL }
		},
		{ &hf_bscvlc_result_data,
			{ "Result Data",	"bscvlc.result_data",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BSCVLC Result Data", HFILL }
		},
		{ &hf_bscvlc_uris,
			{ "URI's",		"bscvlc.uris",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BSCVLC Address URI's", HFILL }
		},
		{ &hf_bscvlc_msg_id,
			{ "Message ID",         "bscvlc.msgid",
			FT_UINT16, BASE_DEC, NULL, 0,
			"BSCVLC Message ID", HFILL }
		},
		{ &hf_bscvlc_orig_vmac,
			{ "SVMAC",              "bscvlc.orig_virtual_address",
			FT_BYTES, BASE_NONE, NULL, 0,
			"ORIG VMAC", HFILL }
		},
		{ &hf_bscvlc_dest_vmac,
			{ "DVMAC",              "bscvlc.dest_virtual_address",
			FT_BYTES, BASE_NONE, NULL, 0,
			"DEST VMAC", HFILL }
		},
		{ &hf_bscvlc_connect_vmac,
			{ "Connecting VMAC",	"bscvlc.connect_virtual_address",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BSCVLC Connecting VMAC", HFILL }
		},
		{ &hf_bscvlc_connect_uuid,
			{ "Connecting UUID",	"bscvlc.connect_uuid",
			FT_BYTES, BASE_NONE, NULL, 0,
			"BSCVLC Connecting UUID", HFILL }
		},
	};

	static int *bsc_ett[] = {
		&ett_bscvlc,
		&ett_bscvlc_ctrl,
		&ett_bscvlc_hdr
	};

	proto_bvlc = proto_register_protocol("BACnet Virtual Link Control", "BVLC", "bvlc");

	proto_register_field_array(proto_bvlc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	bvlc_handle = register_dissector("bvlc", dissect_bvlc, proto_bvlc);

	bvlc_dissector_table = register_dissector_table("bvlc.function", "BVLC Function", proto_bvlc, FT_UINT8, BASE_HEX);
	bvlc_ipv6_dissector_table = register_dissector_table("bvlc.function_ipv6", "BVLC Function IPV6", proto_bvlc, FT_UINT8, BASE_HEX);

	proto_bscvlc = proto_register_protocol("BACnet Secure Connect Virtual Link Control", "BSCVLC", "bscvlc");

	proto_register_field_array(proto_bscvlc, bsc_hf, array_length(bsc_hf));
	proto_register_subtree_array(bsc_ett, array_length(bsc_ett));

	bscvlc_handle = register_dissector("bscvlc", dissect_bscvlc, proto_bscvlc);

	bscvlc_dissector_table = register_dissector_table("bscvlc.function", "BSCVLC Function", proto_bscvlc, FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_bvlc(void)
{
	dissector_add_uint_with_preference("udp.port", BVLC_UDP_PORT, bvlc_handle);
	dissector_add_string("ws.protocol", "hub.bsc.bacnet.org", bscvlc_handle);
	dissector_add_string("ws.protocol", "dc.bsc.bacnet.org", bscvlc_handle);
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
