/* Shared EPP decoding for SAP Diag and classic RFC.
 * Callers retain their protocol-specific registered fields and expert info.
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef PACKET_SAPEPP_H
#define PACKET_SAPEPP_H

#define SAP_EPP_MAGIC 0x2a54482aU

typedef struct {
	int magic;
	int version;
	int length;
	int trace_flags;
	int component;
	int service;
	int user;
	int action;
	int action_type;
	int previous_component;
	int transaction_id;
	int client;
	int component_type;
	int root_context_id;
	int connection_id;
	int connection_counter;
	int variable_part_count;
	int variable_part_offset;
	int variable_part;
	int variable_part_length;
	int variable_part_last;
	int variable_part_id;
	int item_count;
	int item;
	int item_key;
	int item_application;
	int item_type;
	int item_length;
	int item_value;
	int trailer;
	int ett_variable_part;
	int ett_item;
	expert_field *malformed;
} sap_epp_fields_t;

extern const value_string sap_epp_version_vals[];
extern const value_string sap_epp_item_type_vals[];

uint16_t dissect_sap_epp(tvbuff_t *tvb, packet_info *pinfo, proto_item *item,
		proto_tree *tree, uint32_t offset, uint32_t item_length,
		const sap_epp_fields_t *fields);

#endif /* PACKET_SAPEPP_H */
