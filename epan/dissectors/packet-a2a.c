/* packet-a2a.c
 * Routines for Agent-to-Agent (A2A) protocol dissection,
 * detailed protocol reference: https://a2a-protocol.org/v1.0.0/specification/
 *
 * Copyright 2026, Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * A2A is carried inside JSON payloads (HTTP+JSON binding), so this dissector
 * registers as a heuristic dissector on the JSON sub-dissectors table.
 *
 * Notes:
 *
 * The JSON data is not parsed here: the JSON dissector hands over its parsed
 * form through the "data" argument, as a json_heur_data_t holding the jsmn
 * token array built for the JSON+ form (see packet-json.h). Token offsets are
 * relative to the start of the document, which is offset 0 of the tvbuff
 * passed to this dissector, so they are used directly as tvbuff offsets.
 *
 * The message types and field names follow the A2A protobuf definitions.
 * Heuristic logic is based on required field presence and enums values.
 *
 * Some property exists in both camelCase (extendedAgentCard) and
 * underscore_case (extended_agent_card) form in the proto to JSON mapping,
 * so both flavorus are accepted; enums are accepted both as their name
 * and as their number.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <wsutil/nstime.h>
#include <wsutil/strtoi.h>

#include "packet-json.h"

void proto_register_a2a(void);
void proto_reg_handoff_a2a(void);

static int proto_a2a;

static int hf_a2a_type;
static int hf_a2a_message_id;
static int hf_a2a_context_id;
static int hf_a2a_task_id;
static int hf_a2a_role;
static int hf_a2a_part_text;
static int hf_a2a_part_raw;
static int hf_a2a_part_url;
static int hf_a2a_part_filename;
static int hf_a2a_part_media_type;
static int hf_a2a_task_state;
static int hf_a2a_task_timestamp;
static int hf_a2a_task_count;
static int hf_a2a_artifact_id;
static int hf_a2a_artifact_name;
static int hf_a2a_artifact_description;
static int hf_a2a_agent_name;
static int hf_a2a_agent_version;
static int hf_a2a_agent_description;
static int hf_a2a_skill_id;
static int hf_a2a_skill_name;
static int hf_a2a_protocol_binding;
static int hf_a2a_protocol_version;
static int hf_a2a_interface_url;
static int hf_a2a_provider_organization;
static int hf_a2a_provider_url;
static int hf_a2a_cap_streaming;
static int hf_a2a_cap_push_notifications;
static int hf_a2a_cap_extended_agent_card;
static int hf_a2a_accepted_output_mode;
static int hf_a2a_return_immediately;
static int hf_a2a_history_length;
static int hf_a2a_push_config_id;
static int hf_a2a_push_config_url;
static int hf_a2a_push_config_token;
static int hf_a2a_auth_scheme;
static int hf_a2a_auth_credentials;
static int hf_a2a_next_page_token;
static int hf_a2a_page_size;
static int hf_a2a_tenant;
static int hf_a2a_metadata;
static int hf_a2a_part_data;
static int hf_a2a_extension;
static int hf_a2a_reference_task_id;
static int hf_a2a_append;
static int hf_a2a_last_chunk;
static int hf_a2a_input_mode;
static int hf_a2a_output_mode;
static int hf_a2a_skill_description;
static int hf_a2a_skill_tag;
static int hf_a2a_skill_example;
static int hf_a2a_agent_extension_uri;
static int hf_a2a_agent_extension_required;
static int hf_a2a_signature;

static expert_field ei_a2a_invalid_structure;

static int ett_a2a;
static int ett_a2a_message;
static int ett_a2a_task;
static int ett_a2a_part;
static int ett_a2a_artifact;
static int ett_a2a_agent_card;
static int ett_a2a_configuration;
static int ett_a2a_push_config;

typedef enum {
	A2A_TYPE_NONE = 0,
	A2A_TYPE_SEND_MESSAGE_REQUEST,
	A2A_TYPE_SEND_MESSAGE_RESPONSE,
	A2A_TYPE_STREAM_RESPONSE,
	A2A_TYPE_TASK,
	A2A_TYPE_TASK_STATUS_UPDATE,
	A2A_TYPE_TASK_ARTIFACT_UPDATE,
	A2A_TYPE_LIST_TASKS_RESPONSE,
	A2A_TYPE_MESSAGE,
	A2A_TYPE_AGENT_CARD,
	A2A_TYPE_PUSH_CONFIG,
	A2A_TYPE_LIST_PUSH_CONFIGS_RESPONSE
} a2a_type_t;

static const value_string a2a_type_names[] = {
	{ A2A_TYPE_SEND_MESSAGE_REQUEST,  "SendMessageRequest" },
	{ A2A_TYPE_SEND_MESSAGE_RESPONSE, "SendMessageResponse" },
	{ A2A_TYPE_STREAM_RESPONSE,       "StreamResponse" },
	{ A2A_TYPE_TASK,                  "Task" },
	{ A2A_TYPE_TASK_STATUS_UPDATE,    "TaskStatusUpdateEvent" },
	{ A2A_TYPE_TASK_ARTIFACT_UPDATE,  "TaskArtifactUpdateEvent" },
	{ A2A_TYPE_LIST_TASKS_RESPONSE,   "ListTasksResponse" },
	{ A2A_TYPE_MESSAGE,               "Message" },
	{ A2A_TYPE_AGENT_CARD,            "AgentCard" },
	{ A2A_TYPE_PUSH_CONFIG,           "TaskPushNotificationConfig" },
	{ A2A_TYPE_LIST_PUSH_CONFIGS_RESPONSE, "ListTaskPushNotificationConfigsResponse" },
	{ 0, NULL }
};

/* ROLE_USER is the client, ROLE_AGENT the server */
typedef enum {
	A2A_ROLE_UNSPECIFIED = 0,
	A2A_ROLE_USER = 1,
	A2A_ROLE_AGENT = 2
} a2a_role_t;

/* In the proto 2 JSON mapping an enum value is serialized either as a name
 * or as a number, so both forms are accepted and normalized to the name. */
static const value_string a2a_role_vals[] = {
	{ A2A_ROLE_UNSPECIFIED, "ROLE_UNSPECIFIED" },
	{ A2A_ROLE_USER,        "ROLE_USER" },
	{ A2A_ROLE_AGENT,       "ROLE_AGENT" },
	{ 0, NULL }
};

static const value_string a2a_task_state_vals[] = {
	{ 0, "TASK_STATE_UNSPECIFIED" },
	{ 1, "TASK_STATE_SUBMITTED" },
	{ 2, "TASK_STATE_WORKING" },
	{ 3, "TASK_STATE_COMPLETED" },
	{ 4, "TASK_STATE_FAILED" },
	{ 5, "TASK_STATE_CANCELED" },
	{ 6, "TASK_STATE_INPUT_REQUIRED" },
	{ 7, "TASK_STATE_REJECTED" },
	{ 8, "TASK_STATE_AUTH_REQUIRED" },
	{ 0, NULL }
};

/* JSON data and its tokens, as received from the JSON dissector. */
typedef struct {
	const char *buf;
	jsmntok_t *tokens;
	int num_tokens;
} a2a_json_t;

static bool
a2a_tok_streq(const a2a_json_t *json, int idx, const char *str)
{
	size_t str_len = strlen(str);
	int tok_len = json->tokens[idx].end - json->tokens[idx].start;

	return (tok_len >= 0 && (size_t)tok_len == str_len &&
		strncmp(json->buf + json->tokens[idx].start, str, str_len) == 0);
}

static bool
a2a_tok_has_prefix(const a2a_json_t *json, int idx, const char *prefix)
{
	size_t prefix_len = strlen(prefix);
	int tok_len = json->tokens[idx].end - json->tokens[idx].start;

	return (tok_len >= 0 && (size_t)tok_len >= prefix_len &&
		strncmp(json->buf + json->tokens[idx].start, prefix, prefix_len) == 0);
}

/* returns a NULL terminated copy of a token's text */
static char *
a2a_tok_strdup(wmem_allocator_t *scope, const a2a_json_t *json, int idx)
{
	int len = json->tokens[idx].end - json->tokens[idx].start;

	return wmem_strndup(scope, json->buf + json->tokens[idx].start, (size_t)MAX(len, 0));
}

static const char *
a2a_enum_string(wmem_allocator_t *scope, const a2a_json_t *json, int idx,
		const value_string *vs, bool *known)
{
	const char *str;
	uint32_t num;

	*known = false;

	if (idx < 0) {
		return NULL;
	}

	if (json->tokens[idx].type == JSMN_STRING) {
		str = a2a_tok_strdup(scope, json, idx);

		for (const value_string *v = vs; v->strptr != NULL; v++) {
			if (strcmp(str, v->strptr) == 0) {
				*known = true;
				break;
			}
		}
		return str;
	}

	if (json->tokens[idx].type != JSMN_PRIMITIVE) {
		return NULL;
	}

	if (!ws_strtou32(a2a_tok_strdup(scope, json, idx), NULL, &num)) {
		return NULL;
	}

	str = try_val_to_str(num, vs);
	if (str != NULL) {
		*known = true;
		return str;
	}

	return wmem_strdup_printf(scope, "Unknown (%u)", num);
}

/* given a JSON object return the index of the token holding the value "name" or "alt_name"
 * If not found -1.
 */
static int
a2a_field(const a2a_json_t *json, int obj_idx, const char *name, const char *alt_name)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return -1;
	}

	for (int i = obj_idx + 1; i < json->num_tokens - 1 &&
	     json->tokens[i].start < json->tokens[obj_idx].end; i++) {
		if (json->tokens[i].parent != obj_idx ||
		    json->tokens[i].type != JSMN_STRING ||
		    json->tokens[i].size != 1) {
			continue;
		}

		if (a2a_tok_streq(json, i, name) ||
		    (alt_name != NULL && a2a_tok_streq(json, i, alt_name))) {
			return i + 1;
		}
	}

	return -1;
}

/* like a2a_field(), but only returns the member when the value has the expected type */
static int
a2a_field_of_type(const a2a_json_t *json, int obj_idx, const char *name, const char *alt_name,
		  jsmntype_t type)
{
	int idx = a2a_field(json, obj_idx, name, alt_name);

	if (idx < 0 || json->tokens[idx].type != type) {
		return -1;
	}

	return idx;
}

/* returns the index of the first element of the array at array_idx (-1 if
 * empty array). Elements are the tokens whose parent is the array
 * (see wsutils/jsmn). */
static int
a2a_array_first(const a2a_json_t *json, int array_idx)
{
	if (array_idx < 0 || json->tokens[array_idx].type != JSMN_ARRAY) {
		return -1;
	}

	for (int i = array_idx + 1; i < json->num_tokens &&
	     json->tokens[i].start < json->tokens[array_idx].end; i++) {
		if (json->tokens[i].parent == array_idx) {
			return i;
		}
	}

	return -1;
}

/* returns index of the next array element following elem_idx, or -1. */
static int
a2a_array_next(const a2a_json_t *json, int array_idx, int elem_idx)
{
	if (array_idx < 0) {
		return -1;
	}

	for (int i = elem_idx + 1; i < json->num_tokens &&
	     json->tokens[i].start < json->tokens[array_idx].end; i++) {
		if (json->tokens[i].parent == array_idx) {
			return i;
		}
	}

	return -1;
}

/* parse a primitive token as an unsigned number */
static bool
ws_strtou32_no_alloc(const a2a_json_t *json, int idx, uint32_t *value)
{
	char buf[12];
	int len = json->tokens[idx].end - json->tokens[idx].start;

	if (len <= 0 || len >= (int)sizeof(buf)) {
		return false;
	}

	memcpy(buf, json->buf + json->tokens[idx].start, (size_t)len);
	buf[len] = '\0';

	return ws_strtou32(buf, NULL, value);
}

/* return true if obj have a member of the given JSON type */
static bool
a2a_has(const a2a_json_t *json, int obj_idx, const char *name, const char *alt_name, jsmntype_t type)
{
	return (a2a_field_of_type(json, obj_idx, name, alt_name, type) >= 0);
}

/* return true if object has a member holding a value of the given enum. A name is accepted
 * based on prefix */
static bool
a2a_has_enum(const a2a_json_t *json, int obj_idx, const char *name, const char *prefix,
	     const value_string *vs)
{
	int idx = a2a_field(json, obj_idx, name, NULL);
	uint32_t num;

	if (idx < 0) {
		return false;
	}

	if (json->tokens[idx].type == JSMN_STRING) {
		return a2a_tok_has_prefix(json, idx, prefix);
	}

	if (json->tokens[idx].type != JSMN_PRIMITIVE) {
		return false;
	}

	return (ws_strtou32_no_alloc(json, idx, &num) &&
		try_val_to_str(num, vs) != NULL);
}

/* TaskStatus */
static bool
a2a_is_status(const a2a_json_t *json, int obj_idx)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	return a2a_has_enum(json, obj_idx, "state", "TASK_STATE_", a2a_task_state_vals);
}

/* Message */
static bool
a2a_is_message(const a2a_json_t *json, int obj_idx)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	if (!a2a_has(json, obj_idx, "message_id", "messageId", JSMN_STRING) ||
	    !a2a_has_enum(json, obj_idx, "role", "ROLE_", a2a_role_vals)) {
		return false;
	}

	/* When present it must be the array the schema says. */
	return (a2a_field(json, obj_idx, "parts", NULL) < 0 ||
		a2a_has(json, obj_idx, "parts", NULL, JSMN_ARRAY));
}

/* Task */
static bool
a2a_is_task(const a2a_json_t *json, int obj_idx)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	return (a2a_has(json, obj_idx, "id", NULL, JSMN_STRING) &&
		a2a_is_status(json, a2a_field(json, obj_idx, "status", NULL)));
}

/* Artifact */
static bool
a2a_is_artifact(const a2a_json_t *json, int obj_idx)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	if (!a2a_has(json, obj_idx, "artifact_id", "artifactId", JSMN_STRING)) {
		return false;
	}

	return (a2a_field(json, obj_idx, "parts", NULL) < 0 ||
		a2a_has(json, obj_idx, "parts", NULL, JSMN_ARRAY));
}

/* TaskStatusUpdateEvent */
static bool
a2a_is_status_event(const a2a_json_t *json, int obj_idx)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	return (a2a_has(json, obj_idx, "task_id", "taskId", JSMN_STRING) &&
		a2a_has(json, obj_idx, "context_id", "contextId", JSMN_STRING) &&
		a2a_is_status(json, a2a_field(json, obj_idx, "status", NULL)));
}

/* TaskArtifactUpdateEvent */
static bool
a2a_is_artifact_event(const a2a_json_t *json, int obj_idx)
{
	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	return (a2a_has(json, obj_idx, "task_id", "taskId", JSMN_STRING) &&
		a2a_has(json, obj_idx, "context_id", "contextId", JSMN_STRING) &&
		a2a_is_artifact(json, a2a_field(json, obj_idx, "artifact", NULL)));
}

/* TaskPushNotificationConfig */
static bool
a2a_is_push_config(const a2a_json_t *json, int obj_idx)
{
	int auth_idx;

	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	if (!a2a_has(json, obj_idx, "url", NULL, JSMN_STRING)) {
		return false;
	}

	auth_idx = a2a_field_of_type(json, obj_idx, "authentication", NULL, JSMN_OBJECT);

	return (a2a_has(json, obj_idx, "task_id", "taskId", JSMN_STRING) ||
		(auth_idx >= 0 && a2a_has(json, auth_idx, "scheme", NULL, JSMN_STRING)));
}

/* AgentCard */
static bool
a2a_is_agent_card(const a2a_json_t *json, int obj_idx)
{
	unsigned collections = 0;

	if (obj_idx < 0 || json->tokens[obj_idx].type != JSMN_OBJECT) {
		return false;
	}

	if (!a2a_has(json, obj_idx, "name", NULL, JSMN_STRING) ||
	    !a2a_has(json, obj_idx, "description", NULL, JSMN_STRING) ||
	    !a2a_has(json, obj_idx, "version", NULL, JSMN_STRING)) {
		return false;
	}

	if (a2a_has(json, obj_idx, "capabilities", NULL, JSMN_OBJECT)) {
		collections++;
	}
	if (a2a_has(json, obj_idx, "supported_interfaces", "supportedInterfaces",
		    JSMN_ARRAY)) {
		collections++;
	}
	if (a2a_has(json, obj_idx, "default_input_modes", "defaultInputModes",
		    JSMN_ARRAY)) {
		collections++;
	}
	if (a2a_has(json, obj_idx, "default_output_modes", "defaultOutputModes",
		    JSMN_ARRAY)) {
		collections++;
	}
	if (a2a_has(json, obj_idx, "skills", NULL, JSMN_ARRAY)) {
		collections++;
	}

	return (collections >= 2);
}

/* return the "message" object of a request/response */
static int
a2a_message_field(const a2a_json_t *json, int obj_idx)
{
	return a2a_field_of_type(json, obj_idx, "message", NULL, JSMN_OBJECT);
}

/* true when the Message at obj_idx has ROLE_AGENT (name or number format)
 * i.e. this is a response, request otherwise */
static bool
a2a_is_agent_message(const a2a_json_t *json, int obj_idx)
{
	int idx = a2a_field(json, obj_idx, "role", NULL);
	uint32_t num;

	if (idx < 0) {
		return false;
	}

	if (json->tokens[idx].type == JSMN_STRING) {
		return a2a_tok_streq(json, idx, "ROLE_AGENT");
	}

	if (json->tokens[idx].type != JSMN_PRIMITIVE) {
		return false;
	}

	return (ws_strtou32_no_alloc(json, idx, &num) && num == A2A_ROLE_AGENT);
}

/*
 * classify the JSON payload, by looking for the required fields of each
 * message type. Returns A2A_TYPE_NONE when the document is not recognized
 */
static a2a_type_t
a2a_identify(const a2a_json_t *json)
{
	int task_idx, msg_idx, tasks_idx, configs_idx;

	if (json->tokens[0].type != JSMN_OBJECT) {
		return A2A_TYPE_NONE;
	}

	/* StreamResponse is a oneof; only the update fields discriminate
	 * from a SendMessageResponse */
	if (a2a_is_status_event(json, a2a_field(json, 0, "status_update", "statusUpdate")) ||
	    a2a_is_artifact_event(json, a2a_field(json, 0, "artifact_update", "artifactUpdate"))) {
		return A2A_TYPE_STREAM_RESPONSE;
	}

	/* update events sent on their own. */
	if (a2a_is_status_event(json, 0)) {
		return A2A_TYPE_TASK_STATUS_UPDATE;
	}

	if (a2a_is_artifact_event(json, 0)) {
		return A2A_TYPE_TASK_ARTIFACT_UPDATE;
	}

	/* ListTasksResponse: tasks required or pagination fields */
	tasks_idx = a2a_field_of_type(json, 0, "tasks", NULL, JSMN_ARRAY);
	if (tasks_idx >= 0) {
		int first = a2a_array_first(json, tasks_idx);

		if (first >= 0 && a2a_is_task(json, first)) {
			return A2A_TYPE_LIST_TASKS_RESPONSE;
		}

		if (first < 0 &&
		    (a2a_field(json, 0, "total_size", "totalSize") >= 0 ||
		     a2a_field(json, 0, "next_page_token", "nextPageToken") >= 0 ||
		     a2a_field(json, 0, "page_size", "pageSize") >= 0)) {
			return A2A_TYPE_LIST_TASKS_RESPONSE;
		}
	}

	/* ListTaskPushNotificationConfigsResponse: configs holding the
	 * configurations, next_page_token for an empty list */
	configs_idx = a2a_field_of_type(json, 0, "configs", NULL, JSMN_ARRAY);
	if (configs_idx >= 0 &&
	    (a2a_field(json, 0, "next_page_token", "nextPageToken") >= 0 ||
	     a2a_is_push_config(json, a2a_array_first(json, configs_idx)))) {
		return A2A_TYPE_LIST_PUSH_CONFIGS_RESPONSE;
	}

	/* SendMessageRequest: message required; SendMessageResponse is a
	 * oneof of a Task and a Message. In the Message branch the two only
	 * differ by who sent the Message: the client in a request, the agent
	 * in a response. */
	task_idx = a2a_field(json, 0, "task", NULL);
	msg_idx = a2a_message_field(json, 0);

	if (a2a_is_task(json, task_idx)) {
		return A2A_TYPE_SEND_MESSAGE_RESPONSE;
	}

	if (a2a_is_message(json, msg_idx)) {
		return a2a_is_agent_message(json, msg_idx) ?
			A2A_TYPE_SEND_MESSAGE_RESPONSE : A2A_TYPE_SEND_MESSAGE_REQUEST;
	}

	/* a bare Task, as returned by GetTask */
	if (a2a_is_task(json, 0)) {
		return A2A_TYPE_TASK;
	}

	/* a bare Message */
	if (a2a_is_message(json, 0)) {
		return A2A_TYPE_MESSAGE;
	}

	if (a2a_is_agent_card(json, 0)) {
		return A2A_TYPE_AGENT_CARD;
	}

	/* the body of a push notification config */
	if (a2a_is_push_config(json, 0)) {
		return A2A_TYPE_PUSH_CONFIG;
	}

	return A2A_TYPE_NONE;
}

/* add the value of a JSON token as hf */
static proto_item *
a2a_add_token(proto_tree *tree, int hf, tvbuff_t *tvb, const a2a_json_t *json, int idx)
{
	return proto_tree_add_item(tree, hf, tvb, json->tokens[idx].start,
				   json->tokens[idx].end - json->tokens[idx].start, ENC_UTF_8);
}

/* add a string field with an explicit value, covering the bytes of a token. */
static proto_item *
a2a_add_string(proto_tree *tree, int hf, tvbuff_t *tvb, const a2a_json_t *json, int idx,
	       const char *value)
{
	return proto_tree_add_string(tree, hf, tvb, json->tokens[idx].start,
				     json->tokens[idx].end - json->tokens[idx].start, value);
}

/* add a message field indexed by obj_idx as hf, if present. */
static proto_item *
a2a_add_field(proto_tree *tree, int hf, tvbuff_t *tvb, const a2a_json_t *json,
	      int obj_idx, const char *name, const char *alt_name)
{
	int idx = a2a_field(json, obj_idx, name, alt_name);

	if (idx < 0) {
		return NULL;
	}

	return a2a_add_token(tree, hf, tvb, json, idx);
}

/* add enum as hf holding the enum value name, whichever form
 * the JSON used (string/int). Returns the name to be used in info column */
static const char *
a2a_add_enum(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo,
	     const a2a_json_t *json, int obj_idx, const char *name,
	     const value_string *vs)
{
	int idx = a2a_field(json, obj_idx, name, NULL);
	bool known;
	const char *value = a2a_enum_string(pinfo->pool, json, idx, vs, &known);
	proto_item *item;

	if (value == NULL) {
		return NULL;
	}

	item = a2a_add_string(tree, hf, tvb, json, idx, value);

	if (!known) {
		expert_add_info_format(pinfo, item, &ei_a2a_invalid_structure,
				       "\"%s\" is not a value of the enum: %s", name, value);
	}

	return value;
}

/* add a boolean filed as hf, if present. */
static void
a2a_add_bool(proto_tree *tree, int hf, tvbuff_t *tvb, const a2a_json_t *json,
	     int obj_idx, const char *name, const char *alt_name)
{
	int idx = a2a_field_of_type(json, obj_idx, name, alt_name, JSMN_PRIMITIVE);

	if (idx < 0) {
		return;
	}

	if (a2a_tok_streq(json, idx, "true") || a2a_tok_streq(json, idx, "false")) {
		proto_tree_add_boolean(tree, hf, tvb, json->tokens[idx].start,
				       json->tokens[idx].end - json->tokens[idx].start,
				       a2a_tok_streq(json, idx, "true"));
	}
}

/* add a JSON number as an unsigned hf */
static void
a2a_add_uint(proto_tree *tree, int hf, tvbuff_t *tvb, packet_info *pinfo,
	     const a2a_json_t *json, int obj_idx, const char *name,
	     const char *alt_name)
{
	int idx = a2a_field(json, obj_idx, name, alt_name);
	uint32_t value;

	if (idx < 0 || (json->tokens[idx].type != JSMN_PRIMITIVE &&
			json->tokens[idx].type != JSMN_STRING)) {
		return;
	}

	if (ws_strtou32(a2a_tok_strdup(pinfo->pool, json, idx), NULL, &value)) {
		proto_tree_add_uint(tree, hf, tvb, json->tokens[idx].start,
				    json->tokens[idx].end - json->tokens[idx].start, value);
	}
}

/* add any JSON type as an hf holding its raw text. Used for metadata and
 * Part.data, whose contents the protocol does not define. */
static void
a2a_add_raw(proto_tree *tree, int hf, tvbuff_t *tvb, const a2a_json_t *json,
	    int obj_idx, const char *name, const char *alt_name)
{
	int idx = a2a_field(json, obj_idx, name, alt_name);

	if (idx >= 0) {
		a2a_add_token(tree, hf, tvb, json, idx);
	}
}

/* add every element of an array of strings as hf */
static void
a2a_add_string_array(proto_tree *tree, int hf, tvbuff_t *tvb, const a2a_json_t *json,
		     int array_idx)
{
	int elem;

	for (elem = a2a_array_first(json, array_idx); elem >= 0;
	     elem = a2a_array_next(json, array_idx, elem)) {
		if (json->tokens[elem].type == JSMN_STRING) {
			a2a_add_token(tree, hf, tvb, json, elem);
		}
	}
}

static void
a2a_dissect_parts(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		  const a2a_json_t *json, int parts_idx)
{
	int elem;

	for (elem = a2a_array_first(json, parts_idx); elem >= 0;
	     elem = a2a_array_next(json, parts_idx, elem)) {
		proto_tree *part_tree;
		int text_idx;

		if (json->tokens[elem].type != JSMN_OBJECT) {
			continue;
		}

		part_tree = proto_tree_add_subtree(tree, tvb, json->tokens[elem].start,
						   json->tokens[elem].end - json->tokens[elem].start,
						   ett_a2a_part,
						   NULL, "Part");

		text_idx = a2a_field(json, elem, "text", NULL);
		if (text_idx >= 0) {
			a2a_add_token(part_tree, hf_a2a_part_text, tvb, json, text_idx);
			proto_item_append_text(part_tree, ": %s",
					       a2a_tok_strdup(pinfo->pool, json, text_idx));
		}

		/* Part.content is a oneof: text, raw, url or data. "raw" carries
		 * base64 encoded bytes in JSON mapping */
		a2a_add_field(part_tree, hf_a2a_part_raw, tvb, json, elem, "raw", NULL);
		a2a_add_field(part_tree, hf_a2a_part_url, tvb, json, elem, "url", NULL);
		a2a_add_field(part_tree, hf_a2a_part_filename, tvb, json, elem, "filename", NULL);
		a2a_add_raw(part_tree, hf_a2a_part_data, tvb, json, elem, "data", NULL);
		a2a_add_field(part_tree, hf_a2a_part_media_type, tvb, json, elem, "media_type", "mediaType");
		a2a_add_raw(part_tree, hf_a2a_metadata, tvb, json, elem, "metadata", NULL);
	}
}

/* Dissect a Message into the given tree */
static void
a2a_dissect_message(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		    const a2a_json_t *json, int msg_idx, const char *label)
{
	proto_tree *msg_tree;
	const char *role;
	int parts_idx;

	if (msg_idx < 0 || json->tokens[msg_idx].type != JSMN_OBJECT) {
		return;
	}

	msg_tree = proto_tree_add_subtree(tree, tvb, json->tokens[msg_idx].start,
					  json->tokens[msg_idx].end - json->tokens[msg_idx].start,
					  ett_a2a_message,
					  NULL, label);

	role = a2a_add_enum(msg_tree, hf_a2a_role, tvb, pinfo, json, msg_idx,
			    "role", a2a_role_vals);
	if (role != NULL) {
		proto_item_append_text(msg_tree, " (%s)", role);
	}

	a2a_add_field(msg_tree, hf_a2a_message_id, tvb, json, msg_idx, "message_id", "messageId");
	a2a_add_field(msg_tree, hf_a2a_context_id, tvb, json, msg_idx, "context_id", "contextId");
	a2a_add_field(msg_tree, hf_a2a_task_id, tvb, json, msg_idx, "task_id", "taskId");

	parts_idx = a2a_field_of_type(json, msg_idx, "parts", NULL, JSMN_ARRAY);
	if (parts_idx >= 0) {
		a2a_dissect_parts(msg_tree, tvb, pinfo, json, parts_idx);
	}

	a2a_add_string_array(msg_tree, hf_a2a_extension, tvb, json,
			     a2a_field_of_type(json, msg_idx, "extensions", NULL, JSMN_ARRAY));
	a2a_add_string_array(msg_tree, hf_a2a_reference_task_id, tvb, json,
			     a2a_field_of_type(json, msg_idx,
					       "reference_task_ids",
					       "referenceTaskIds", JSMN_ARRAY));
	a2a_add_raw(msg_tree, hf_a2a_metadata, tvb, json, msg_idx, "metadata", NULL);
}

/* Dissect a TaskStatus into the given tree. Returns the task state, or NULL,
 * so that callers can use it for the info column (TaskStatus may carry
 * the Message that describes the state change */
static const char *
a2a_dissect_status(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		   const a2a_json_t *json, int status_idx)
{
	const char *state;
	int ts_idx;

	if (status_idx < 0 || json->tokens[status_idx].type != JSMN_OBJECT) {
		return NULL;
	}

	state = a2a_add_enum(tree, hf_a2a_task_state, tvb, pinfo, json, status_idx,
			     "state", a2a_task_state_vals);

	a2a_dissect_message(tree, tvb, pinfo, json,
			    a2a_field_of_type(json, status_idx, "message", NULL, JSMN_OBJECT),
			    "Status message");

	ts_idx = a2a_field_of_type(json, status_idx, "timestamp", NULL, JSMN_STRING);
	if (ts_idx >= 0) {
		/* TaskStatus.timestamp is a protobuf Timestamp, serialized as an
		 * RFC 3339 string. */
		char *value = a2a_tok_strdup(pinfo->pool, json, ts_idx);
		nstime_t ts;

		if (iso8601_to_nstime(&ts, value, ISO8601_DATETIME_AUTO) != NULL) {
			proto_tree_add_time(tree, hf_a2a_task_timestamp, tvb,
					    json->tokens[ts_idx].start,
					    json->tokens[ts_idx].end - json->tokens[ts_idx].start, &ts);
		} else {
			proto_tree_add_expert_format(tree, pinfo, &ei_a2a_invalid_structure,
						     tvb, json->tokens[ts_idx].start,
						     json->tokens[ts_idx].end - json->tokens[ts_idx].start,
						     "\"timestamp\" is not an RFC 3339 date-time: %s", value);
		}
	}

	return state;
}

static void
a2a_dissect_artifact(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		     const a2a_json_t *json, int art_idx)
{
	proto_tree *art_tree;
	int name_idx, parts_idx;

	if (art_idx < 0 || json->tokens[art_idx].type != JSMN_OBJECT) {
		return;
	}

	art_tree = proto_tree_add_subtree(tree, tvb, json->tokens[art_idx].start,
					  json->tokens[art_idx].end - json->tokens[art_idx].start,
					  ett_a2a_artifact, NULL, "Artifact");

	name_idx = a2a_field(json, art_idx, "name", NULL);
	if (name_idx >= 0) {
		a2a_add_token(art_tree, hf_a2a_artifact_name, tvb, json, name_idx);
		proto_item_append_text(art_tree, ": %s",
				       a2a_tok_strdup(pinfo->pool, json, name_idx));
	}

	a2a_add_field(art_tree, hf_a2a_artifact_id, tvb, json, art_idx, "artifact_id", "artifactId");
	a2a_add_field(art_tree, hf_a2a_artifact_description, tvb, json, art_idx, "description", NULL);

	parts_idx = a2a_field_of_type(json, art_idx, "parts", NULL, JSMN_ARRAY);
	if (parts_idx >= 0) {
		a2a_dissect_parts(art_tree, tvb, pinfo, json, parts_idx);
	}

	a2a_add_string_array(art_tree, hf_a2a_extension, tvb, json,
			     a2a_field_of_type(json, art_idx, "extensions", NULL, JSMN_ARRAY));
	a2a_add_raw(art_tree, hf_a2a_metadata, tvb, json, art_idx, "metadata", NULL);
}

static void
a2a_dissect_artifacts(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		      const a2a_json_t *json, int artifacts_idx)
{
	int elem;

	for (elem = a2a_array_first(json, artifacts_idx); elem >= 0;
	     elem = a2a_array_next(json, artifacts_idx, elem)) {
		a2a_dissect_artifact(tree, tvb, pinfo, json, elem);
	}
}

/* TaskPushNotificationConfig (nested AuthenticationInfo) */
static void
a2a_dissect_push_config(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
			const a2a_json_t *json, int cfg_idx, bool subtree)
{
	proto_tree *cfg_tree = tree;
	int auth_idx;

	if (cfg_idx < 0 || json->tokens[cfg_idx].type != JSMN_OBJECT) {
		return;
	}

	if (subtree) {
		int id_idx = a2a_field(json, cfg_idx, "id", NULL);

		cfg_tree = proto_tree_add_subtree(tree, tvb, json->tokens[cfg_idx].start,
						  json->tokens[cfg_idx].end - json->tokens[cfg_idx].start,
						  ett_a2a_push_config, NULL, "Push notification config");

		if (id_idx >= 0) {
			proto_item_append_text(cfg_tree, ": %s",
					       a2a_tok_strdup(pinfo->pool, json, id_idx));
		}
	}

	a2a_add_field(cfg_tree, hf_a2a_push_config_id, tvb, json, cfg_idx, "id", NULL);
	a2a_add_field(cfg_tree, hf_a2a_task_id, tvb, json, cfg_idx, "task_id", "taskId");
	a2a_add_field(cfg_tree, hf_a2a_push_config_url, tvb, json, cfg_idx, "url", NULL);
	a2a_add_field(cfg_tree, hf_a2a_push_config_token, tvb, json, cfg_idx, "token", NULL);
	a2a_add_field(cfg_tree, hf_a2a_tenant, tvb, json, cfg_idx, "tenant", NULL);

	auth_idx = a2a_field_of_type(json, cfg_idx, "authentication", NULL, JSMN_OBJECT);
	if (auth_idx >= 0) {
		a2a_add_field(cfg_tree, hf_a2a_auth_scheme, tvb, json, auth_idx, "scheme", NULL);
		a2a_add_field(cfg_tree, hf_a2a_auth_credentials, tvb, json, auth_idx, "credentials", NULL);
	}
}

/* SendMessageConfiguration */
static void
a2a_dissect_configuration(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
			  const a2a_json_t *json, int cfg_idx)
{
	proto_tree *cfg_tree;

	if (cfg_idx < 0 || json->tokens[cfg_idx].type != JSMN_OBJECT) {
		return;
	}

	cfg_tree = proto_tree_add_subtree(tree, tvb, json->tokens[cfg_idx].start,
					  json->tokens[cfg_idx].end - json->tokens[cfg_idx].start,
					  ett_a2a_configuration, NULL, "Configuration");

	a2a_add_string_array(cfg_tree, hf_a2a_accepted_output_mode, tvb, json,
			     a2a_field_of_type(json, cfg_idx,
					       "accepted_output_modes", "acceptedOutputModes", JSMN_ARRAY));
	a2a_add_bool(cfg_tree, hf_a2a_return_immediately, tvb, json, cfg_idx,
		     "return_immediately", "returnImmediately");
	a2a_add_uint(cfg_tree, hf_a2a_history_length, tvb, pinfo, json, cfg_idx,
		     "history_length", "historyLength");

	a2a_dissect_push_config(cfg_tree, tvb, pinfo, json,
				a2a_field_of_type(json, cfg_idx,
						  "task_push_notification_config",
						  "taskPushNotificationConfig", JSMN_OBJECT), true);
}

/* dissect a Task into its own subtree. Returns the task state or NULL */
static const char *
a2a_dissect_task(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo,
		 const a2a_json_t *json, int task_idx)
{
	proto_tree *task_tree;
	int id_idx, status_idx, artifacts_idx, history_idx;
	const char *state;
	int elem;

	if (task_idx < 0 || json->tokens[task_idx].type != JSMN_OBJECT) {
		return NULL;
	}

	task_tree = proto_tree_add_subtree(tree, tvb, json->tokens[task_idx].start,
					   json->tokens[task_idx].end - json->tokens[task_idx].start,
					   ett_a2a_task, NULL, "Task");

	id_idx = a2a_field(json, task_idx, "id", NULL);
	if (id_idx >= 0) {
		a2a_add_token(task_tree, hf_a2a_task_id, tvb, json, id_idx);
		proto_item_append_text(task_tree, ": %s",
				       a2a_tok_strdup(pinfo->pool, json, id_idx));
	}

	a2a_add_field(task_tree, hf_a2a_context_id, tvb, json, task_idx, "context_id", "contextId");

	status_idx = a2a_field(json, task_idx, "status", NULL);
	state = a2a_dissect_status(task_tree, tvb, pinfo, json, status_idx);
	if (state != NULL) {
		proto_item_append_text(task_tree, " [%s]", state);
	}

	artifacts_idx = a2a_field_of_type(json, task_idx, "artifacts", NULL, JSMN_ARRAY);
	if (artifacts_idx >= 0) {
		a2a_dissect_artifacts(task_tree, tvb, pinfo, json, artifacts_idx);
	}

	history_idx = a2a_field_of_type(json, task_idx, "history", NULL, JSMN_ARRAY);
	for (elem = a2a_array_first(json, history_idx); elem >= 0;
	     elem = a2a_array_next(json, history_idx, elem)) {
		a2a_dissect_message(task_tree, tvb, pinfo, json, elem, "History message");
	}

	a2a_add_raw(task_tree, hf_a2a_metadata, tvb, json, task_idx, "metadata", NULL);

	return state;
}

static void
a2a_dissect_agent_card(proto_tree *tree, tvbuff_t *tvb, const a2a_json_t *json)
{
	proto_tree *card_tree;
	int skills_idx, ifaces_idx, provider_idx, caps_idx, exts_idx, sigs_idx, elem;

	card_tree = proto_tree_add_subtree(tree, tvb, 0, -1, ett_a2a_agent_card, NULL, "Agent card");

	a2a_add_field(card_tree, hf_a2a_agent_name, tvb, json, 0, "name", NULL);
	a2a_add_field(card_tree, hf_a2a_agent_version, tvb, json, 0, "version", NULL);
	a2a_add_field(card_tree, hf_a2a_agent_description, tvb, json, 0, "description", NULL);

	/* AgentProvider and AgentCapabilities. */
	provider_idx = a2a_field_of_type(json, 0, "provider", NULL, JSMN_OBJECT);
	if (provider_idx >= 0) {
		a2a_add_field(card_tree, hf_a2a_provider_organization, tvb, json,
			      provider_idx, "organization", NULL);
		a2a_add_field(card_tree, hf_a2a_provider_url, tvb, json, provider_idx,
			      "url", NULL);
	}

	caps_idx = a2a_field_of_type(json, 0, "capabilities", NULL, JSMN_OBJECT);
	if (caps_idx >= 0) {
		a2a_add_bool(card_tree, hf_a2a_cap_streaming, tvb, json,
			     caps_idx, "streaming", NULL);
		a2a_add_bool(card_tree, hf_a2a_cap_push_notifications, tvb, json,
			     caps_idx, "push_notifications", "pushNotifications");
		a2a_add_bool(card_tree, hf_a2a_cap_extended_agent_card, tvb, json,
			     caps_idx, "extended_agent_card", "extendedAgentCard");
	}

	/* AgentExtension list inside the capabilities. */
	if (caps_idx >= 0) {
		exts_idx = a2a_field_of_type(json, caps_idx, "extensions", NULL, JSMN_ARRAY);

		for (elem = a2a_array_first(json, exts_idx); elem >= 0;
		     elem = a2a_array_next(json, exts_idx, elem)) {
			if (json->tokens[elem].type != JSMN_OBJECT) {
				continue;
			}

			a2a_add_field(card_tree, hf_a2a_agent_extension_uri, tvb, json,
				      elem, "uri", NULL);
			a2a_add_bool(card_tree, hf_a2a_agent_extension_required, tvb,
				     json, elem, "required", NULL);
		}
	}

	a2a_add_string_array(card_tree, hf_a2a_input_mode, tvb, json,
			     a2a_field_of_type(json, 0, "default_input_modes", "defaultInputModes",
					       JSMN_ARRAY));
	a2a_add_string_array(card_tree, hf_a2a_output_mode, tvb, json,
			     a2a_field_of_type(json, 0, "default_output_modes", "defaultOutputModes",
					       JSMN_ARRAY));

	skills_idx = a2a_field_of_type(json, 0, "skills", NULL, JSMN_ARRAY);
	for (elem = a2a_array_first(json, skills_idx); elem >= 0;
	     elem = a2a_array_next(json, skills_idx, elem)) {
		a2a_add_field(card_tree, hf_a2a_skill_id, tvb, json, elem, "id", NULL);
		a2a_add_field(card_tree, hf_a2a_skill_name, tvb, json, elem, "name", NULL);
		a2a_add_field(card_tree, hf_a2a_skill_description, tvb, json, elem,
			      "description", NULL);
		a2a_add_string_array(card_tree, hf_a2a_skill_tag, tvb, json,
				     a2a_field_of_type(json, elem, "tags", NULL, JSMN_ARRAY));
		a2a_add_string_array(card_tree, hf_a2a_skill_example, tvb, json,
				     a2a_field_of_type(json, elem, "examples", NULL, JSMN_ARRAY));
		a2a_add_string_array(card_tree, hf_a2a_input_mode, tvb, json,
				     a2a_field_of_type(json, elem, "input_modes", "inputModes",
						       JSMN_ARRAY));
		a2a_add_string_array(card_tree, hf_a2a_output_mode, tvb, json,
				     a2a_field_of_type(json, elem, "output_modes", "outputModes",
						       JSMN_ARRAY));
	}

	sigs_idx = a2a_field_of_type(json, 0, "signatures", NULL, JSMN_ARRAY);
	for (elem = a2a_array_first(json, sigs_idx); elem >= 0;
	     elem = a2a_array_next(json, sigs_idx, elem)) {
		a2a_add_field(card_tree, hf_a2a_signature, tvb, json, elem, "signature", NULL);
	}

	ifaces_idx = a2a_field_of_type(json, 0, "supported_interfaces", "supportedInterfaces", JSMN_ARRAY);

	for (elem = a2a_array_first(json, ifaces_idx); elem >= 0;
	     elem = a2a_array_next(json, ifaces_idx, elem)) {
		a2a_add_field(card_tree, hf_a2a_protocol_binding, tvb, json, elem,
			      "protocol_binding", "protocolBinding");
		a2a_add_field(card_tree, hf_a2a_protocol_version, tvb, json, elem,
			      "protocol_version", "protocolVersion");
		a2a_add_field(card_tree, hf_a2a_interface_url, tvb, json, elem, "url", NULL);
		a2a_add_field(card_tree, hf_a2a_tenant, tvb, json, elem, "tenant", NULL);
	}
}

/*
 * Message type identification based on required properties
 *
 *   Message                 message_id, role, parts
 *   TaskStatus              state
 *   Task                    id, status
 *   Artifact                artifact_id, parts
 *   TaskStatusUpdateEvent   task_id, context_id, status
 *   TaskArtifactUpdateEvent task_id, context_id, artifact
 *   SendMessageRequest      message, sent by the client (Role.ROLE_USER)
 *   SendMessageResponse     task, or message sent by the agent (Role.ROLE_AGENT)
 *   ListTasksResponse       tasks, next_page_token, page_size, total_size
 *   AgentCard               name, description, version, capabilities,
 *                           supported_interfaces, default_input_modes,
 *                           default_output_modes, skills
 */
static bool
dissect_a2a_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	json_heur_data_t *heur_data = (json_heur_data_t *)data;
	a2a_json_t json;
	a2a_type_t type;
	proto_tree *a2a_tree;
	proto_item *ti;
	const char *type_name;
	const char *state = NULL;
	int idx, msg_idx, elem;

	/* the JSON dissector hands over the token array built for the JSON+ form,
	 * or one built on-the-fly when disabled. */
	if (heur_data == NULL || heur_data->tokens == NULL) {
		return false;
	}

	json.buf = heur_data->buf;
	json.tokens = heur_data->tokens;
	json.num_tokens = heur_data->num_tokens;

	type = a2a_identify(&json);
	if (type == A2A_TYPE_NONE) {
		return false;
	}

	type_name = val_to_str_const(type, a2a_type_names, "Unknown");
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "A2A");
	ti = proto_tree_add_item(tree, proto_a2a, tvb, 0, -1, ENC_NA);
	proto_item_append_text(ti, ", %s", type_name);
	a2a_tree = proto_item_add_subtree(ti, ett_a2a);
	proto_tree_add_uint(a2a_tree, hf_a2a_type, tvb, 0, 0, type);

	switch (type) {
	case A2A_TYPE_SEND_MESSAGE_REQUEST:
	case A2A_TYPE_SEND_MESSAGE_RESPONSE:
	case A2A_TYPE_STREAM_RESPONSE:
		a2a_dissect_message(a2a_tree, tvb, pinfo, &json,
				    a2a_message_field(&json, 0), "Message");

		state = a2a_dissect_task(a2a_tree, tvb, pinfo, &json,
					 a2a_field_of_type(&json, 0, "task", NULL, JSMN_OBJECT));

		a2a_dissect_configuration(a2a_tree, tvb, pinfo, &json,
					  a2a_field_of_type(&json, 0, "configuration", NULL, JSMN_OBJECT));

		a2a_add_field(a2a_tree, hf_a2a_tenant, tvb, &json, 0, "tenant", NULL);
		a2a_add_raw(a2a_tree, hf_a2a_metadata, tvb, &json, 0, "metadata", NULL);

		/* StreamResponse updates. */
		idx = a2a_field(&json, 0, "status_update", "statusUpdate");
		if (idx >= 0) {
			a2a_add_field(a2a_tree, hf_a2a_task_id, tvb, &json, idx, "task_id", "taskId");
			state = a2a_dissect_status(a2a_tree, tvb, pinfo, &json,
						   a2a_field(&json, idx, "status", NULL));
		}

		idx = a2a_field(&json, 0, "artifact_update", "artifactUpdate");
		if (idx >= 0) {
			a2a_add_field(a2a_tree, hf_a2a_task_id, tvb, &json, idx, "task_id", "taskId");
			a2a_dissect_artifact(a2a_tree, tvb, pinfo, &json,
					     a2a_field_of_type(&json, idx, "artifact", NULL, JSMN_OBJECT));
			a2a_add_bool(a2a_tree, hf_a2a_append, tvb, &json, idx, "append", NULL);
			a2a_add_bool(a2a_tree, hf_a2a_last_chunk, tvb, &json, idx,
				     "last_chunk", "lastChunk");
		}
		break;

	case A2A_TYPE_TASK:
		state = a2a_dissect_task(a2a_tree, tvb, pinfo, &json, 0);
		break;

	case A2A_TYPE_TASK_STATUS_UPDATE:
		a2a_add_field(a2a_tree, hf_a2a_task_id, tvb, &json, 0, "task_id", "taskId");
		a2a_add_field(a2a_tree, hf_a2a_context_id, tvb, &json, 0, "context_id", "contextId");
		state = a2a_dissect_status(a2a_tree, tvb, pinfo, &json, a2a_field(&json, 0, "status", NULL));
		a2a_add_raw(a2a_tree, hf_a2a_metadata, tvb, &json, 0, "metadata", NULL);
		break;

	case A2A_TYPE_TASK_ARTIFACT_UPDATE:
		a2a_add_field(a2a_tree, hf_a2a_task_id, tvb, &json, 0, "task_id", "taskId");
		a2a_add_field(a2a_tree, hf_a2a_context_id, tvb, &json, 0, "context_id", "contextId");
		a2a_dissect_artifact(a2a_tree, tvb, pinfo, &json,
				     a2a_field_of_type(&json, 0, "artifact", NULL, JSMN_OBJECT));
		a2a_add_bool(a2a_tree, hf_a2a_append, tvb, &json, 0, "append", NULL);
		a2a_add_bool(a2a_tree, hf_a2a_last_chunk, tvb, &json, 0, "last_chunk", "lastChunk");
		a2a_add_raw(a2a_tree, hf_a2a_metadata, tvb, &json, 0, "metadata", NULL);
		break;

	case A2A_TYPE_LIST_TASKS_RESPONSE:
		a2a_add_uint(a2a_tree, hf_a2a_task_count, tvb, pinfo, &json, 0,
			     "total_size", "totalSize");

		a2a_add_uint(a2a_tree, hf_a2a_page_size, tvb, pinfo, &json, 0,
			     "page_size", "pageSize");
		a2a_add_field(a2a_tree, hf_a2a_next_page_token, tvb, &json, 0,
			      "next_page_token", "nextPageToken");

		idx = a2a_field_of_type(&json, 0, "tasks", NULL, JSMN_ARRAY);
		for (elem = a2a_array_first(&json, idx); elem >= 0;
		     elem = a2a_array_next(&json, idx, elem)) {
			a2a_dissect_task(a2a_tree, tvb, pinfo, &json, elem);
		}
		break;

	case A2A_TYPE_MESSAGE:
		a2a_dissect_message(a2a_tree, tvb, pinfo, &json, 0, "Message");
		break;

	case A2A_TYPE_AGENT_CARD:
		a2a_dissect_agent_card(a2a_tree, tvb, &json);
		break;

	case A2A_TYPE_PUSH_CONFIG:
		a2a_dissect_push_config(a2a_tree, tvb, pinfo, &json, 0, false);
		break;

	case A2A_TYPE_LIST_PUSH_CONFIGS_RESPONSE:
		idx = a2a_field_of_type(&json, 0, "configs", NULL, JSMN_ARRAY);
		for (elem = a2a_array_first(&json, idx); elem >= 0;
		     elem = a2a_array_next(&json, idx, elem)) {
			a2a_dissect_push_config(a2a_tree, tvb, pinfo, &json, elem, true);
		}

		a2a_add_field(a2a_tree, hf_a2a_next_page_token, tvb, &json, 0,
			      "next_page_token", "nextPageToken");
		break;

	case A2A_TYPE_NONE:
		break;
	}

	/* info column: the message type, followed by the most
	 * useful discriminator available for that type */
	col_add_str(pinfo->cinfo, COL_INFO, type_name);

	if (state != NULL) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", state);
	}

	switch (type) {
	case A2A_TYPE_SEND_MESSAGE_REQUEST:
	case A2A_TYPE_SEND_MESSAGE_RESPONSE:
	case A2A_TYPE_MESSAGE:
		msg_idx = (type == A2A_TYPE_MESSAGE) ? 0 : a2a_message_field(&json, 0);
		idx = a2a_field(&json, msg_idx, "role", NULL);
		if (idx >= 0) {
			bool known;
			const char *role = a2a_enum_string(pinfo->pool, &json, idx,
							   a2a_role_vals, &known);

			if (role != NULL) {
				col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)", role);
			}
		}
		break;

	case A2A_TYPE_LIST_TASKS_RESPONSE: {
		unsigned count = 0;

		idx = a2a_field_of_type(&json, 0, "tasks", NULL, JSMN_ARRAY);
		for (elem = a2a_array_first(&json, idx); elem >= 0;
		     elem = a2a_array_next(&json, idx, elem)) {
			count++;
		}

		col_append_fstr(pinfo->cinfo, COL_INFO, " (%u task%s)", count,
				(count == 1) ? "" : "s");
		break;
	}

	case A2A_TYPE_AGENT_CARD:
		idx = a2a_field(&json, 0, "name", NULL);
		if (idx >= 0) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
					a2a_tok_strdup(pinfo->pool, &json, idx));
		}
		break;

	case A2A_TYPE_PUSH_CONFIG:
		idx = a2a_field(&json, 0, "url", NULL);
		if (idx >= 0) {
			col_append_fstr(pinfo->cinfo, COL_INFO, " (%s)",
					a2a_tok_strdup(pinfo->pool, &json, idx));
		}
		break;

	case A2A_TYPE_LIST_PUSH_CONFIGS_RESPONSE: {
		unsigned count = 0;

		idx = a2a_field_of_type(&json, 0, "configs", NULL, JSMN_ARRAY);
		for (elem = a2a_array_first(&json, idx); elem >= 0;
		     elem = a2a_array_next(&json, idx, elem)) {
			count++;
		}

		col_append_fstr(pinfo->cinfo, COL_INFO, " (%u config%s)", count,
				(count == 1) ? "" : "s");
		break;
	}

	default:
		break;
	}

	return true;
}

void
proto_register_a2a(void)
{
	static hf_register_info hf[] = {
		{ &hf_a2a_type,
		  { "Message type", "a2a.type",
		    FT_UINT8, BASE_DEC, VALS(a2a_type_names), 0x0,
		    "Message type", HFILL }
		},
		{ &hf_a2a_message_id,
		  { "Message ID", "a2a.message_id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The unique identifier of the message", HFILL }
		},
		{ &hf_a2a_context_id,
		  { "Context ID", "a2a.context_id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Identifier of the conversation context", HFILL }
		},
		{ &hf_a2a_task_id,
		  { "Task ID", "a2a.task_id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Identifier of the task", HFILL }
		},
		{ &hf_a2a_role,
		  { "Role", "a2a.role",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Sender identifier (ROLE_USER or ROLE_AGENT)", HFILL }
		},
		{ &hf_a2a_part_text,
		  { "Text", "a2a.part.text",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Part.text", HFILL }
		},
		{ &hf_a2a_part_raw,
		  { "Raw bytes", "a2a.part.raw",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Part.raw, base64 encoded", HFILL }
		},
		{ &hf_a2a_part_url,
		  { "URL", "a2a.part.url",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Part.url", HFILL }
		},
		{ &hf_a2a_part_filename,
		  { "File name", "a2a.part.filename",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Part.filename", HFILL }
		},
		{ &hf_a2a_part_media_type,
		  { "Media type", "a2a.part.media_type",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Part.media_type", HFILL }
		},
		{ &hf_a2a_task_state,
		  { "Task state", "a2a.task.state",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "The current state of this task", HFILL }
		},
		{ &hf_a2a_task_timestamp,
		  { "Task timestamp", "a2a.task.timestamp",
		    FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
		    "When the status was recorded", HFILL }
		},
		{ &hf_a2a_task_count,
		  { "Total tasks", "a2a.task_count",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Number of tasks reported by the server", HFILL }
		},
		{ &hf_a2a_artifact_id,
		  { "Artifact ID", "a2a.artifact.id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Artifact.artifact_id", HFILL }
		},
		{ &hf_a2a_artifact_name,
		  { "Artifact name", "a2a.artifact.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Artifact.name", HFILL }
		},
		{ &hf_a2a_artifact_description,
		  { "Artifact description", "a2a.artifact.description",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Artifact.description", HFILL }
		},
		{ &hf_a2a_agent_name,
		  { "Agent name", "a2a.agent.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentCard.name", HFILL }
		},
		{ &hf_a2a_agent_version,
		  { "Agent version", "a2a.agent.version",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentCard.version", HFILL }
		},
		{ &hf_a2a_agent_description,
		  { "Agent description", "a2a.agent.description",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentCard.description", HFILL }
		},
		{ &hf_a2a_skill_id,
		  { "Skill ID", "a2a.skill.id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentSkill.id", HFILL }
		},
		{ &hf_a2a_skill_name,
		  { "Skill name", "a2a.skill.name",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentSkill.name", HFILL }
		},
		{ &hf_a2a_provider_organization,
		  { "Provider organization", "a2a.agent.provider.organization",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentProvider.organization", HFILL }
		},
		{ &hf_a2a_provider_url,
		  { "Provider URL", "a2a.agent.provider.url",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentProvider.url", HFILL }
		},
		{ &hf_a2a_cap_streaming,
		  { "Streaming", "a2a.agent.capabilities.streaming",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "AgentCapabilities.streaming", HFILL }
		},
		{ &hf_a2a_cap_push_notifications,
		  { "Push notifications", "a2a.agent.capabilities.push_notifications",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "AgentCapabilities.push_notifications", HFILL }
		},
		{ &hf_a2a_cap_extended_agent_card,
		  { "Extended agent card", "a2a.agent.capabilities.extended_agent_card",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "AgentCapabilities.extended_agent_card", HFILL }
		},
		{ &hf_a2a_accepted_output_mode,
		  { "Accepted output mode", "a2a.configuration.accepted_output_mode",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "SendMessageConfiguration.accepted_output_modes", HFILL }
		},
		{ &hf_a2a_return_immediately,
		  { "Return immediately", "a2a.configuration.return_immediately",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "SendMessageConfiguration.return_immediately", HFILL }
		},
		{ &hf_a2a_history_length,
		  { "History length", "a2a.configuration.history_length",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "SendMessageConfiguration.history_length", HFILL }
		},
		{ &hf_a2a_push_config_id,
		  { "Push config ID", "a2a.push_config.id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "TaskPushNotificationConfig.id", HFILL }
		},
		{ &hf_a2a_push_config_url,
		  { "Push config URL", "a2a.push_config.url",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "TaskPushNotificationConfig.url", HFILL }
		},
		{ &hf_a2a_push_config_token,
		  { "Push config token", "a2a.push_config.token",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "TaskPushNotificationConfig.token", HFILL }
		},
		{ &hf_a2a_auth_scheme,
		  { "Authentication scheme", "a2a.push_config.auth.scheme",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AuthenticationInfo.scheme", HFILL }
		},
		{ &hf_a2a_auth_credentials,
		  { "Authentication credentials", "a2a.push_config.auth.credentials",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AuthenticationInfo.credentials", HFILL }
		},
		{ &hf_a2a_next_page_token,
		  { "Next page token", "a2a.next_page_token",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Pagination token of a list response", HFILL }
		},
		{ &hf_a2a_page_size,
		  { "Page size", "a2a.page_size",
		    FT_UINT32, BASE_DEC, NULL, 0x0,
		    "Page size of a list response", HFILL }
		},
		{ &hf_a2a_tenant,
		  { "Tenant", "a2a.tenant",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Tenant the request or interface belongs to", HFILL }
		},
		{ &hf_a2a_metadata,
		  { "Metadata", "a2a.metadata",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Free form metadata", HFILL }
		},
		{ &hf_a2a_part_data,
		  { "Data", "a2a.part.data",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Part.data", HFILL }
		},
		{ &hf_a2a_extension,
		  { "Extension", "a2a.extension",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "URI of an extension activated for this message or artifact", HFILL }
		},
		{ &hf_a2a_reference_task_id,
		  { "Reference task ID", "a2a.reference_task_id",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Message.reference_task_ids", HFILL }
		},
		{ &hf_a2a_append,
		  { "Append", "a2a.append",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "TaskArtifactUpdateEvent.append", HFILL }
		},
		{ &hf_a2a_last_chunk,
		  { "Last chunk", "a2a.last_chunk",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "TaskArtifactUpdateEvent.last_chunk", HFILL }
		},
		{ &hf_a2a_input_mode,
		  { "Input mode", "a2a.input_mode",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Accepted input media type", HFILL }
		},
		{ &hf_a2a_output_mode,
		  { "Output mode", "a2a.output_mode",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "Produced output media type", HFILL }
		},
		{ &hf_a2a_skill_description,
		  { "Skill description", "a2a.skill.description",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentSkill.description", HFILL }
		},
		{ &hf_a2a_skill_tag,
		  { "Skill tag", "a2a.skill.tag",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentSkill.tags", HFILL }
		},
		{ &hf_a2a_skill_example,
		  { "Skill example", "a2a.skill.example",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentSkill.examples", HFILL }
		},
		{ &hf_a2a_agent_extension_uri,
		  { "Extension URI", "a2a.agent.extension.uri",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentExtension.uri", HFILL }
		},
		{ &hf_a2a_agent_extension_required,
		  { "Extension required", "a2a.agent.extension.required",
		    FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "AgentExtension.required", HFILL }
		},
		{ &hf_a2a_signature,
		  { "Card signature", "a2a.agent.signature",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentCardSignature.signature", HFILL }
		},
		{ &hf_a2a_protocol_binding,
		  { "Protocol binding", "a2a.interface.protocol_binding",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentInterface.protocol_binding", HFILL }
		},
		{ &hf_a2a_protocol_version,
		  { "Protocol version", "a2a.interface.protocol_version",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentInterface.protocol_version", HFILL }
		},
		{ &hf_a2a_interface_url,
		  { "Interface URL", "a2a.interface.url",
		    FT_STRING, BASE_NONE, NULL, 0x0,
		    "AgentInterface.url", HFILL }
		},
	};

	static int *ett[] = {
		&ett_a2a,
		&ett_a2a_message,
		&ett_a2a_task,
		&ett_a2a_part,
		&ett_a2a_artifact,
		&ett_a2a_agent_card,
		&ett_a2a_configuration,
		&ett_a2a_push_config,
	};

	static ei_register_info ei[] = {
		{ &ei_a2a_invalid_structure,
		  { "a2a.invalid_structure", PI_PROTOCOL, PI_WARN,
		    "Invalid A2A message structure", EXPFILL }
		},
	};

	proto_a2a = proto_register_protocol("Agent-to-Agent Protocol", "A2A", "a2a");

	proto_register_field_array(proto_a2a, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	expert_module_t *expert_a2a = expert_register_protocol(proto_a2a);
	expert_register_field_array(expert_a2a, ei, array_length(ei));
}

void
proto_reg_handoff_a2a(void)
{
	heur_dissector_add("json", dissect_a2a_heur, "A2A over JSON", "a2a_json",
			   proto_a2a, HEURISTIC_ENABLE);
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
