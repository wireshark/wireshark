/* packet-lwm2mtlv.c
 * Routines for LWM2M TLV dissection
 * References:
 *     OMA LWM2M Specification: OMA-TS-LightweightM2M_Core-V1_1-20180710-A.pdf
 *     available from
 *     http://openmobilealliance.org/release/LightweightM2M/V1_1-20180710-A/
 *
 * Copyright 2016, Christoph Burger-Scheidlin
 * Copyright 2018, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include <epan/strutil.h>
#include <wsutil/str_util.h>

#include "packet-gsm_a_common.h"
#include "packet-media-type.h"

void proto_register_lwm2mtlv(void);
void proto_reg_handoff_lwm2mtlv(void);

static dissector_handle_t lwm2mtlv_handle;

static int proto_lwm2mtlv;

static int hf_lwm2mtlv_object_name;
static int hf_lwm2mtlv_resource_name;
static int hf_lwm2mtlv_header;
static int hf_lwm2mtlv_type_type;
static int hf_lwm2mtlv_type_length_of_identifier;
static int hf_lwm2mtlv_type_length_of_length;
static int hf_lwm2mtlv_type_length;
static int hf_lwm2mtlv_type_ignored;

static int hf_lwm2mtlv_identifier;
static int hf_lwm2mtlv_length;
static int hf_lwm2mtlv_value;
static int hf_lwm2mtlv_value_string;
static int hf_lwm2mtlv_value_integer;
static int hf_lwm2mtlv_value_unsigned_integer;
static int hf_lwm2mtlv_value_float;
static int hf_lwm2mtlv_value_double;
static int hf_lwm2mtlv_value_boolean;
static int hf_lwm2mtlv_value_timestamp;

static int hf_lwm2mtlv_object_instance;
static int hf_lwm2mtlv_resource_instance;
static int hf_lwm2mtlv_resource_array;
static int hf_lwm2mtlv_resource;

static int ett_lwm2mtlv;
static int ett_lwm2mtlv_header;
static int ett_lwm2mtlv_resource;
static int ett_lwm2mtlv_resource_instance;
static int ett_lwm2mtlv_resource_array;
static int ett_lwm2mtlv_object_instance;
static int ett_lwm2mtlv_location_velocity;

typedef enum {
	OBJECT_INSTANCE   = 0,
	RESOURCE_INSTANCE = 1,
	RESOURCE_ARRAY    = 2,
	RESOURCE          = 3
} lwm2m_identifier_t;

static const value_string identifiers[] = {
	{ OBJECT_INSTANCE,   "Object Instance" },
	{ RESOURCE_INSTANCE, "Resource Instance" },
	{ RESOURCE_ARRAY,    "Multiple Resources" },
	{ RESOURCE,          "Resource with value" },
	{ 0, NULL }
};

static const value_string length_identifier[] = {
	{ 0x00, "1 byte identifier" },
	{ 0x01, "2 bytes identifier" },
	{ 0, NULL }
};

static const value_string length_type[] = {
	{ 0x00, "No length field" },
	{ 0x01, "1 byte length field" },
	{ 0x02, "2 bytes length field" },
	{ 0x03, "3 bytes length field" },
	{ 0, NULL }
};

typedef struct
{
	unsigned type;
	unsigned length_of_identifier;
	unsigned length_of_length;
	unsigned length_of_value;
	unsigned identifier;
	unsigned length;
	unsigned totalLength;
} lwm2mElement_t;

typedef struct _lwm2m_object_name_t {
	unsigned   object_id;
	char   *name;
} lwm2m_object_name_t;

typedef struct _lwm2m_resource_t {
	unsigned   object_id;
	unsigned   resource_id;
	char   *name;
	unsigned   data_type;
	int    *hf_id;
	int     ett_id;
	char   *field_name;
} lwm2m_resource_t;

static void parseArrayOfElements(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tlv_tree, int object_id, int resource_id);

/* RESOURCE_FILL initializes all the dynamic fields in a lwm2m_resource_t. */
#define RESOURCE_FILL NULL, -1, NULL

#define DATA_TYPE_NONE             0
#define DATA_TYPE_STRING           1
#define DATA_TYPE_INTEGER          2
#define DATA_TYPE_UNSIGNED_INTEGER 3
#define DATA_TYPE_FLOAT            4
#define DATA_TYPE_BOOLEAN          5
#define DATA_TYPE_OPAQUE           6
#define DATA_TYPE_TIME             7
#define DATA_TYPE_OBJLNK           8
#define DATA_TYPE_CORELNK          9

static const value_string data_types[] = {
	{ DATA_TYPE_NONE,             "None"             },
	{ DATA_TYPE_STRING,           "String"           },
	{ DATA_TYPE_INTEGER,          "Integer"          },
	{ DATA_TYPE_UNSIGNED_INTEGER, "Unsigned Integer" },
	{ DATA_TYPE_FLOAT,            "Float"            },
	{ DATA_TYPE_BOOLEAN,          "Boolean"          },
	{ DATA_TYPE_OPAQUE,           "Opaque"           },
	{ DATA_TYPE_TIME,             "Time"             },
	{ DATA_TYPE_OBJLNK,           "Objlnk"           },
	{ DATA_TYPE_CORELNK,          "Corelnk"          },
	{ 0, NULL }
};

/* LwM2M Objects defined by OMA (Normative) */
static const value_string lwm2m_oma_objects[] = {
	{ 0,  "LwM2M Security"          },
	{ 1,  "LwM2M Server"            },
	{ 2,  "Access Control"          },
	{ 3,  "Device"                  },
	{ 4,  "Connectivity Monitoring" },
	{ 5,  "Firmware Update"         },
	{ 6,  "Location"                },
	{ 7,  "Connectivity Statistics" },
	{ 21, "OSCORE"                  },
	{ 0, NULL }
};

static lwm2m_resource_t lwm2m_oma_resources[] =
{
	/* LwM2M Security (0) */
	{ 0, 0,  "LwM2M Server URI", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 0, 1,  "Bootstrap-Server", DATA_TYPE_BOOLEAN, RESOURCE_FILL },
	{ 0, 2,  "Security Mode", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 0, 3,  "Public Key or Identity", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 0, 4,  "Server Public Key", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 0, 5,  "Secret Key", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 0, 6,  "SMS Security Mode", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 0, 7,  "SMS Binding Key Parameters", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 0, 8,  "SMS Binding Secret Keys", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 0, 9,  "LwM2M Server SMS Number", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 0, 10, "Short Server ID", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 0, 11, "Client Hold Off Time", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 0, 12, "Bootstrap-Server Account Timeout", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 0, 13, "Matching Type", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 0, 14, "SNI", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 0, 15, "Certificate Usage", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 0, 16, "TLS DTLS Ciphersuite", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 0, 17, "OSCORE Security Mode", DATA_TYPE_OBJLNK, RESOURCE_FILL },

	/* LwM2M Server (1) */
	{ 1, 0,  "Short Server ID", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 1, 1,  "Lifetime", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 1, 2,  "Default Minimum Period", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 1, 3,  "Default Maximum Period", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 1, 4,  "Disable", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 1, 5,  "Disable Timeout", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 1, 6,  "Notification Storing When Disabled or Offline", DATA_TYPE_BOOLEAN, RESOURCE_FILL },
	{ 1, 7,  "Binding", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 1, 8,  "Registration Update Trigger", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 1, 9,  "Bootstrap Request Trigger", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 1, 10, "APN Link", DATA_TYPE_OBJLNK, RESOURCE_FILL },
	{ 1, 11, "TLS DTLS Alert Code", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 12, "Last Bootstrapped", DATA_TYPE_TIME, RESOURCE_FILL },
	{ 1, 13, "Registration Priority Order", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 14, "Initial Registration Delay Timer", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 15, "Registration Failure Block", DATA_TYPE_BOOLEAN, RESOURCE_FILL },
	{ 1, 16, "Bootstrap on Registration Failure", DATA_TYPE_BOOLEAN, RESOURCE_FILL },
	{ 1, 17, "Communication Retry Count", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 18, "Communication Retry Timer", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 19, "Communication Sequence Delay Timer", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 20, "Communication Sequence Retry Count", DATA_TYPE_UNSIGNED_INTEGER, RESOURCE_FILL },
	{ 1, 21, "Trigger", DATA_TYPE_BOOLEAN, RESOURCE_FILL },
	{ 1, 22, "Preferred Transport", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 1, 23, "Mute Send", DATA_TYPE_BOOLEAN, RESOURCE_FILL },

	/* Access Control (2) */
	{ 2, 0,  "Object ID", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 2, 1,  "Object Instance ID", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 2, 2,  "ACL", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 2, 3,  "Access Control Owner", DATA_TYPE_INTEGER, RESOURCE_FILL },

	/* Device (3) */
	{ 3, 0,  "Manufacturer", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 1,  "Model Number", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 2,  "Serial Number", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 3,  "Firmware Version", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 4,  "Reboot", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 3, 5,  "Factory Reset", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 3, 6,  "Available Power Sources", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 7,  "Power Source Voltage", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 8,  "Power Source Current", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 9,  "Battery Level", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 10, "Memory Free", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 11, "Error Code", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 12, "Reset Error Code", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 3, 13, "Current Time", DATA_TYPE_TIME, RESOURCE_FILL },
	{ 3, 14, "UTC Offset", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 15, "Timezone", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 16, "Supported Binding and Modes", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 17, "Device Type", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 18, "Hardware Version", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 19, "Software Version", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 3, 20, "Battery Status", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 21, "Memory Total", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 3, 22, "ExtDevInfo", DATA_TYPE_OBJLNK, RESOURCE_FILL },

	/* Connectivity Monitoring (4) */
	{ 4, 0,  "Network Bearer", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 1,  "Available Network Bearer", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 2,  "Radio Signal Strength", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 3,  "Link Quality", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 4,  "IP Addresses", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 4, 5,  "Router IP Addresses", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 4, 6,  "Link Utilization", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 7,  "APN", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 4, 8,  "Cell ID", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 9,  "SMNC", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 10, "SMCC", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 4, 11, "SignalSNR", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 5, 12, "LAC", DATA_TYPE_INTEGER, RESOURCE_FILL },

	/* Firmware Update (5) */
	{ 5, 0,  "Package", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 5, 1,  "Package URI", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 5, 2,  "Update", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 5, 3,  "State", DATA_TYPE_INTEGER, RESOURCE_FILL },
	/* { 5, 4,  "", DATA_TYPE_NONE, RESOURCE_FILL }, */
	{ 5, 5,  "Update Result", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 5, 6,  "PkgName", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 5, 7,  "PkgVersion", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 5, 8,  "Firmware Update Protocol Support", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 5, 9,  "Firmware Update Delivery Method", DATA_TYPE_INTEGER, RESOURCE_FILL },

	/* Location (6) */
	{ 6, 0,  "Latitude", DATA_TYPE_FLOAT, RESOURCE_FILL },
	{ 6, 1,  "Longitude", DATA_TYPE_FLOAT, RESOURCE_FILL },
	{ 6, 2,  "Altitude", DATA_TYPE_FLOAT, RESOURCE_FILL },
	{ 6, 3,  "Radius", DATA_TYPE_FLOAT, RESOURCE_FILL },
	{ 6, 4,  "Velocity", DATA_TYPE_OPAQUE, RESOURCE_FILL },
	{ 6, 5,  "Timestamp", DATA_TYPE_TIME, RESOURCE_FILL },
	{ 6, 6,  "Speed", DATA_TYPE_FLOAT, RESOURCE_FILL },

	/* Connectivity Statistics (7) */
	{ 7, 0,  "SMS Tx Counter", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 7, 1,  "SMS Rx Counter", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 7, 2,  "Tx Data", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 7, 3,  "Rx Data", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 7, 4,  "Max Message Size", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 7, 5,  "Average Message Size", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 7, 6,  "Start", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 7, 7,  "Stop", DATA_TYPE_NONE, RESOURCE_FILL },
	{ 7, 8,  "Collection Period", DATA_TYPE_INTEGER, RESOURCE_FILL },

	/* OSCORE (21) */
	{ 21, 0, "Master Secret", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 21, 1, "Sender ID", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 21, 2, "Recipient ID", DATA_TYPE_STRING, RESOURCE_FILL },
	{ 21, 3, "AEAD Algorithm", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 21, 4, "HMAC Algorithm", DATA_TYPE_INTEGER, RESOURCE_FILL },
	{ 21, 5, "Master Salt", DATA_TYPE_STRING, RESOURCE_FILL },
};
static const unsigned num_lwm2m_oma_resources = array_length(lwm2m_oma_resources);

typedef struct _lwm2m_allocated_fields_t {
	hf_register_info *hf;
	unsigned          hf_size;
	GArray           *ett;
	lwm2m_resource_t *float_resources;
	unsigned          num_float_resources;
} lwm2m_allocated_fields_t;

static lwm2m_allocated_fields_t oma_allocated_fields;
static lwm2m_allocated_fields_t uat_allocated_fields;

/* LwM2M Objects defined by User */
static lwm2m_object_name_t *lwm2m_uat_object_names;
static unsigned num_lwm2m_uat_object_names;
static lwm2m_resource_t *lwm2m_uat_resources;
static unsigned num_lwm2m_uat_resources;

static bool lwm2m_object_name_update_cb(void *record, char **error)
{
	lwm2m_object_name_t *rec = (lwm2m_object_name_t *)record;

	if (rec->name == NULL) {
		*error = g_strdup("Object Name can't be empty");
		return false;
	}

	g_strstrip(rec->name);
	if (rec->name[0] == 0) {
		*error = g_strdup("Object Name can't be empty");
		return false;
	}

	*error = NULL;
	return true;
}

static void *lwm2m_object_name_copy_cb(void *dest, const void *source, size_t len _U_)
{
	const lwm2m_object_name_t *s = (const lwm2m_object_name_t *)source;
	lwm2m_object_name_t *d = (lwm2m_object_name_t *)dest;

	d->object_id = s->object_id;
	d->name = g_strdup(s->name);

	return d;
}

static void lwm2m_object_name_free_cb(void *record)
{
	lwm2m_object_name_t *rec = (lwm2m_object_name_t *)record;

	g_free(rec->name);
}

UAT_DEC_CB_DEF(object_name, object_id, lwm2m_object_name_t)
UAT_CSTRING_CB_DEF(object_name, name, lwm2m_object_name_t)

static bool lwm2m_resource_update_cb(void *record, char **error)
{
	lwm2m_resource_t *rec = (lwm2m_resource_t *)record;
	char c;

	if (rec->name == NULL) {
		*error = g_strdup("Resource Name can't be empty");
		return false;
	}

	g_strstrip(rec->name);
	if (rec->name[0] == 0) {
		*error = g_strdup("Resource Name can't be empty");
		return false;
	}

	g_free(rec->field_name);
	rec->field_name = g_ascii_strdown(rec->name, -1);
	for (size_t i = 0; i < strlen(rec->field_name); i++) {
		if (rec->field_name[i] == ' ' || rec->field_name[i] == '.') {
			rec->field_name[i] = '_';
		}
	}

	/* Check for invalid characters (to avoid asserting out when registering the field). */
	c = proto_check_field_name(rec->field_name);
	if (c) {
		*error = ws_strdup_printf("Resource Name can't contain '%c'", c);
		return false;
	}

	*error = NULL;
	return true;
}

static void *lwm2m_resource_copy_cb(void *dest, const void *source, size_t len _U_)
{
	const lwm2m_resource_t *s = (const lwm2m_resource_t *)source;
	lwm2m_resource_t *d = (lwm2m_resource_t *)dest;

	d->object_id = s->object_id;
	d->resource_id = s->resource_id;
	d->name = g_strdup(s->name);
	d->field_name = g_strdup(s->field_name);
	d->data_type = s->data_type;

	return d;
}

static void lwm2m_resource_free_cb(void *record)
{
	lwm2m_resource_t *rec = (lwm2m_resource_t *)record;

	g_free(rec->name);
	g_free(rec->field_name);
}

static void lwm2m_add_resource(lwm2m_resource_t *resource, hf_register_info *hf, bool float_as_double)
{
	char *resource_abbrev;
	int *hf_id;

	hf_id = g_new(int,1);
	*hf_id = -1;

	if (resource->field_name) {
		resource_abbrev = g_strdup(resource->field_name);
	} else {
		resource_abbrev = g_ascii_strdown(resource->name, -1);
		for (size_t i = 0; i < strlen(resource_abbrev); i++) {
			if (resource_abbrev[i] == ' ' || resource_abbrev[i] == '.') {
				resource_abbrev[i] = '_';
			}
		}
	}

	resource->hf_id = hf_id;
	resource->ett_id = -1;

	hf->p_id = hf_id;
	hf->hfinfo.name = g_strdup(resource->name);
	hf->hfinfo.abbrev = ws_strdup_printf("lwm2mtlv.resource.%s", resource_abbrev);
	g_free (resource_abbrev);

	switch (resource->data_type) {
	case DATA_TYPE_STRING:
	case DATA_TYPE_CORELNK:
		hf->hfinfo.display = BASE_NONE;
		hf->hfinfo.type = FT_STRING;
		break;
	case DATA_TYPE_INTEGER:
		hf->hfinfo.display = BASE_DEC;
		hf->hfinfo.type = FT_INT64;
		break;
	case DATA_TYPE_UNSIGNED_INTEGER:
		hf->hfinfo.display = BASE_DEC;
		hf->hfinfo.type = FT_UINT64;
		break;
	case DATA_TYPE_FLOAT:
		hf->hfinfo.display = BASE_NONE;
		hf->hfinfo.type = (float_as_double ? FT_DOUBLE : FT_FLOAT);
		break;
	case DATA_TYPE_BOOLEAN:
		hf->hfinfo.display = BASE_DEC;
		hf->hfinfo.type = FT_BOOLEAN;
		break;
	case DATA_TYPE_TIME:
		hf->hfinfo.display = ABSOLUTE_TIME_LOCAL;
		hf->hfinfo.type = FT_ABSOLUTE_TIME;
		break;
	case DATA_TYPE_OPAQUE:
	case DATA_TYPE_OBJLNK:
	default:
		hf->hfinfo.display = BASE_NONE;
		hf->hfinfo.type = FT_BYTES;
		break;
	}
	hf->hfinfo.strings = NULL;
	hf->hfinfo.bitmask = 0;
	hf->hfinfo.blurb = NULL;
	HFILL_INIT(*hf);
}

static void lwm2m_allocate_fields(lwm2m_allocated_fields_t *fields, lwm2m_resource_t *lwm2m_resources, unsigned num_lwm2m_resources)
{
	unsigned resource_index;

	fields->num_float_resources = 0;
	for (unsigned i = 0; i < num_lwm2m_resources; i++) {
		if (lwm2m_resources[i].data_type == DATA_TYPE_FLOAT) {
			fields->num_float_resources++;
		}
	}

	fields->hf_size = num_lwm2m_resources + fields->num_float_resources;
	fields->hf = g_new0(hf_register_info, fields->hf_size);
	fields->ett = g_array_new(true, true, sizeof(int*));
	fields->float_resources = g_new0(lwm2m_resource_t, fields->num_float_resources);

	resource_index = 0;
	for (unsigned i = 0; i < num_lwm2m_resources; i++) {
		int *ettp = &(lwm2m_resources[i].ett_id);
		lwm2m_add_resource(&lwm2m_resources[i], &fields->hf[i], false);
		g_array_append_val(fields->ett, ettp);

		/* 8 bytes Float is handled as Double, allocate a separate resource for FT_DOUBLE */
		if (lwm2m_resources[i].data_type == DATA_TYPE_FLOAT) {
			unsigned hf_index = num_lwm2m_resources + resource_index;
			memcpy(&fields->float_resources[resource_index], &lwm2m_resources[i], sizeof(lwm2m_resource_t));
			lwm2m_add_resource(&fields->float_resources[resource_index++], &fields->hf[hf_index], true);
		}
	}

	proto_register_field_array(proto_lwm2mtlv, fields->hf, fields->hf_size);
	proto_register_subtree_array((int**)(void*)fields->ett->data, fields->ett->len);

	resource_index = 0;
	for (unsigned i = 0; i < num_lwm2m_resources; i++) {
		/* Reuse the same ETT for Float and Double resources */
		if (lwm2m_resources[i].data_type == DATA_TYPE_FLOAT) {
			fields->float_resources[resource_index++].ett_id = lwm2m_resources[i].ett_id;
		}
	}
}

static const lwm2m_resource_t *lwm2m_search_float_resources(unsigned object_id, unsigned resource_id,
						     const lwm2m_allocated_fields_t *fields)
{
	const lwm2m_resource_t *resource = NULL;

	for (unsigned i = 0; i < fields->num_float_resources; i++) {
		if ((object_id == fields->float_resources[i].object_id) &&
		    (resource_id == fields->float_resources[i].resource_id))
		{
			resource = &fields->float_resources[i];
			break;
		}
	}

	return resource;
}

static const lwm2m_resource_t *lwm2m_search_fields(unsigned object_id, unsigned resource_id, unsigned length_of_value,
					    const lwm2m_allocated_fields_t *fields,
					    const lwm2m_resource_t *lwm2m_resources, unsigned num_lwm2m_resources)
{
	const lwm2m_resource_t *resource = NULL;

	for (unsigned i = 0; i < num_lwm2m_resources; i++) {
		if ((object_id == lwm2m_resources[i].object_id) &&
		    (resource_id == lwm2m_resources[i].resource_id))
		{
			/* 8 bytes Float is handled as Double, lookup the FT_DOUBLE resource */
			if (length_of_value == 8 && lwm2m_resources[i].data_type == DATA_TYPE_FLOAT) {
				resource = lwm2m_search_float_resources(object_id, resource_id, fields);
			} else {
				resource = &lwm2m_resources[i];
			}
			break;
		}
	}

	return resource;
}

static void lwm2m_free_fields(lwm2m_allocated_fields_t *fields)
{
	if (fields->hf) {
		/* Deregister all fields */
		for (unsigned i = 0; i < fields->hf_size; i++) {
			proto_deregister_field(proto_lwm2mtlv, *(fields->hf[i].p_id));
			g_free (fields->hf[i].p_id);
		}

		proto_add_deregistered_data(fields->hf);
		fields->hf = NULL;
		fields->hf_size = 0;
	}

	if (fields->ett) {
		g_array_free(fields->ett, true);
		fields->ett = NULL;
	}

	if (fields->float_resources) {
		g_free(fields->float_resources);
		fields->float_resources = NULL;
		fields->num_float_resources = 0;
	}
}

static void lwm2m_resource_post_update_cb(void)
{
	lwm2m_free_fields(&uat_allocated_fields);

	if (num_lwm2m_uat_resources) {
		lwm2m_allocate_fields(&uat_allocated_fields, lwm2m_uat_resources, num_lwm2m_uat_resources);
	}
}

static void lwm2m_resource_reset_cb(void)
{
	lwm2m_free_fields(&uat_allocated_fields);
}

static int64_t
decodeVariableInt(tvbuff_t *tvb, const int offset, const unsigned length)
{
	switch(length)
	{
	case 1:
		return tvb_get_int8(tvb, offset);
	case 2:
		return tvb_get_ntohis(tvb, offset);
	case 3:
		return tvb_get_ntohi24(tvb, offset);
	case 4:
		return tvb_get_ntohil(tvb, offset);
	case 5:
		return tvb_get_ntohi40(tvb, offset);
	case 6:
		return tvb_get_ntohi48(tvb, offset);
	case 7:
		return tvb_get_ntohi56(tvb, offset);
	case 8:
		return tvb_get_ntohi64(tvb, offset);
	default:
		return 0;
	}
}

UAT_DEC_CB_DEF(resource, object_id, lwm2m_resource_t)
UAT_DEC_CB_DEF(resource, resource_id, lwm2m_resource_t)
UAT_CSTRING_CB_DEF(resource, name, lwm2m_resource_t)
UAT_VS_DEF(resource, data_type, lwm2m_resource_t, unsigned, DATA_TYPE_NONE, "None")

static void
addTlvHeaderElements(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_type, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_length_of_identifier, tvb, 0, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_length_of_length, tvb, 0, 1, ENC_BIG_ENDIAN);
	if ( element->length_of_length == 0 ) {
		proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_length, tvb, 0, 1, ENC_BIG_ENDIAN);
	} else {
		proto_tree_add_item(tlv_tree, hf_lwm2mtlv_type_ignored, tvb, 0, 1, ENC_BIG_ENDIAN);
	}

	proto_tree_add_item(tlv_tree, hf_lwm2mtlv_identifier, tvb, 1, element->length_of_identifier, ENC_BIG_ENDIAN);

	if ( element->length_of_length > 0 ) {
		proto_tree_add_item(tlv_tree, hf_lwm2mtlv_length, tvb, 1+element->length_of_identifier, element->length_of_length, ENC_BIG_ENDIAN);
	}
}

static void
addTlvHeaderTree(tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element)
{
	proto_item *item = NULL;
	proto_tree *header_tree = NULL;

	unsigned valueOffset = 1 + element->length_of_identifier + element->length_of_length;

	item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_header, tvb, 0, valueOffset, ENC_NA);
	header_tree = proto_item_add_subtree(item, ett_lwm2mtlv_header);
	addTlvHeaderElements(tvb, header_tree, element);
}

static proto_tree*
addElementTree(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element, const lwm2m_resource_t *resource)
{
	proto_item *item = NULL;
	char *identifier = NULL;
	int ett_id;

	if (resource) {
		identifier = wmem_strdup_printf(pinfo->pool, "[%02u] %s", element->identifier, resource->name);
	} else {
		identifier = wmem_strdup_printf(pinfo->pool, "[%02u]", element->identifier);
	}

	switch ( element->type )
	{
	case OBJECT_INSTANCE:
		item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_object_instance, tvb, 0, element->totalLength, ENC_NA);
		proto_item_append_text(item, " %02u", element->identifier);
		return proto_item_add_subtree(item, ett_lwm2mtlv_object_instance);

	case RESOURCE_INSTANCE:
		item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_resource_instance, tvb, 0, element->totalLength, ENC_NA);
		proto_item_set_text(item, "%02u", element->identifier);
		return proto_item_add_subtree(item, ett_lwm2mtlv_resource_instance);

	case RESOURCE_ARRAY:
		ett_id = resource ? resource->ett_id : ett_lwm2mtlv_resource_array;
		item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_resource_array, tvb, 0, element->totalLength, ENC_NA);
		proto_item_set_text(item, "%s", identifier);
		return proto_item_add_subtree(item, ett_id);

	case RESOURCE:
		ett_id = resource ? resource->ett_id : ett_lwm2mtlv_resource;
		item = proto_tree_add_item(tlv_tree, hf_lwm2mtlv_resource, tvb, 0, element->totalLength, ENC_NA);
		proto_item_set_text(item, "%s", identifier);
		return proto_item_add_subtree(item, ett_id);
	}
	return NULL;
}

static void
addValueInterpretations(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element, const lwm2m_resource_t *resource)
{
	unsigned valueOffset;
	if ( element->length_of_value == 0 ) return;

	valueOffset = 1 + element->length_of_identifier + element->length_of_length;

	if (resource && resource->data_type != DATA_TYPE_NONE) {
		switch (resource->data_type) {
		case DATA_TYPE_STRING:
		case DATA_TYPE_CORELNK:
		{
			const uint8_t *strval;
			proto_tree_add_item_ret_string(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, ENC_UTF_8, pinfo->pool, &strval);
			proto_item_append_text(tlv_tree, ": %s", format_text(pinfo->pool, strval, strlen(strval)));
			break;
		}
		case DATA_TYPE_INTEGER:
			proto_tree_add_item(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_item_append_text(tlv_tree, ": %" PRId64, decodeVariableInt(tvb, valueOffset, element->length_of_value));
			break;
		case DATA_TYPE_UNSIGNED_INTEGER:
		{
			uint64_t value;
			proto_tree_add_item_ret_uint64(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN, &value);
			proto_item_append_text(tlv_tree, ": %" PRIu64, value);
			break;
		}
		case DATA_TYPE_FLOAT:
			proto_tree_add_item(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			if (element->length_of_value == 4) {
				proto_item_append_text(tlv_tree, ": %." G_STRINGIFY(FLT_DIG) "g", tvb_get_ieee_float(tvb, valueOffset, ENC_BIG_ENDIAN));
			} else {
				proto_item_append_text(tlv_tree, ": %." G_STRINGIFY(DBL_DIG) "g", tvb_get_ieee_double(tvb, valueOffset, ENC_BIG_ENDIAN));
			}
			break;
		case DATA_TYPE_BOOLEAN:
		{
			bool boolval;
			proto_tree_add_item_ret_boolean(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN, &boolval);
			proto_item_append_text(tlv_tree, ": %s", boolval ? "True" : "False");
			break;
		}
		case DATA_TYPE_TIME:
		{
			nstime_t ts;
			ts.secs = (time_t)decodeVariableInt(tvb, valueOffset, element->length_of_value);
			ts.nsecs = 0;
			proto_tree_add_time(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, &ts);
			proto_item_append_text(tlv_tree, ": %s", abs_time_to_str(pinfo->pool, &ts, ABSOLUTE_TIME_LOCAL, false));
			break;
		}
		case DATA_TYPE_OBJLNK:
		{
			uint16_t lnk1 = tvb_get_uint16(tvb, valueOffset, ENC_BIG_ENDIAN);
			uint16_t lnk2 = tvb_get_uint16(tvb, valueOffset + 2, ENC_BIG_ENDIAN);
			proto_tree_add_bytes_format(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, NULL, "%u:%u", lnk1, lnk2);
			proto_item_append_text(tlv_tree, ": %u:%u", lnk1, lnk2);
			break;
		}
		case DATA_TYPE_OPAQUE:
		default:
		{
			proto_item *ti = proto_tree_add_item(tlv_tree, *resource->hf_id, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);

			proto_item_append_text(tlv_tree, ": %s", tvb_bytes_to_str(pinfo->pool, tvb, valueOffset, element->length_of_value));

			if (resource->object_id == 6 && resource->resource_id == 4) {
				proto_tree *pt = proto_item_add_subtree(ti, ett_lwm2mtlv_location_velocity);
				dissect_description_of_velocity(tvb, pt, pinfo, valueOffset, element->length_of_value, NULL, 0);
			}
			break;
		}
		}
	} else {
		uint8_t *str = tvb_get_string_enc(pinfo->pool, tvb, valueOffset, element->length_of_value, ENC_UTF_8);
		if (isprint_utf8_string(str, element->length_of_value)) {
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_string, tvb, valueOffset, element->length_of_value, ENC_UTF_8);
		} else {
			str = tvb_bytes_to_str(pinfo->pool, tvb, valueOffset, element->length_of_value);
		}
		proto_item_append_text(tlv_tree, ": %s", str);

		switch(element->length_of_value) {
		case 0x01:
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_unsigned_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			if (tvb_get_uint8(tvb, valueOffset) < 2) {
				proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_boolean, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			}
			break;
		case 0x02:
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_unsigned_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			break;
		case 0x04:
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_unsigned_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_float, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_timestamp, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			break;
		case 0x08:
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_unsigned_integer, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_double, tvb, valueOffset, element->length_of_value, ENC_BIG_ENDIAN);
			/* apparently, wireshark does not deal well with 8 bytes. */
			proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value_timestamp, tvb, valueOffset+4, element->length_of_value-4, ENC_BIG_ENDIAN);
			break;
		}
	}
}

static void
// NOLINTNEXTLINE(misc-no-recursion)
addValueTree(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element, int object_id, int resource_id, const lwm2m_resource_t *resource)
{
	unsigned valueOffset = 1 + element->length_of_identifier + element->length_of_length;

	if (resource && (element->type == RESOURCE || element->type == RESOURCE_ARRAY)) {
		proto_item *ti = proto_tree_add_string(tlv_tree, hf_lwm2mtlv_resource_name, tvb, 0, 0, resource->name);
		proto_item_set_generated(ti);
	}

	if ( element->type == RESOURCE || element->type == RESOURCE_INSTANCE ) {
		proto_tree_add_item(tlv_tree, hf_lwm2mtlv_value, tvb, valueOffset, element->length_of_value, ENC_NA);
		addValueInterpretations(pinfo, tvb, tlv_tree, element, resource);
	} else {
		tvbuff_t* sub = tvb_new_subset_length(tvb, valueOffset, element->length_of_value);
		parseArrayOfElements(pinfo, sub, tlv_tree, object_id, resource_id);
	}
}

static void
// NOLINTNEXTLINE(misc-no-recursion)
addTlvElement(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tlv_tree, lwm2mElement_t *element, int object_id, int resource_id)
{
	proto_tree *element_tree = NULL;
	const lwm2m_resource_t *resource = NULL;

	if (object_id != -1 && resource_id != -1) {
		/* First search user configured objects */
		resource = lwm2m_search_fields(object_id, resource_id, element->length_of_value,
					       &uat_allocated_fields, lwm2m_uat_resources, num_lwm2m_uat_resources);

		if (resource == NULL) {
			/* Then search OMA objects */
			resource = lwm2m_search_fields(object_id, resource_id, element->length_of_value,
						       &oma_allocated_fields, lwm2m_oma_resources, num_lwm2m_oma_resources);
		}
	}

	element_tree = addElementTree(pinfo, tvb, tlv_tree, element, resource);
	addTlvHeaderTree(tvb, element_tree, element);
	addValueTree(pinfo, tvb, element_tree, element, object_id, resource_id, resource);
}

static uint64_t
decodeVariableUInt(tvbuff_t *tvb, const int offset, const unsigned length)
{
	switch(length)
	{
	case 1:
		return tvb_get_uint8(tvb, offset);
	case 2:
		return tvb_get_ntohs(tvb, offset);
	case 3:
		return tvb_get_ntoh24(tvb, offset);
	case 4:
		return tvb_get_ntohl(tvb, offset);
	case 5:
		return tvb_get_ntoh40(tvb, offset);
	case 6:
		return tvb_get_ntoh48(tvb, offset);
	case 7:
		return tvb_get_ntoh56(tvb, offset);
	case 8:
		return tvb_get_ntoh64(tvb, offset);
	default:
		return 0;
	}
}

static unsigned parseTLVHeader(tvbuff_t *tvb, lwm2mElement_t *element)
{
	unsigned type_field = tvb_get_uint8(tvb, 0);
	element->type                 = (( type_field >> 6 ) & 0x03 );
	element->length_of_identifier = (( type_field >> 5 ) & 0x01 ) + 1;
	element->length_of_length     = (( type_field >> 3 ) & 0x03 );
	element->length_of_value      = (( type_field >> 0 ) & 0x07 );

	/* It is ok to shorten identifier and length_of_value, they are never more than 24 bits long */
	element->identifier = (unsigned) decodeVariableUInt(tvb, 1, element->length_of_identifier);
	if ( element->length_of_length > 0 ) {
		element->length_of_value = (unsigned) decodeVariableUInt(tvb, 1 + element->length_of_identifier, element->length_of_length);
	}

	element->totalLength = 1 + element->length_of_identifier + element->length_of_length + element->length_of_value;

	return element->totalLength;
}

// NOLINTNEXTLINE(misc-no-recursion)
static void parseArrayOfElements(packet_info *pinfo, tvbuff_t *tvb, proto_tree *tlv_tree, int object_id, int resource_id)
{
	unsigned length;
	unsigned offset = 0;
	unsigned elementLength = 0;
	unsigned element_count = 0;
	lwm2mElement_t element;

	length = tvb_reported_length(tvb);

	increment_dissection_depth(pinfo);
	while ( length > 0 ) {
		tvbuff_t* sub = tvb_new_subset_length(tvb, offset, length);
		elementLength = parseTLVHeader(sub, &element);
		if (element.type == RESOURCE || element.type == RESOURCE_ARRAY) {
			resource_id = (int)element.identifier;
		}
		addTlvElement(pinfo, sub, tlv_tree, &element, object_id, resource_id);
		element_count++;

		length -= elementLength;
		offset += elementLength;
		if ( elementLength == 0 )
		{
			break;
		}
	}
	decrement_dissection_depth(pinfo);

	proto_item_append_text(tlv_tree, " (%u element%s)", element_count, plurality(element_count, "", "s"));
}

static int
dissect_lwm2mtlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	proto_tree* lwm2mtlv_tree;
	proto_item* lwm2mtlv_item;
	media_content_info_t *content_info = (media_content_info_t *) data;
	int object_id = -1;
	int resource_id = -1;

	if (content_info && content_info->media_str && content_info->media_str[0]) {
		char **ids = wmem_strsplit(pinfo->pool, content_info->media_str, "/", 5);

		/* URI path is defined as:
		 *  ids[1] = Object ID
		 *  ids[2] = Object Instance
		 *  ids[3] = Resource ID
		 *  ids[4] = Resource Instance
		 */
		if (ids && ids[0] && ids[1]) {
			object_id = (int)strtol(ids[1], NULL, 10);

			if (ids[2] && ids[3]) {
				resource_id = (int)strtol(ids[1], NULL, 10);
			}
		}
	}

	if (tree) { /* we are being asked for details */
		lwm2mtlv_item = proto_tree_add_item(tree, proto_lwm2mtlv, tvb, 0, -1, ENC_NA);
		lwm2mtlv_tree = proto_item_add_subtree(lwm2mtlv_item, ett_lwm2mtlv);

		if (object_id != -1) {
			const char *object_name = NULL;

			for (unsigned i = 0; i < num_lwm2m_uat_object_names; i++) {
				if ((unsigned)object_id == lwm2m_uat_object_names[i].object_id) {
					object_name = lwm2m_uat_object_names[i].name;
					break;
				}
			}

			if (!object_name) {
				object_name = val_to_str_const(object_id, lwm2m_oma_objects, "");
			}

			if (object_name && object_name[0]) {
				proto_item *ti = proto_tree_add_string(lwm2mtlv_tree, hf_lwm2mtlv_object_name, tvb, 0, 0, object_name);
				proto_item_set_generated(ti);
				proto_item_append_text(lwm2mtlv_item, ", %s", object_name);
			}
		}

		parseArrayOfElements(pinfo, tvb, lwm2mtlv_tree, object_id, resource_id);
	}
	return tvb_captured_length(tvb);
}

static void lwm2m_shutdown_routine(void)
{
	lwm2m_free_fields(&oma_allocated_fields);
}

void proto_register_lwm2mtlv(void)
{
	static hf_register_info hf[] = {
		{ &hf_lwm2mtlv_object_name,
			{ "Object Name", "lwm2mtlv.object_name",
				FT_STRING, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_resource_name,
			{ "Resource Name", "lwm2mtlv.resource_name",
				FT_STRING, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_header,
			{ "TLV header", "lwm2mtlv.header",
				FT_NONE, BASE_NONE, NULL, 0x0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_type_type,
			{ "Type of Identifier", "lwm2mtlv.type.type",
				FT_UINT8, BASE_DEC, VALS(identifiers), 0xC0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_type_length_of_identifier,
			{ "Length of Identifier", "lwm2mtlv.type.loi",
				FT_UINT8, BASE_DEC, VALS(length_identifier), 0x20,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_type_length_of_length,
			{ "Length of Length", "lwm2mtlv.type.lol",
				FT_UINT8, BASE_DEC, VALS(length_type), 0x18,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_type_length,
			{ "Length", "lwm2mtlv.type.length",
				FT_UINT8, BASE_DEC, NULL, 0x07,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_type_ignored,
			{ "Ignored", "lwm2mtlv.type.ignored",
				FT_UINT8, BASE_DEC, NULL, 0x07,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_identifier,
			{ "Identifier", "lwm2mtlv.identifier",
				FT_UINT16, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_length,
			{ "Length", "lwm2mtlv.length",
				FT_UINT32, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value,
			{ "Value", "lwm2mtlv.value",
				FT_BYTES, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_string,
			{ "As String", "lwm2mtlv.value.string",
				FT_STRING, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_integer,
			{ "As Integer", "lwm2mtlv.value.integer",
				FT_INT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_unsigned_integer,
			{ "As Unsigned Integer", "lwm2mtlv.value.unsigned_integer",
				FT_UINT64, BASE_DEC, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_float,
			{ "As Float", "lwm2mtlv.value.float",
				FT_FLOAT, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_double,
			{ "As Double", "lwm2mtlv.value.double",
				FT_DOUBLE, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_boolean,
			{ "As Boolean", "lwm2mtlv.value.boolean",
				FT_BOOLEAN, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_value_timestamp,
			{ "As Timestamp", "lwm2mtlv.value.timestamp",
				FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_object_instance,
			{ "Object Instance", "lwm2mtlv.object_instance",
				FT_NONE, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_resource_instance,
			{ "Resource Instance", "lwm2mtlv.resource_instance",
				FT_NONE, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_resource_array,
			{ "Resource Array", "lwm2mtlv.resource_array",
				FT_NONE, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
		{ &hf_lwm2mtlv_resource,
			{ "Resource", "lwm2mtlv.resource",
				FT_NONE, BASE_NONE, NULL, 0,
				NULL, HFILL }
		},
	};

	static int* ett[] = {
		&ett_lwm2mtlv,
		&ett_lwm2mtlv_header,
		&ett_lwm2mtlv_resource,
		&ett_lwm2mtlv_resource_instance,
		&ett_lwm2mtlv_resource_array,
		&ett_lwm2mtlv_object_instance,
		&ett_lwm2mtlv_location_velocity
	};

	static uat_field_t lwm2m_object_name_flds[] = {
		UAT_FLD_DEC(object_name, object_id, "Object ID", "Object ID"),
		UAT_FLD_CSTRING(object_name, name, "Object Name", "Object Name"),
		UAT_END_FIELDS
	};

	static uat_field_t lwm2m_resource_flds[] = {
		UAT_FLD_DEC(resource, object_id, "Object ID", "Object ID"),
		UAT_FLD_DEC(resource, resource_id, "Resource ID", "Resource ID"),
		UAT_FLD_CSTRING(resource, name, "Resource Name", "Resource Name"),
		UAT_FLD_VS(resource, data_type, "Data Type", data_types, "Data Type"),
		UAT_END_FIELDS
	};

	uat_t *object_name_uat = uat_new("User Object Names",
	                                 sizeof(lwm2m_object_name_t),
	                                 "lwm2m_object_names",
	                                 true,
	                                 &lwm2m_uat_object_names,
	                                 &num_lwm2m_uat_object_names,
	                                 UAT_AFFECTS_DISSECTION,
	                                 "ChLwM2MResourceNames",
	                                 lwm2m_object_name_copy_cb,
	                                 lwm2m_object_name_update_cb,
	                                 lwm2m_object_name_free_cb,
	                                 NULL,
	                                 NULL,
	                                 lwm2m_object_name_flds);

	uat_t *resource_uat = uat_new("User Resource Names",
	                              sizeof(lwm2m_resource_t),
	                              "lwm2m_resource_names",
	                              true,
	                              &lwm2m_uat_resources,
	                              &num_lwm2m_uat_resources,
	                              UAT_AFFECTS_DISSECTION|UAT_AFFECTS_FIELDS,
	                              "ChLwM2MResourceNames",
	                              lwm2m_resource_copy_cb,
	                              lwm2m_resource_update_cb,
	                              lwm2m_resource_free_cb,
	                              lwm2m_resource_post_update_cb,
	                              lwm2m_resource_reset_cb,
	                              lwm2m_resource_flds);

	module_t *lwm2mtlv_module;

	/* Register our configuration options */
	proto_lwm2mtlv = proto_register_protocol ("Lightweight M2M TLV", "LwM2M-TLV","lwm2mtlv");

	proto_register_field_array(proto_lwm2mtlv, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	lwm2mtlv_handle = register_dissector("lwm2mtlv", dissect_lwm2mtlv, proto_lwm2mtlv);

	/* Register the dissector shutdown function */
	register_shutdown_routine(lwm2m_shutdown_routine);

	lwm2mtlv_module = prefs_register_protocol(proto_lwm2mtlv, NULL);

	prefs_register_uat_preference(lwm2mtlv_module, "object_table",
	                              "Object Names",
	                              "User Object Names",
	                              object_name_uat);

	prefs_register_uat_preference(lwm2mtlv_module, "resource_table",
	                              "Resource Names",
	                              "User Resource Names",
	                              resource_uat);

	lwm2m_allocate_fields(&oma_allocated_fields, lwm2m_oma_resources, num_lwm2m_oma_resources);
}

void
proto_reg_handoff_lwm2mtlv(void)
{
	dissector_add_string("media_type", "application/vnd.oma.lwm2m+tlv", lwm2mtlv_handle);
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
