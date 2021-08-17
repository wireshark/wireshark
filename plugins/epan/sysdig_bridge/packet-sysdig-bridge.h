/* packet-sysdig-bridge.h
 *
 * By Loris Degioanni
 * Copyright (C) 2021 Sysdig, Inc.
*
* Wireshark - Network traffic analyzer
* By Gerald Combs <gerald@wireshark.org>
* Copyright 1998 Gerald Combs
*
* SPDX-License-Identifier: GPL-2.0-or-later
*/

/*
 * API versions of this plugin engine
 */
#define PLUGIN_API_VERSION_MAJOR 1
#define PLUGIN_API_VERSION_MINOR 0
#define PLUGIN_API_VERSION_PATCH 0

/*
 * Return types
 */
#define SCAP_SUCCESS 0
#define SCAP_FAILURE 1
#define SCAP_TIMEOUT -1
#define SCAP_ILLEGAL_INPUT 3
#define SCAP_NOTFOUND 4
#define SCAP_INPUT_TOO_SMALL 5
#define SCAP_EOF 6
#define SCAP_UNEXPECTED_BLOCK 7
#define SCAP_VERSION_MISMATCH 8
#define SCAP_NOT_SUPPORTED 9

#define PROTO_DATA_BRIDGE_HANDLE    0x00
#define PROTO_DATA_CONVINFO_USER_0   10000
#define PROTO_DATA_CONVINFO_USER_1   10001
#define PROTO_DATA_CONVINFO_USER_2   10002
#define PROTO_DATA_CONVINFO_USER_3   10003
#define PROTO_DATA_CONVINFO_USER_4   10004
#define PROTO_DATA_CONVINFO_USER_5   10005
#define PROTO_DATA_CONVINFO_USER_6   10006
#define PROTO_DATA_CONVINFO_USER_7   10007
#define PROTO_DATA_CONVINFO_USER_8   10008
#define PROTO_DATA_CONVINFO_USER_9   10009
#define PROTO_DATA_CONVINFO_USER_10  10010
#define PROTO_DATA_CONVINFO_USER_11  10011
#define PROTO_DATA_CONVINFO_USER_12  10012
#define PROTO_DATA_CONVINFO_USER_13  10013
#define PROTO_DATA_CONVINFO_USER_14  10014
#define PROTO_DATA_CONVINFO_USER_15  10015
#define PROTO_DATA_CONVINFO_USER_BASE PROTO_DATA_CONVINFO_USER_0

#define PLG_PARAM_TYPE_UINT64 8
#define PLG_PARAM_TYPE_CHARBUF 9

#define FLD_FLAG_USE_IN_INFO 1
#define FLD_FLAG_USE_IN_CONVERSATIONS (1 << 1)

/*
 * Plugin types
 */
typedef enum ss_plugin_type
{
    TYPE_SOURCE_PLUGIN = 1,
    TYPE_EXTRACTOR_PLUGIN = 2
}ss_plugin_type;

typedef enum async_extractor_lock_state
{
    LS_INIT = 0,
    LS_INPUT_READY = 1,
    LS_PROCESSING = 2,
    LS_DONE = 3,
    LS_SHUTDOWN_REQ = 4,
    LS_SHUTDOWN_DONE = 5,
} async_extractor_lock_state;

typedef gboolean (*cb_wait_t)(void* wait_ctx);

/*
 * This is the opaque pointer to the state of a source plugin.
 * It points to any data that might be needed plugin-wise. It is 
 * allocated by init() and must be destroyed by destroy().
 * It is defined as void because the engine doesn't care what it is
 * and it treats is as opaque.
 */
typedef void ss_plugin_t;

/*
 * This is the opaque pointer to the state of an open instance of the source 
 * plugin.
 * It points to any data that is needed while a capture is running. It is 
 * allocated by open() and must be destroyed by close().
 * It is defined as void because the engine doesn't care what it is
 * and it treats is as opaque.
 */
typedef void ss_instance_t;

// This struct represents an event returned by the plugin, and is used
// below in next()/next_batch().
// - evtnum: incremented for each event returned. Might not be contiguous.
// - data: pointer to a memory buffer pointer. The plugin will set it
//   to point to the memory containing the next event. Once returned,
//   the memory is owned by the plugin framework and will be freed via
//   a call to free().
// - datalen: pointer to a 32bit integer. The plugin will set it the size of the
//   buffer pointed by data.
// - ts: the event timestamp. Can be (uint64_t)-1, in which case the engine will
//   automatically fill the event time with the current time.
typedef struct ss_plugin_event
{
	uint64_t evtnum;
	uint8_t *data;
	uint32_t datalen;
	uint64_t ts;
} ss_plugin_event;

// Used in extract_fields functions below to receive a field/arg
// pair and return an extracted value.
// field: the field name.
// arg: the field argument, if an argument has been specified
//      for the field, otherwise it's NULL.
//      For example:
//         * if the field specified by the user is foo.bar[pippo], arg will be the
//           string "pippo"
//         * if the field specified by the user is foo.bar, arg will be NULL
// ftype: the type of the field. Could be derived from the field name alone,
//   but including here can prevent a second lookup of field names.
// The following should be filled in by the extraction function:
// - field_present: set to true if the event has a meaningful
//   extracted value for the provided field, false otherwise
// - res_str: if the corresponding field was type==string, this should be
//   filled in with the string value. The string should be allocated by
//   the plugin using malloc() and will be free()d by the plugin framework.
// - res_u64: if the corresponding field was type==uint64, this should be
//   filled in with the uint64 value.

typedef struct ss_plugin_extract_field
{
	const char *field;
	const char *arg;
	uint32_t ftype;

	bool field_present;
	char *res_str;
	uint64_t res_u64;
} ss_plugin_extract_field;

typedef struct async_extractor_info
{
    // Pointer as this allows swapping out events from other
    // structs.
    const ss_plugin_event *evt;
    ss_plugin_extract_field *field;
    gint32 rc;
    cb_wait_t cb_wait;
    void* wait_ctx;
} async_extractor_info;


/*
 * Interface of a sinsp/scap plugin
 */
typedef struct
{
    ss_plugin_t* (*init)(char* config, gint32* rc);
    void (*destroy)(ss_plugin_t* s);
    char* (*get_last_error)(ss_plugin_t* s);
    guint64 (*get_type)(void);
    guint64 (*get_id)(void);
    char* (*get_name)(void);
    char* (*get_filter_name)(void);
    char* (*get_description)(void);
    char* (*get_required_api_version)(void);
    char* (*get_fields)(void);
    ss_instance_t* (*open)(ss_plugin_t* s, char* params, gint32* rc);
    void (*close)(ss_plugin_t* s, ss_instance_t* h);
    gint32 (*next)(ss_plugin_t* s, ss_instance_t* h, ss_plugin_event **evt);
    char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, guint64* progress_pct);
    char *(*event_to_string)(ss_plugin_t *s, guint8 *data, guint64 datalen);
    int32_t (*extract_fields)(ss_plugin_t *s, const ss_plugin_event *evt, uint32_t num_fields, ss_plugin_extract_field *fields);
    gint32 (*next_batch)(ss_plugin_t* s, ss_instance_t* h, uint32_t *nevts, ss_plugin_event **evts);
    gint32 (*register_async_extractor)(ss_plugin_t *s, async_extractor_info *info);

    //
    // The following members are PRIVATE for the engine and should not be touched.
    //
    ss_plugin_t* state;
    ss_instance_t* handle;
    guint32 id;
    char* name;
    async_extractor_info async_extractor_info;
    gboolean is_async_extractor_configured;
    gboolean is_async_extractor_present;
    volatile int lock;
} ss_plugin_info;

typedef struct bridge_info {
    ss_plugin_info si;
    int proto;
    hf_register_info* hf;
    int* hf_ids;
    guint32* field_flags;
    guint32 n_fields;
}bridge_info;

typedef struct conv_fld_info {
    char* proto_name;
    hf_register_info* field_info;
    char field_val[4096];
}conv_fld_info;

