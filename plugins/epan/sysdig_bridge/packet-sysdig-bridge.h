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

#define PROTO_DATA_BRIDGE_HANDLE   0x00

#define PLG_PARAM_TYPE_UINT64 8
#define PLG_PARAM_TYPE_CHARBUF 9

#define FLD_FLAG_USE_IN_INFO 1

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

typedef struct async_extractor_info
{
    guint64 evtnum;
    guint32 id;
    guint32 ftype;
    char* arg;
    char* data;
    guint32 datalen;
    guint32 field_present;
    char* res_str;
    guint64 res_u64;
    gint32 rc;
    cb_wait_t cb_wait;
    void* wait_ctx;
} async_extractor_info;

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
    gint32 (*next)(ss_plugin_t* s, ss_instance_t* h, guint8** data, guint64* datalen, guint64* ts);
    char* (*get_progress)(ss_plugin_t* s, ss_instance_t* h, guint64* progress_pct);
    char *(*event_to_string)(ss_plugin_t *s, guint8 *data, guint64 datalen);
    char *(*extract_str)(ss_plugin_t *s, guint64 evtnum, guint64 id, char *arg, guint8 *data, guint64 datalen);
    guint64 (*extract_u64)(ss_plugin_t *s, guint64 evtnum, guint64 id, char *arg, guint8 *data, guint64 datalen, guint64 *field_present);
    gint32 (*next_batch)(ss_plugin_t* s, ss_instance_t* h, guint8** data, guint64* datalen);
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
    guint64* field_ids;
    guint32* field_flags;
    guint32 n_fields;
}bridge_info;

