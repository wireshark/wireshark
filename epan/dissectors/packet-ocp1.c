/* packet-ocp1.c
 * Dissector for Open Control Protocol OCP.1/AES70
 *
 * Copyright (c) 2021 by Martin Mayer <martin.mayer@m2-it-solutions.de>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include "packet-tcp.h"

#define OCP1_SYNC_VAL                0x3B
#define OCP1_PROTO_VER             0x0001
#define OCP1_FRAME_HEADER_LEN          10

/* PDU Types */
#define OCP1_PDU_TYPE_OCA_CMD        0x00
#define OCP1_PDU_TYPE_OCA_CMD_RRQ    0x01
#define OCP1_PDU_TYPE_OCA_NTF        0x02
#define OCP1_PDU_TYPE_OCA_RSP        0x03
#define OCP1_PDU_TYPE_OCA_KEEPALIVE  0x04

/* DeviceState flags */
#define OCP1_DEVICESTATE_OPER        0x01
#define OCP1_DEVICESTATE_DISABLED    0x02
#define OCP1_DEVICESTATE_ERROR       0x04
#define OCP1_DEVICESTATE_INIT        0x08
#define OCP1_DEVICESTATE_UPDATING    0x10

/* no valid PDU type, only used as array index for type errors
 * must be highest PDU type + 1 */
#define OCP1_PDU_TYPE_ERROR_INDEX    0x05

/* Handle Hashmap Key */
struct oca_request_hash_key {
    guint32 conv_index;
    guint32 handle;
};
/* Handle Hashmap Val */
struct oca_request_hash_val {
    guint32 pnum;
    guint32 ono;
    guint16 tree_level;
    guint16 method_index;
};
static wmem_map_t *oca_request_hash_map = NULL;

void proto_register_ocp1(void);
void proto_reg_handoff_ocp1(void);

static dissector_handle_t ocp1_tcp_handle;
static dissector_handle_t ocp1_udp_handle;

static int proto_ocp1 = -1;
expert_module_t* expert_ocp1;

/* Header Fields */
static int hf_ocp1_sync_value = -1;
static int hf_ocp1_protocol_version = -1;
static int hf_ocp1_pdu_size = -1;
static int hf_ocp1_pdu_type = -1;
static int hf_ocp1_message_count = -1;

/* Keep-Alive Fields */
static int hf_ocp1_heartbeat_time_s = -1;
static int hf_ocp1_heartbeat_time_ms = -1;

/* Common Fields */
static int hf_ocp1_message_size = -1;
static int hf_ocp1_message_handle = -1;
static int hf_ocp1_message_target_ono = -1;
static int hf_ocp1_message_emitter_ono = -1;
static int hf_ocp1_message_occ = -1;
static int hf_ocp1_message_method_id = -1;
static int hf_ocp1_message_method_tree_level = -1;
static int hf_ocp1_message_method_index = -1;
static int hf_ocp1_message_event_id = -1;
static int hf_ocp1_message_event_tree_level = -1;
static int hf_ocp1_message_event_index = -1;
static int hf_ocp1_message_parameter_count = -1;
static int hf_ocp1_message_status_code = -1;
static int hf_ocp1_response_to = -1;

/* Notification Fields */
static int hf_ocp1_notification_parameter_context = -1;

/* Parameters */
static int hf_ocp1_params = -1;
static int hf_ocp1_params_bool = -1;
static int hf_ocp1_params_ono = -1;
static int hf_ocp1_params_event_id = -1;
static int hf_ocp1_params_event_tree_level = -1;
static int hf_ocp1_params_event_index = -1;
static int hf_ocp1_params_method_id = -1;
static int hf_ocp1_params_method_tree_level = -1;
static int hf_ocp1_params_method_index = -1;
static int hf_ocp1_params_property_id = -1;
static int hf_ocp1_params_property_tree_level = -1;
static int hf_ocp1_params_property_index = -1;
static int hf_ocp1_params_blob = -1;
static int hf_ocp1_params_blob_datasize = -1;
static int hf_ocp1_params_blob_data = -1;
static int hf_ocp1_params_string = -1;
static int hf_ocp1_params_string_length = -1;
static int hf_ocp1_params_string_value = -1;
static int hf_ocp1_params_ntf_delivery_mode = -1;
static int hf_ocp1_params_list_count = -1;
static int hf_ocp1_params_map_count = -1;
static int hf_ocp1_params_imageid = -1;
static int hf_ocp1_params_classid = -1;
static int hf_ocp1_params_classid_fields = -1;
static int hf_ocp1_params_class_version = -1;
static int hf_ocp1_params_oca_version = -1;
static int hf_ocp1_params_reset_cause = -1;
static int hf_ocp1_params_power_state = -1;
static int hf_ocp1_params_media_clock_type = -1;
static int hf_ocp1_params_component = -1;
static int hf_ocp1_params_devicestate = -1;
static int hf_ocp1_params_devicestate_oper = -1;
static int hf_ocp1_params_devicestate_disabled = -1;
static int hf_ocp1_params_devicestate_error = -1;
static int hf_ocp1_params_devicestate_init = -1;
static int hf_ocp1_params_devicestate_updating = -1;
static int hf_ocp1_params_ocaver_major = -1;
static int hf_ocp1_params_ocaver_minor = -1;
static int hf_ocp1_params_ocaver_build = -1;
static int hf_ocp1_params_ocaver_comp = -1;
static int hf_ocp1_params_subscriber_ctx_len = -1;
static int hf_ocp1_params_libvol_id = -1;
static int hf_ocp1_params_libvoltype_id = -1;
static int hf_ocp1_params_library_count = -1;
static int hf_ocp1_params_time_ntp = -1;
static int hf_ocp1_params_time_ptp = -1;
static int hf_ocp1_params_time_ptp_negative = -1;
static int hf_ocp1_params_time_ptp_seconds = -1;
static int hf_ocp1_params_time_ptp_nanoseconds = -1;
static int hf_ocp1_params_time_mode = -1;
static int hf_ocp1_params_time_units = -1;
static int hf_ocp1_params_task_id = -1;
static int hf_ocp1_params_task_group_id = -1;
static int hf_ocp1_params_time_interval = -1;
static int hf_ocp1_params_start_time = -1;
static int hf_ocp1_params_task_command = -1;
static int hf_ocp1_params_task_manager_state = -1;
static int hf_ocp1_params_task_state = -1;
static int hf_ocp1_params_task_status_error_code = -1;
static int hf_ocp1_params_media_coding_scheme_id = -1;

/* Expert fields */
static expert_field ei_ocp1_handle_fail = EI_INIT;
static expert_field ei_ocp1_bad_status_code = EI_INIT;

/* Trees */
static gint ett_ocp1 = -1;
static gint ett_ocp1_pdu = -1;
static gint ett_ocp1_keepalive = -1;
static gint ett_ocp1_message_method = -1;
static gint ett_ocp1_event_data = -1;
static gint ett_ocp1_event_method = -1;
static gint ett_ocp1_params = -1;
static gint ett_ocp1_params_event = -1;
static gint ett_ocp1_params_method = -1;
static gint ett_ocp1_params_property = -1;
static gint ett_ocp1_params_blob = -1;
static gint ett_ocp1_params_string = -1;
static gint ett_ocp1_params_manager_desc = -1;
static gint ett_ocp1_params_devicestate = -1;
static gint ett_ocp1_params_compversion = -1;
static gint ett_ocp1_params_ocaver = -1;
static gint ett_ocp1_params_ptp = -1;

/* PDU Types */
static const value_string pdu_type_vals[] = {
    { OCP1_PDU_TYPE_OCA_CMD,        "Command, no response required" },
    { OCP1_PDU_TYPE_OCA_CMD_RRQ,    "Command, response required" },
    { OCP1_PDU_TYPE_OCA_NTF,        "Notification" },
    { OCP1_PDU_TYPE_OCA_RSP,        "Response" },
    { OCP1_PDU_TYPE_OCA_KEEPALIVE,  "Keep-Alive" },
    { 0,                            NULL }
};

/* OCA enums */
static const value_string OcaStatus[] = {
    { 0x00, "OK" },
    { 0x01, "Protocol Version Error" },
    { 0x02, "Device Error" },
    { 0x03, "Locked" },
    { 0x04, "Bad Format" },
    { 0x05, "Bad Object Number" },
    { 0x06, "Parameter Error" },
    { 0x07, "Parameter Out Of Range" },
    { 0x08, "Not Implemented" },
    { 0x09, "Invalid Request" },
    { 0x0A, "Processing Failed" },
    { 0x0B, "Bad Method" },
    { 0x0C, "Partially Succeeded" },
    { 0x0D, "Timeout" },
    { 0x0E, "Buffer Overflow" },
    { 0,    NULL }
};

static const value_string OcaNotificationDeliveryMode[] = {
    { 0x01, "Reliable" },
    { 0x02, "Fast" },
    { 0,    NULL }
};
static const value_string OcaPowerState[] = {
    { 0x00, "None" },
    { 0x01, "Working" },
    { 0x02, "Standby" },
    { 0x03, "Off" },
    { 0,    NULL }
};
static const value_string OcaMediaClockType[] = {
    { 0x00, "None" },
    { 0x01, "Internal" },
    { 0x02, "Network" },
    { 0x03, "External" },
    { 0,    NULL }
};

static const value_string OcaResetCause[] = {
    { 0x00, "PowerOn" },
    { 0x01, "InternalError" },
    { 0x02, "Upgrade" },
    { 0x03, "ExternalRequest" },
    { 0,    NULL }
};

static const value_string OcaComponent[] = {
    { 0x0000, "BootLoader" },
    { 0,    NULL }
};

static const value_string OcaTaskCommand[] = {
    { 0x00, "None" },
    { 0x01, "Prepare" },
    { 0x02, "Enable" },
    { 0x03, "Start" },
    { 0x04, "Stop" },
    { 0x05, "Abort" },
    { 0x06, "Disable" },
    { 0x07, "Clear" },
    { 0,    NULL }
};

static const value_string OcaTaskManagerState[] = {
    { 0x00, "None" },
    { 0x01, "Enabled" },
    { 0x02, "Disabled" },
    { 0,    NULL }
};

static const value_string OcaTaskState[] = {
    { 0x00, "None" },
    { 0x01, "NotPrepared" },
    { 0x02, "Disabled" },
    { 0x03, "Enabled" },
    { 0x04, "Running" },
    { 0x05, "Completed" },
    { 0x06, "Failed" },
    { 0x07, "Stopped" },
    { 0x08, "Aborted" },
    { 0,    NULL }
};

static const value_string OaFixedONo[] = {
    { 0x01, "OcaDeviceManager" },
    { 0x02, "OcaSecurityManager" },
    { 0x03, "OcaFirmwareManager" },
    { 0x04, "OcaSubscriptionManager" },
    { 0x05, "OcaPowerManager" },
    { 0x06, "OcaNetworkManager" },
    { 0x07, "OcaMediaClockManager" },
    { 0x08, "OcaLibraryManager" },
    { 0x09, "OcaAudioProcessingManager" },
    { 0x0A, "OcaDeviceTimeManager" },
    { 0x0B, "OcaTaskManager" },
    { 0x0C, "OcaCodingManager" },
    { 0x0D, "OcaDiagnosticManager" },
    { 0,    NULL }
};

static const value_string OcaRootMethods[] = {
    { 0x01, "GetClassIdentification" },
    { 0x02, "GetLockable" },
    { 0x03, "LockTotal" },
    { 0x04, "Unlock" },
    { 0x05, "GetRole" },
    { 0x06, "LockReadonly" },
    { 0,    NULL }
};

static const value_string OcaDeviceManagerMethods[] = {
    { 0x01, "GetOcaVersion" },
    { 0x02, "GetModelGUID" },
    { 0x03, "GetSerialNumber" },
    { 0x04, "GetDeviceName" },
    { 0x05, "SetDeviceName" },
    { 0x06, "GetModelDescription" },
    { 0x07, "GetRole" },
    { 0x08, "SetRole" },
    { 0x09, "GetUserInventoryCode" },
    { 0x0A, "SetUserInventoryCode" },
    { 0x0B, "GetEnabled" },
    { 0x0C, "SetEnabled" },
    { 0x0D, "GetState" },
    { 0x0E, "SetResetKey" },
    { 0x0F, "GetResetCause" },
    { 0x10, "ClearResetCause" },
    { 0x11, "GetMessage" },
    { 0x12, "SetMessage" },
    { 0x13, "GetManagers" },
    { 0x14, "GetDeviceRevisionID" },
    { 0,    NULL }
};

static const value_string OcaSecurityManagerMethods[] = {
    { 0x01, "EnableControlSecurity" },
    { 0x02, "DisableControlSecurity" },
    { 0x03, "ChangePreSharedKey" },
    { 0x04, "AddPreSharedKey" },
    { 0x05, "DeletePreSharedKey" },
    { 0,    NULL }
};

static const value_string OcaFirmwareManagerMethods[] = {
    { 0x01, "GetComponentVersions" },
    { 0x02, "StartUpdateProcess" },
    { 0x03, "BeginActiveImageUpdate" },
    { 0x04, "AddImageData" },
    { 0x05, "VerifyImage" },
    { 0x06, "EndActiveImageUpdate" },
    { 0x07, "BeginPassiveComponentUpdate" },
    { 0x08, "EndUpdateProcess" },
    { 0,    NULL }
};

static const value_string OcaSubscriptionManagerMethods[] = {
    { 0x01, "AddSubscription" },
    { 0x02, "RemoveSubscription" },
    { 0x03, "DisableNotifications" },
    { 0x04, "ReEnableNotifications" },
    { 0x05, "AddPropertyChangeSubscription" },
    { 0x06, "RemovePropertyChangeSubscription" },
    { 0x07, "GetMaximumSubscriberContextLength" },
    { 0,    NULL }
};

static const value_string OcaPowerManagerMethods[] = {
    { 0x01, "GetState" },
    { 0x02, "SetState" },
    { 0x03, "GetPowerSupplies" },
    { 0x04, "GetActivePowerSupplies" },
    { 0x05, "ExchangePowerSupply" },
    { 0x06, "GetAutoState" },
    { 0,    NULL }
};

static const value_string OcaNetworkManagerMethods[] = {
    { 0x01, "GetNetworks" },
    { 0x02, "GetStreamNetworks" },
    { 0x03, "GetControlNetworks" },
    { 0x04, "GetMediaTransportNetworks" },
    { 0,    NULL }
};

static const value_string OcaMediaClockManagerMethods[] = {
    { 0x01, "GetClocks" },
    { 0x02, "GetMediaClockTypesSupported" },
    { 0x03, "GetClock3s" },
    { 0,    NULL }
};

static const value_string OcaLibraryManagerMethods[] = {
    { 0x01, "AddLibrary" },
    { 0x02, "DeleteLibrary" },
    { 0x03, "GetLibraryCount" },
    { 0x04, "GetLibraryList" },
    { 0x05, "GetCurrentPatch" },
    { 0x06, "ApplyPatch" },
    { 0,    NULL }
};

static const value_string OcaTimeMode[] = {
    { 0x01, "Absolute" },
    { 0x02, "Relative" },
    { 0, NULL }
};

static const value_string OcaTimeUnits[] = {
    { 0x01, "Seconds" },
    { 0x02, "Samples" },
    { 0, NULL }
};

static const value_string OcaAudioProcessingManagerMethods[] = {
    { 0,    NULL }
};

static const value_string OcaDeviceTimeManagerMethods[] = {
    { 0x01, "GetDeviceTimeNTP" },
    { 0x02, "SetDeviceTimeNTP" },
    { 0x03, "GetTimeSources" },
    { 0x04, "GetCurrentDeviceTimeSource" },
    { 0x05, "SetCurrentDeviceTimeSource" },
    { 0x06, "GetDeviceTimePTP" },
    { 0x07, "SetDeviceTimePTP" },
    { 0,    NULL }
};

static const value_string OcaTaskManagerMethods[] = {
    { 0x01, "Enable" },
    { 0x02, "ControlAllTasks" },
    { 0x03, "ControlTaskGroup" },
    { 0x04, "ControlTask" },
    { 0x05, "GetState" },
    { 0x06, "GetTaskStatuses" },
    { 0x07, "GetTaskStatus" },
    { 0x08, "AddTask" },
    { 0x09, "GetTasks" },
    { 0x0A, "GetTask" },
    { 0x0B, "SetTask" },
    { 0x0C, "DeleteTask"},
    { 0,    NULL }
};

static const value_string OcaCodingManagerMethods[] = {
    { 0x01, "GetAvailableEncodingSchemes" },
    { 0x02, "GetAvailableDecodingSchemes" },
    { 0,    NULL }
};

static const value_string OcaDiagnosticManagerMethods[] = {
    { 0x01, "GetLockStatus" },
    { 0,    NULL }
};


/* wmem hash/equal funcs */
static guint
oca_handle_hash (gconstpointer v)
{
    const struct oca_request_hash_key *key = (const struct oca_request_hash_key *)v;
    guint val;

    val = key->conv_index + key->handle;

    return val;
}

static gint
oca_handle_equal(gconstpointer v, gconstpointer w)
{
    const struct oca_request_hash_key *v1 = (const struct oca_request_hash_key *)v;
    const struct oca_request_hash_key *v2 = (const struct oca_request_hash_key *)w;

    if (
        v1->conv_index == v2->conv_index &&
        v1->handle == v2->handle
    )
    {
        return 1;
    }

    return 0;
}


static void
format_occ(gchar *s, guint64 value) {


    guint32 ono        = value >> 32;
    guint16 tree_level = (guint32)value >> 16;
    guint16 idx        = (guint16)value;

    /* Currently, we can only solve fixed object numbers */
    if(ono < 0x01 || ono > 0x0D) {
        snprintf(s, ITEM_LABEL_LENGTH, "Unknown Object Class");
        return;
    }

    const gchar *unknown_method = "UnknownMethod";
    const gchar *unknown_class = "UnknownClass";

    const gchar *method;

    switch (tree_level) {

        /* OcaRoot Class */
        case 0x0001:
            method = val_to_str_const(idx, OcaRootMethods, unknown_method);
            break;

        /* OcaManager Classes */
        case 0x0003:
            switch (ono) {
                case 0x01:
                    method = val_to_str_const(idx, OcaDeviceManagerMethods, unknown_method);
                    break;
                case 0x02:
                    method = val_to_str_const(idx, OcaSecurityManagerMethods, unknown_method);
                    break;
                case 0x03:
                    method = val_to_str_const(idx, OcaFirmwareManagerMethods, unknown_method);
                    break;
                case 0x04:
                    method = val_to_str_const(idx, OcaSubscriptionManagerMethods, unknown_method);
                    break;
                case 0x05:
                    method = val_to_str_const(idx, OcaPowerManagerMethods, unknown_method);
                    break;
                case 0x06:
                    method = val_to_str_const(idx, OcaNetworkManagerMethods, unknown_method);
                    break;
                case 0x07:
                    method = val_to_str_const(idx, OcaMediaClockManagerMethods, unknown_method);
                    break;
                case 0x08:
                    method = val_to_str_const(idx, OcaLibraryManagerMethods, unknown_method);
                    break;
                case 0x09:
                    method = val_to_str_const(idx, OcaAudioProcessingManagerMethods, unknown_method);
                    break;
                case 0x0A:
                    method = val_to_str_const(idx, OcaDeviceTimeManagerMethods, unknown_method);
                    break;
                case 0x0B:
                    method = val_to_str_const(idx, OcaTaskManagerMethods, unknown_method);
                    break;
                case 0x0C:
                    method = val_to_str_const(idx, OcaCodingManagerMethods, unknown_method);
                    break;
                case 0x0D:
                    method = val_to_str_const(idx, OcaDiagnosticManagerMethods, unknown_method);
                    break;
                default:
                    snprintf(s, ITEM_LABEL_LENGTH, "%s.%s", val_to_str_const(ono, OaFixedONo, unknown_class), unknown_method);
                    return;
            }
            break;

        default:
            /* Only level 1 (OcaRoot) and 3 (Managers) are valid */
            snprintf(s, ITEM_LABEL_LENGTH, "%s.%s", val_to_str_const(ono, OaFixedONo, unknown_class), unknown_method);
            return;
    }


    snprintf(s, ITEM_LABEL_LENGTH, "%s.%s", val_to_str_const(ono, OaFixedONo, unknown_class), method);

}

/* Parameter Decoder Datatypes */
static int
decode_params_OcaONo(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_ono, tvb, offset, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
decode_params_OcaResetCause(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_reset_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaPowerState(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_power_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaMediaClockType(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_media_clock_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaComponent(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_component, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
}

static int
decode_params_OcaBlob(tvbuff_t *tvb, guint offset, proto_tree *tree, char *fname)
{
    proto_tree *l_tree;
    proto_item *ti;

    guint offset_m = offset;
    guint16 datasize = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item(tree, hf_ocp1_params_blob, tvb, offset_m, 2 + datasize, ENC_NA);
    proto_item_prepend_text(ti, "%s: ", fname);
    l_tree = proto_item_add_subtree(ti, ett_ocp1_params_blob);

    proto_tree_add_item(l_tree, hf_ocp1_params_blob_datasize, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(l_tree, hf_ocp1_params_blob_data, tvb, offset_m, datasize, ENC_NA);
    offset_m += datasize;

    return offset_m - offset;
}
static int
decode_params_OcaBlobFixedLen(tvbuff_t *tvb, guint offset, guint length, proto_tree *tree, char *fname)
{
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_ocp1_params_blob_data, tvb, offset, length, ENC_NA);
    proto_item_prepend_text(ti, "%s: ", fname);

    return length;
}

static int
decode_params_OcaString(tvbuff_t *tvb, guint offset, proto_tree *tree, char *fname)
{
    proto_tree *l_tree;
    proto_item *ti;

    guint offset_m = offset;
    guint16 length = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);

    ti = proto_tree_add_item(tree, hf_ocp1_params_string, tvb, offset_m, 2 + length, ENC_NA);
    l_tree = proto_item_add_subtree(ti, ett_ocp1_params_string);

    proto_tree_add_item(l_tree, hf_ocp1_params_string_length, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(l_tree, hf_ocp1_params_string_value, tvb, offset_m, length, ENC_UTF_8);
    proto_item_set_text(ti,"%s: %s", fname, tvb_get_string_enc(wmem_packet_scope(), tvb, offset_m, length, ENC_UTF_8));
    offset_m += length;

    return offset_m - offset;
}

static int
decode_params_OcaBoolean(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_bool, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaEventID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree *l_tree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_ocp1_params_event_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    l_tree = proto_item_add_subtree(ti, ett_ocp1_params_event);

    proto_tree_add_item(l_tree, hf_ocp1_params_event_tree_level, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(l_tree, hf_ocp1_params_event_index, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 4;
}

static int
decode_params_OcaEvent(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaONo(tvb, offset_m, tree);
    offset_m += decode_params_OcaEventID(tvb, offset_m, tree);

    return offset_m - offset;
}

static int
decode_params_OcaMethodID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree *l_tree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_ocp1_params_method_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    l_tree = proto_item_add_subtree(ti, ett_ocp1_params_method);

    proto_tree_add_item(l_tree, hf_ocp1_params_method_tree_level, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(l_tree, hf_ocp1_params_method_index, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 4;
}

static int
decode_params_OcaPropertyID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree *l_tree;
    proto_item *ti;

    ti = proto_tree_add_item(tree, hf_ocp1_params_property_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    l_tree = proto_item_add_subtree(ti, ett_ocp1_params_property);

    proto_tree_add_item(l_tree, hf_ocp1_params_property_tree_level, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(l_tree, hf_ocp1_params_property_index, tvb, offset, 2, ENC_BIG_ENDIAN);

    return 4;
}

static int
decode_params_OcaClassID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_item *ti;
    guint offset_m = offset;

    proto_tree_add_item(tree, hf_ocp1_params_classid_fields, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    guint16 fields = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
    offset_m += 2;

    ti = proto_tree_add_item(tree, hf_ocp1_params_classid, tvb, offset_m, fields*2, ENC_ASCII);


    for(int i=0; i<fields; i++) {
        if(i == fields-1)
            proto_item_append_text(ti, "%d", tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN));
        else
            proto_item_append_text(ti, "%d.", tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN));

        offset_m += 2;
    }

    return offset_m - offset;

}

static int
decode_params_OcaClassVersion(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_class_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
}

static int
decode_params_OcaClassIdentification(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;

    offset_m += decode_params_OcaClassID(tvb, offset_m, tree);
    offset_m += decode_params_OcaClassVersion(tvb, offset_m, tree);

    return offset_m - offset;
}

static int
decode_params_OcaManagerDescriptor(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;

    offset_m += decode_params_OcaONo(tvb, offset_m, tree);
    offset_m += decode_params_OcaString(tvb, offset_m, tree, "Name");
    offset_m += decode_params_OcaClassID(tvb, offset_m, tree);
    offset_m += decode_params_OcaClassVersion(tvb, offset_m, tree);

    return offset_m - offset;
}

static int
decode_params_OcaNotificationDeliveryMode(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_ntf_delivery_mode, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

static int
decode_params_OcaModelDescription(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaString(tvb, offset_m, tree, "Manufacturer");
    offset_m += decode_params_OcaString(tvb, offset_m, tree, "Name");
    offset_m += decode_params_OcaString(tvb, offset_m, tree, "Version");

    return offset_m - offset;
}

static int
decode_params_OcaModelGUID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaBlobFixedLen(tvb, offset_m, 1, tree, "Reserved");
    offset_m += decode_params_OcaBlobFixedLen(tvb, offset_m, 3, tree, "Manufacturer Code");
    offset_m += decode_params_OcaBlobFixedLen(tvb, offset_m, 4, tree, "Model Code");

    return offset_m - offset;
}

static int
decode_params_OcaMethod(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaONo(tvb, offset_m, tree);
    offset_m += decode_params_OcaMethodID(tvb, offset_m, tree);

    return offset_m - offset;
}

static int
decode_params_OcaLibVolType(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaBlobFixedLen(tvb, offset_m, 3, tree, "Authority");
    proto_tree_add_item(tree, hf_ocp1_params_libvoltype_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    return offset_m - offset;
}

static int
decode_params_OcaLibVolID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_libvol_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
decode_params_OcaLibVolIdentifier(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaONo(tvb, offset_m, tree);
    offset_m += decode_params_OcaLibVolID(tvb, offset_m, tree);

    return offset_m - offset;
}

static int
decode_params_OcaLibraryIdentifier(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    offset_m += decode_params_OcaLibVolType(tvb, offset_m, tree);
    offset_m += decode_params_OcaONo(tvb, offset_m, tree);

    return offset_m - offset;
}

static int
decode_params_OcaVersion(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    proto_item *ti;
    proto_tree *v_tree;

    v_tree = proto_tree_add_subtree_format(tree, tvb, offset_m, 14, ett_ocp1_params_ocaver, &ti,
        "Version %d.%d.%d.%d",
        tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN),
        tvb_get_guint32(tvb, offset + 4, ENC_BIG_ENDIAN),
        tvb_get_guint32(tvb, offset + 8, ENC_BIG_ENDIAN),
        tvb_get_guint16(tvb, offset + 12, ENC_BIG_ENDIAN));

    proto_tree_add_item(v_tree, hf_ocp1_params_ocaver_major, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;
    proto_tree_add_item(v_tree, hf_ocp1_params_ocaver_minor, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;
    proto_tree_add_item(v_tree, hf_ocp1_params_ocaver_build, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;
    proto_tree_add_item(v_tree, hf_ocp1_params_ocaver_comp, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    return offset_m - offset;
}

static int
decode_params_OcaTimeNTP(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_time_ntp, tvb, offset, 8, ENC_TIME_NTP);
    return 8;
}

static int
decode_params_OcaTimePTP(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;
    proto_item *ti;
    proto_tree *pt;

    proto_tree_add_item(tree, hf_ocp1_params_time_ptp_negative, tvb, offset_m, 1, ENC_BIG_ENDIAN);
    offset_m += 1;

    ti = proto_tree_add_item(tree, hf_ocp1_params_time_ptp, tvb, offset_m, 12, ENC_TIME_SECS_NSECS);

    pt = proto_item_add_subtree(ti, ett_ocp1_params_ptp);
    proto_tree_add_item(pt, hf_ocp1_params_time_ptp_seconds, tvb, offset_m, 8, ENC_BIG_ENDIAN);
    offset_m += 8;

    proto_tree_add_item(pt, hf_ocp1_params_time_ptp_nanoseconds, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;


    return offset_m - offset;
}

static int
decode_params_OcaTimeMode(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_time_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaTimeInterval(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_time_interval, tvb, offset, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
decode_params_OcaTimeUnits(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_time_units, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaTaskID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_task_id, tvb, offset, 4, ENC_BIG_ENDIAN);
    return 4;
}

static int
decode_params_OcaTaskGroupID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_task_group_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
}

static int
decode_params_OcaTaskCommand(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_task_command, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaTaskManagerState(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_task_manager_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaTaskState(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_task_state, tvb, offset, 1, ENC_BIG_ENDIAN);
    return 1;
}

static int
decode_params_OcaTaskStatus(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    guint offset_m = offset;

    offset_m += decode_params_OcaTaskID(tvb, offset_m, tree);
    offset_m += decode_params_OcaTaskState(tvb, offset_m, tree);
    proto_tree_add_item(tree, hf_ocp1_params_task_status_error_code, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    return offset_m - offset;
}

static int
decode_params_OcaTask(tvbuff_t *tvb, guint offset, proto_tree *tree)
{

    guint offset_m = offset;

    offset_m += decode_params_OcaTaskID(tvb, offset_m, tree);
    offset_m += decode_params_OcaString(tvb, offset_m, tree, "Label");
    offset_m += decode_params_OcaLibVolIdentifier(tvb, offset_m, tree);
    offset_m += decode_params_OcaTaskGroupID(tvb, offset_m, tree);

    guint8 mode = tvb_get_guint8(tvb, offset_m);
    offset_m += decode_params_OcaTimeMode(tvb, offset_m, tree);
    offset_m += decode_params_OcaTimeUnits(tvb, offset_m, tree);
    offset_m += decode_params_OcaONo(tvb, offset_m, tree);

    if(mode==1) {/* seconds, PTP */
        offset_m += decode_params_OcaTimePTP(tvb, offset_m, tree);
    } else if (mode==2) { /* samples, guint64 */
        proto_tree_add_item(tree, hf_ocp1_params_start_time, tvb, offset_m, 8, ENC_BIG_ENDIAN);
        offset_m += 8;
    } else { /* fail, malformed */
        return offset_m - offset;
    }

    offset_m += decode_params_OcaTimeInterval(tvb, offset_m, tree);
    offset_m += decode_params_OcaBlob(tvb, offset_m, tree, "ApplicationSpecificParameters");

    return offset_m - offset;
}

static int
decode_params_OcaMediaCodingSchemeID(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_ocp1_params_media_coding_scheme_id, tvb, offset, 2, ENC_BIG_ENDIAN);
    return 2;
}

static int
decode_params_OcaDeviceState(tvbuff_t *tvb, guint offset, proto_tree *tree)
{
    static int* const state_bits[] = {
            &hf_ocp1_params_devicestate_oper,
            &hf_ocp1_params_devicestate_disabled,
            &hf_ocp1_params_devicestate_error,
            &hf_ocp1_params_devicestate_init,
            &hf_ocp1_params_devicestate_updating,
            NULL
        };
    proto_tree_add_bitmask(tree, tvb, offset, hf_ocp1_params_devicestate, ett_ocp1_params_devicestate, state_bits, ENC_BIG_ENDIAN);

    return 2;
}

/* Parameter Decoder (Class Methods) */
static int
decode_params_OcaRoot(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetClassIdentification ([out] OcaClassIdentification) */
        proto_tree *p1_tree;
        proto_item *t1;

        guint len = 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN)*2 + 2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, len, ett_ocp1_params, &t1, "Parameter 1 (Class Identification)");
        offset_m += decode_params_OcaClassIdentification(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x02 && !request && pcount == 1) {
        /* GetLockable ([out] lockable: OcaBoolean) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (Lockable)");
        offset_m += decode_params_OcaBoolean(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x05 && !request && pcount == 1) {
        /* GetRole ([out] role: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Role)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Role");
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaDeviceManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetOcaVersion ([out] OcaVersion: OcaUint16) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2, ett_ocp1_params, &t1, "Parameter 1 (OCA Version)");
        proto_tree_add_item(p1_tree, hf_ocp1_params_oca_version, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
    }
    else if(m_idx == 0x02 && !request && pcount == 1) {
        /* GetModelGUID ([out] GUID: OcaModelGUID) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t1, "Parameter 1 (GUID)");
        offset_m += decode_params_OcaModelGUID(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x03 && !request && pcount == 1) {
        /* GetSerialNumber ([out] serialNumber: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Serial Number)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Serial Number");
    }
    else if(m_idx == 0x04 && !request && pcount == 1) {
        /* GetDeviceName ([out] Name: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Name)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Name");
    }
    else if(m_idx == 0x05 && request && pcount == 1) {
        /* SetDeviceName (Name: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Name)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Name");
    }
    else if(m_idx == 0x06 && !request && pcount == 1) {
        /* GetModelDescription ([out] Description: OcaModelDescription) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Description)");
        offset_m += decode_params_OcaModelDescription(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x07 && !request && pcount == 1) {
        /* GetRole ([out] role: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Role)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Role");
    }
    else if(m_idx == 0x08 && request && pcount == 1) {
        /* SetRole (role: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Role)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Role");
    }
    else if(m_idx == 0x09 && !request && pcount == 1) {
        /* GetUserInventoryCode ([out] Code: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Code)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Code");
    }
    else if(m_idx == 0x0A && request && pcount == 1) {
        /* SetUserInventoryCode (Code: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Code)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Code");
    }
    else if(m_idx == 0x0B && !request && pcount == 1) {
        /* GetEnabled ([out] enabled: OcaBoolean) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (enabled)");
        offset_m += decode_params_OcaBoolean(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x0C && request && pcount == 1) {
        /* SetEnabled (enabled: OcaBoolean) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (enabled)");
        offset_m += decode_params_OcaBoolean(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x0D && !request && pcount == 1) {
        /* GetState ([out] state: OcaDeviceState) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2, ett_ocp1_params, &t1, "Parameter 1 (State)");
        offset_m += decode_params_OcaDeviceState(tvb, offset_m, p1_tree);

    }
    else if(m_idx == 0x0E && request && pcount == 2) {
        /* SetResetKey (Key: OcaBlobFixedLen<16>, Address: OcaNetworkAddress) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 16, ett_ocp1_params, &t1, "Parameter 1 (Key)");
        offset_m += decode_params_OcaBlobFixedLen(tvb, offset_m, 16, p1_tree, "Key");
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t2, "Parameter 2 (Address)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p2_tree, "Address");

    }
    else if(m_idx == 0x0F && !request && pcount == 1) {
        /* GetResetCause ([out] resetCause: OcaResetCause) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (Reset Cause)");
        offset_m += decode_params_OcaResetCause(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x11 && !request && pcount == 1) {
        /* GetMessage ([out] Message: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Message)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Message");
    }
    else if(m_idx == 0x12 && request && pcount == 1) {
        /* SetMessage (Message: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Message)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Message");
    }
    else if(m_idx == 0x13 && !request && pcount == 1) {
        /* GetManagers ([out] Managers: OcaList<OcaManagerDescriptor>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        for(int i = 0; i < item_count; i++) { /* Loop list items */
            plen_total += 4; /* ono */
            plen_total += tvb_get_guint16(tvb, offset_m + plen_total, ENC_BIG_ENDIAN) + 2;   /* string length + length field (uint16) */
            plen_total += tvb_get_guint16(tvb, offset_m + plen_total, ENC_BIG_ENDIAN)*2 + 2; /* ClassID field count (uint16) + count x ID (uint16) */
            plen_total += 2; /* OcaClassVersionNumber */
        }

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Managers)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            int plen = 0;
            proto_tree *list_tree;
            plen += 4; /* ono */
            plen += tvb_get_guint16(tvb, offset_m + plen, ENC_BIG_ENDIAN) + 2;   /* string length + length field (uint16) */
            plen += tvb_get_guint16(tvb, offset_m + plen, ENC_BIG_ENDIAN)*2 + 2; /* ClassID field count (uint16) + count x ID (uint16) */
            plen += 2; /* OcaClassVersioNumber */
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, plen, ett_ocp1_params_manager_desc, NULL, "Manager Descriptor Item %d", i+1 );
            offset_m += decode_params_OcaManagerDescriptor(tvb, offset_m, list_tree);
        }

    }
    else if(m_idx == 0x14 && !request && pcount == 1) {
        /* GetDeviceRevisionID ([out] ID: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (ID)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Revision");
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaSecurityManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x03 && request && pcount == 2) {
        /* ChangePreSharedKey (identity: OcaString, newKey: OcaBlob) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Identity)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Identity");
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t2, "Parameter 2 (New Key)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p2_tree, "Key");
    }
    else if(m_idx == 0x04 && request && pcount == 2) {
        /* AddPreSharedKey (identity: OcaString, newKey: OcaBlob) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Identity)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Identity");
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t2, "Parameter 2 (Key)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p2_tree, "Key");
    }
    else if(m_idx == 0x05 && request && pcount == 1) {
        /* DeletePreSharedKey (identity: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Identity)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Identity");
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaFirmwareManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetComponentVersions ([out] componentVersions: OcaList<OcaVersion>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each OcaVersion item length = major uint32 + minor uint32 + build uint32 + component uint16 = 14 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 14;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Component Versions)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 14, ett_ocp1_params_compversion, NULL, "Component Version Item %d", i+1 );
            offset_m += decode_params_OcaVersion(tvb, offset_m, list_tree);
        }

    }
    else if(m_idx == 0x03 && request && pcount == 1) {
        /* BeginActiveImageUpdate (component: OcaComponent) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2, ett_ocp1_params, &t1, "Parameter 1 (Component)");
        offset_m += decode_params_OcaComponent(tvb, offset_m, p1_tree);

    }
    else if(m_idx == 0x04 && request && pcount == 2) {
        /* AddImageData (id: OcaUint32, imageData: OcaBlob) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (ID)");
        proto_tree_add_item(p1_tree, hf_ocp1_params_imageid, tvb, offset_m, 4, ENC_BIG_ENDIAN);
        offset += 4;
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t2, "Parameter 2 (Image Data)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p2_tree, "Image Data");
    }
    else if(m_idx == 0x05 && request && pcount == 1) {
        /* VerifyImage (verifyData: OcaBlob) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Verify Data)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p1_tree, "Data");
    }
    else if(m_idx == 0x07 && request && pcount == 3) {
        /* BeginPassiveComponentUpdate (component: OcaComponent, serverAddress: OcaNetworkAddress, updateFileName: OcaString) */
        proto_tree *p1_tree, *p2_tree, *p3_tree;
        proto_item *t1, *t2, *t3;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2, ett_ocp1_params, &t1, "Parameter 1 (Component)");
        offset_m += decode_params_OcaComponent(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t2, "Parameter 2 (Server Address)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p2_tree, "Server Address");
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t3, "Parameter 3 (Update File Name)");
        offset_m += decode_params_OcaString(tvb, offset_m, p3_tree, "File Name");
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaSubscriptionManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && request && pcount == 5) {
        /* AddSubscription (Event: OcaEvent, Subscriber: OcaMethod, SubscriberContext: OcaBlob, NotificationDeliveryMode: OcaNotificationDeliveryMode, DestinationInformation: OcaNetworkAddress) */
        proto_tree *p1_tree, *p2_tree, *p3_tree, *p4_tree, *p5_tree;
        proto_item *t1, *t2, *t3, *t4, *t5;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t1, "Parameter 1 (Event)");
        offset_m += decode_params_OcaEvent(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t2, "Parameter 2 (Subscriber)");
        offset_m += decode_params_OcaMethod(tvb, offset_m, p2_tree);
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t3, "Parameter 3 (Subscriber Context)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p3_tree, "Subscriber Context");
        p4_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t4, "Parameter 4 (Notification Delivery Mode)");
        offset_m += decode_params_OcaNotificationDeliveryMode(tvb, offset_m, p4_tree);
        p5_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t5, "Parameter 5 (Destination Information)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p5_tree, "Destination Information");

    }
    else if(m_idx == 0x02 && request && pcount == 2) {
        /* RemoveSubscription (Event: OcaEvent, Subscriber: OcaMethod) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t1, "Parameter 1 (Event)");
        offset_m += decode_params_OcaEvent(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t2, "Parameter 2 (Subscriber)");
        offset_m += decode_params_OcaMethod(tvb, offset_m, p2_tree);

    }
    else if(m_idx == 0x05 && request && pcount == 6) {
        /* AddPropertyChangeSubscription (Emitter: OcaONo, Property: OcaPropertyID, Subscriber: OcaMethod, SubscriberContext: OcaBlob, NotificationDeliveryMode: OcaNotificationDeliveryMode, DestinationInformation: OcaNetworkAddress) */
        proto_tree *p1_tree, *p2_tree, *p3_tree, *p4_tree, *p5_tree, *p6_tree;
        proto_item *t1, *t2, *t3, *t4, *t5, *t6;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Emitter)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t2, "Parameter 2 (Property)");
        offset_m += decode_params_OcaPropertyID(tvb, offset_m, p2_tree);
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t3, "Parameter 3 (Subscriber)");
        offset_m += decode_params_OcaMethod(tvb, offset_m, p3_tree);
        p4_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t4, "Parameter 4 (SubscriberContext)");
        offset += decode_params_OcaBlob(tvb, offset_m, p4_tree, "Context");
        p5_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t5, "Parameter 5 (Notification Delivery Mode)");
        offset_m += decode_params_OcaNotificationDeliveryMode(tvb, offset_m, p5_tree);
        p6_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t6, "Parameter 6 (Destination Information)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p6_tree, "Address");
    }
    else if(m_idx == 0x06 && request && pcount == 3) {
        /* RemovePropertyChangeSubscription (Emitter: OcaONo, Property: OcaPropertyID, Subscriber: OcaMethod) */
        proto_tree *p1_tree, *p2_tree, *p3_tree;
        proto_item *t1, *t2, *t3;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Emitter)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t2, "Parameter 2 (Property)");
        offset_m += decode_params_OcaPropertyID(tvb, offset_m, p2_tree);
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t3, "Parameter 3 (Subscriber)");
        offset_m += decode_params_OcaMethod(tvb, offset_m, p3_tree);
    }
    else if(m_idx == 0x07 && !request && pcount == 1) {
        /* GetMaximumSubscriberContextLength ([out] Max: OcaUint16) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2, ett_ocp1_params, &t1, "Parameter 1 (Max)");
        proto_tree_add_item(p1_tree, hf_ocp1_params_subscriber_ctx_len, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;

    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaPowerManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetState ([out] State: OcaPowerState) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (State)");
        offset_m += decode_params_OcaPowerState(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x02 && request && pcount == 1) {
        /* SetState (State: OcaPowerState) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (State)");
        offset_m += decode_params_OcaPowerState(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x03 && !request && pcount == 1) {
        /* GetPowerSupplies ([out] psuList: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (PSU List)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "PSU Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x04 && !request && pcount == 1) {
        /* GetActivePowerSupplies ([out] psuList: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (PSU List)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "PSU Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x05 && request && pcount == 3) {
        /* ExchangePowerSupply (oldPsu: OcaONo, newPsu: OcaONo, powerOffOld: OcaBoolean) */
        proto_tree *p1_tree, *p2_tree, *p3_tree;
        proto_item *t1, *t2, *t3;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Old PSU)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t2, "Parameter 2 (New PSU)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p2_tree);
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t3, "Parameter 3 (Power off old)");
        offset_m += decode_params_OcaBoolean(tvb, offset_m, p3_tree);
    }
    else if(m_idx == 0x06 && !request && pcount == 1) {
        /* GetAutoState ([out] state: OcaBoolean) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (State)");
        offset_m += decode_params_OcaBoolean(tvb, offset_m, p1_tree);
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaNetworkManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetNetworks ([out] Networks: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Networks)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Network Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x02 && !request && pcount == 1) {
        /* GetStreamNetworks ([out] StreamNetworks: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Stream Networks)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Network Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x03 && !request && pcount == 1) {
        /* GetControlNetworks ([out] ControlNetworks: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Control Networks)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Network Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x04 && !request && pcount == 1) {
        /* GetMediaTransportNetworks ([out] MediaTransportNetworks: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Media Transport Networks)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Network Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaMediaClockManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetClocks ([out] Clocks: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Clocks)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Clock Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x02 && !request && pcount == 1) {
        /* GetMediaClockTypesSupported ([out] MediaClockTypes: OcaList<OcaMediaClockType>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each OcaMediaClockType item has length 1 byte */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Media Clock Types)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 1, ett_ocp1_params_compversion, NULL, "Type Item %d", i+1 );
            offset_m += decode_params_OcaMediaClockType(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x03 && !request && pcount == 1) {
        /* GetClock3s ([out] Clocks: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each ONo item has length 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Clocks)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Clock Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaLibraryManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && request && pcount == 1) {
        /* AddLibrary (Type: OcaLibVolType) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Type)");
        offset_m += decode_params_OcaLibVolType(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x01 && !request && pcount == 1) {
        /* AddLibrary ([out] Identifier: OcaLibraryIdentifier) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Identifier)");
        offset_m += decode_params_OcaLibraryIdentifier(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x02 && request && pcount == 1) {
        /* DeleteLibrary (ID: OcaONo) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (ID)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x03 && request && pcount == 1) {
        /* GetLibraryCount (Type: OcaLibVolType) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (OcaLibVolType)");
        offset_m += decode_params_OcaLibVolType(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x03 && !request && pcount == 1) {
        /* GetLibraryCount ([out] Count: OcaUint16) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Count)");
        proto_tree_add_item(p1_tree, hf_ocp1_params_library_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
    }
    else if(m_idx == 0x04 && request && pcount == 1) {
        /* GetLibraryList (Type: OcaLibVolType) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Type)");
        offset_m += decode_params_OcaLibVolType(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x04 && !request && pcount == 1) {
        /* GetLibraryList ([out] OcaList<OcaLibraryIdentifier) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length
         * Each Item consists out of
         * - OcaLibraryIdentifier --> 11 bytes
         *   - Type (authority = fixed len blob 3, id = 4 bytes)
         *   - ONo = 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 11;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Library Identifier)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 11, ett_ocp1_params_compversion, NULL, "Library Item %d", i+1 );
            offset_m += decode_params_OcaLibraryIdentifier(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x05 && !request && pcount == 1) {
        /* GetCurrentPatch ([out] ID: OcaLibVolIdentifier) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (ID)");
        offset_m += decode_params_OcaLibVolIdentifier(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x06 && request && pcount == 1) {
        /* ApplyPatch (ID: OcaLibVolIdentifier) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (ID)");
        offset_m += decode_params_OcaLibVolIdentifier(tvb, offset_m, p1_tree);
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_ocaAudioProcessing(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    guint offset_m = offset;

    /* No registered methods */
    proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
    offset_m += length;

    return offset_m - offset;
}

static int
decode_params_OcaDeviceTimeManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetDeviceTimeNTP ([out] DeviceTime: OcaTimeNTP) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t1, "Parameter 1 (Time)");
        offset_m += decode_params_OcaTimeNTP(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x02 && request && pcount == 1) {
        /* SetDeviceTimeNTP (DeviceTime: OcaTimeNTP) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t1, "Parameter 1 (Time)");
        offset_m += decode_params_OcaTimeNTP(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x03 && !request && pcount == 1) {
        /* GetTimeSources ([out] TimeSourceONos: OcaList<OcaONo>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        /* Each Item is an ONo = 4 bytes */
        int plen_total = 2; /* start with len=2, this is the list count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        plen_total += item_count * 4;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Time Sources)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_list_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 4, ett_ocp1_params_compversion, NULL, "Time Source Item %d", i+1 );
            offset_m += decode_params_OcaONo(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x04 && !request && pcount == 1) {
        /* GetCurrentDeviceTimeSource ([out] TimeSourceONo: OcaONo) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Time Source)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x05 && request && pcount == 1) {
        /* SetCurrentDeviceTimeSource (TimeSourceONo: OcaONo) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 8, ett_ocp1_params, &t1, "Parameter 1 (Time Source)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x06 && !request && pcount == 1) {
        /* GetDeviceTimePTP ([out] DeviceTime: OcaTimePTP) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 13, ett_ocp1_params, &t1, "Parameter 1 (Time)");
        offset_m += decode_params_OcaTimePTP(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x07 && request && pcount == 1) {
        /* SetDeviceTimePTP (DeviceTime: OcaTimePTP) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 13, ett_ocp1_params, &t1, "Parameter 1 (Time)");
        offset_m += decode_params_OcaTimePTP(tvb, offset_m, p1_tree);
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaTaskManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && request && pcount == 1) {
        /* Enable (Enable: OcaBoolean) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (Enable)");
        offset_m += decode_params_OcaBoolean(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x02 && request && pcount == 2) {
        /* ControlAllTasks (Command: OcaTaskCommand, ApplicationTaskParameter: OcaBlob) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (Command)");
        offset_m += decode_params_OcaTaskCommand(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t2, "Parameter 2 (Application Task Parameter)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p2_tree, "Task Parameter");
    }
    else if(m_idx == 0x03 && request && pcount == 3) {
        /* ControlTaskGroup (GroupID: OcaTaskGroupID, Command: OcaTaskCommand, ApplicationTaskParameter: OcaBlob) */
        proto_tree *p1_tree, *p2_tree, *p3_tree;
        proto_item *t1, *t2, *t3;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2, ett_ocp1_params, &t1, "Parameter 1 (Group ID)");
        offset_m += decode_params_OcaTaskGroupID(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t2, "Parameter 2 (Command)");
        offset_m += decode_params_OcaTaskCommand(tvb, offset_m, p2_tree);
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t3, "Parameter 3 (Application Task Parameter)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p3_tree, "Task Parameter");
    }
    else if(m_idx == 0x04 && request && pcount == 3) {
        /* ControlTask (TaskID: OcaTaskID, Command: OcaTaskCommand, ApplicationTaskParameter: OcaBlob) */
        proto_tree *p1_tree, *p2_tree, *p3_tree;
        proto_item *t1, *t2, *t3;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Task ID)");
        offset_m += decode_params_OcaTaskID(tvb, offset_m, p1_tree);
        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t2, "Parameter 2 (Task Command)");
        offset_m += decode_params_OcaTaskCommand(tvb, offset_m, p2_tree);
        p3_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t3, "Parameter 3 (Application Task Parameter)");
        offset_m += decode_params_OcaBlob(tvb, offset_m, p3_tree, "Task Parameter");
    }
    else if(m_idx == 0x05 && !request && pcount == 1) {
        /* GetState ([out] State: OcaTaskManagerState) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 1, ett_ocp1_params, &t1, "Parameter 1 (State)");
        offset_m += decode_params_OcaTaskManagerState(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x06 && request && pcount == 1) {
        /* GetTaskStatuses ([out] Statuses: OcaTaskStatus) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 7, ett_ocp1_params, &t1, "Parameter 1 (Statuses)");
        offset_m += decode_params_OcaTaskStatus(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x07 && request && pcount == 1) {
        /* GetTaskStatus (TaskID: OcaTaskID) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Task ID)");
        offset_m += decode_params_OcaTaskID(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x07 && !request && pcount == 1) {
        /* GetTaskStatus ([out] Status: OcaTaskStatus) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 7, ett_ocp1_params, &t1, "Parameter 1 (Status)");
        offset_m += decode_params_OcaTaskStatus(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x08 /*&& request*/ && pcount == 1) {
        /* AddTask ([inout] Task: OcaTask) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine length */
        /* ID (4) + Label (OcaString) + ProgramID (8) + GroupID (2) + TimeMode (1) + */
        guint len = 4 + 2 + tvb_get_guint16(tvb, offset_m + 4, ENC_BIG_ENDIAN) + 8 + 2 + 1;
        /* TimeUnits (1) + ClockONo (4) + StartTime (13 if TimeUnits=1 (seconds, PTP Time), 8 if TimeUnits=2 (samples)) + Duration (4) + */
        if(tvb_get_guint8(tvb, offset_m + len)==1) { /* 1 = PTP Time, 13 byte */
            len += 1 + 4 + 13 + 4;
        } if(tvb_get_guint8(tvb, offset_m + len)==2) { /* 2 = samples, 8 byte */
            len += 1 + 4 + 8 + 4;
        } else { /* invalid, malformed */
            return offset_m - offset;
        }
        /* ApplicationSpecificParameters (blob) */
        len += 2 + tvb_get_guint16(tvb, offset_m + len, ENC_BIG_ENDIAN);


        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, len, ett_ocp1_params, &t1, "Parameter 1 (Task)");
        offset_m += decode_params_OcaTask(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x09 && !request && pcount == 1) {
        /* GetTasks ([out] Tasks: OcaMap<OcaTaskID,OcaTask>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        int plen_total = 2; /* start with len=2, this is the map item count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        for(int i = 0; i < item_count; i++) { /* Loop map items */
            plen_total += 4;    /* Map Key -> OcaTaskID, Uint32 */

            plen_total += 4; /* ID */
            plen_total += 2 + tvb_get_guint16(tvb, offset_m + plen_total, ENC_BIG_ENDIAN); /* Label OCA String */
            plen_total += 11; /* ProgramID, GroupId, TimeMode */
            /* TimeUnits (1) + ClockONo (4) + StartTime (13 if TimeUnits=1 (seconds, PTP Time), 8 if TimeUnits=2 (samples)) + Duration (4) + */
            if(tvb_get_guint8(tvb, offset_m + plen_total)==1) { /* 1 = PTP Time, 13 byte */
                plen_total += 1 + 4 + 13 + 4;
            } if(tvb_get_guint8(tvb, offset_m + plen_total)==2) { /* 2 = samples, 8 byte */
                plen_total += 1 + 4 + 8 + 4;
            } else { /* invalid, malformed */
                return offset_m - offset;
            }
            /* ApplicationSpecificParameters (blob) */
            plen_total += 2 + tvb_get_guint16(tvb, offset_m + plen_total, ENC_BIG_ENDIAN);
        }

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Task Map)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_map_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;

            /* Determine length */
            /* Task ID (4) (Key) + ID (4) + Label (OcaString) + ProgramID (8) + GroupID (2) + TimeMode (1) + */
            guint len = 4 + 4 + 2 + tvb_get_guint16(tvb, offset_m + 4, ENC_BIG_ENDIAN) + 8 + 2 + 1;
            /* TimeUnits (1) + ClockONo (4) + StartTime (13 if TimeUnits=1 (seconds, PTP Time), 8 if TimeUnits=2 (samples)) + Duration (4) + */
            if(tvb_get_guint8(tvb, offset_m + len)==1) { /* 1 = PTP Time, 13 byte */
                len += 1 + 4 + 13 + 4;
            } if(tvb_get_guint8(tvb, offset_m + len)==2) { /* 2 = samples, 8 byte */
                len += 1 + 4 + 8 + 4;
            } else { /* invalid, malformed */
                return offset_m - offset;
            }
            /* ApplicationSpecificParameters (blob) */
            len += 2 + tvb_get_guint16(tvb, offset_m + len, ENC_BIG_ENDIAN);

            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, len, ett_ocp1_params_compversion, NULL, "Task Item %d", i+1 );
            offset_m += decode_params_OcaTaskID(tvb, offset_m, list_tree);
            offset_m += decode_params_OcaTask(tvb, offset_m, list_tree);
        }
    }
    else if(m_idx == 0x0A && request && pcount == 1) {
        /* GetTask (ID: OcaTaskID) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (ID)");
        offset_m += decode_params_OcaTaskID(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x0A && !request && pcount == 1) {
        /* GetTask ([out] Task: OcaTask) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine length */
        /* ID (4) + Label (OcaString) + ProgramID (8) + GroupID (2) + TimeMode (1) + */
        guint len = 4 + 2 + tvb_get_guint16(tvb, offset_m + 4, ENC_BIG_ENDIAN) + 8 + 2 + 1;
        /* TimeUnits (1) + ClockONo (4) + StartTime (13 if TimeUnits=1 (seconds, PTP Time), 8 if TimeUnits=2 (samples)) + Duration (4) + */
        if(tvb_get_guint8(tvb, offset_m + len)==1) { /* 1 = PTP Time, 13 byte */
            len += 1 + 4 + 13 + 4;
        } if(tvb_get_guint8(tvb, offset_m + len)==2) { /* 2 = samples, 8 byte */
            len += 1 + 4 + 8 + 4;
        } else { /* invalid, malformed */
            return offset_m - offset;
        }
        /* ApplicationSpecificParameters (blob) */
        len += 2 + tvb_get_guint16(tvb, offset_m + len, ENC_BIG_ENDIAN);

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, len, ett_ocp1_params, &t1, "Parameter 1 (Task)");
        offset_m += decode_params_OcaTask(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x0B && request && pcount == 2) {
        /* SetTask (ID: OcaTaskID, Task: OcaTask) */
        proto_tree *p1_tree, *p2_tree;
        proto_item *t1, *t2;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Task ID)");
        offset_m += decode_params_OcaTaskID(tvb, offset_m, p1_tree);

        /* Determine length */
        /* ID (4) + Label (OcaString) + ProgramID (8) + GroupID (2) + TimeMode (1) + */
        guint len = 4 + 2 + tvb_get_guint16(tvb, offset_m + 4, ENC_BIG_ENDIAN) + 8 + 2 + 1;
        /* TimeUnits (1) + ClockONo (4) + StartTime (13 if TimeUnits=1 (seconds, PTP Time), 8 if TimeUnits=2 (samples)) + Duration (4) + */
        if(tvb_get_guint8(tvb, offset_m + len)==1) { /* 1 = PTP Time, 13 byte */
            len += 1 + 4 + 13 + 4;
        } if(tvb_get_guint8(tvb, offset_m + len)==2) { /* 2 = samples, 8 byte */
            len += 1 + 4 + 8 + 4;
        } else { /* invalid, malformed */
            return offset_m - offset;
        }
        /* ApplicationSpecificParameters (blob) */
        len += 2 + tvb_get_guint16(tvb, offset_m + len, ENC_BIG_ENDIAN);

        p2_tree = proto_tree_add_subtree(tree, tvb, offset_m, len, ett_ocp1_params, &t2, "Parameter 2 (Task)");
        offset_m += decode_params_OcaTask(tvb, offset_m, p2_tree);
    }
    else if(m_idx == 0x0C && request && pcount == 1) {
        /* DeleteTask (ID: OcaTaskID) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Task ID)");
        offset_m += decode_params_OcaTaskID(tvb, offset_m, p1_tree);
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaCodingManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if((m_idx == 0x01 || m_idx == 0x02) && !request && pcount == 1) {
        /* GetAvailableEncodingSchemes ([out] Schemes: OcaMap<OcaMediaCodingSchemeID,OcaString>) */
        /* GetAvailableDecodingSchemes ([out] Schemes: OcaMap<OcaMediaCodingSchemeID,OcaString>) */
        proto_tree *p1_tree;
        proto_item *t1;

        /* Determine the full length */
        int plen_total = 2; /* start with len=2, this is the map item count field */
        guint16 item_count = tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN);
        for(int i = 0; i < item_count; i++) { /* Loop map items */
            plen_total += 4;    /* Map Key -> OcaMediaCodingSchemeID, Uint16 */

            plen_total += 2 + tvb_get_guint16(tvb, offset_m + plen_total, ENC_BIG_ENDIAN); /* Value, String */
        }

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, plen_total, ett_ocp1_params, &t1, "Parameter 1 (Schemes)");

        proto_tree_add_item(p1_tree, hf_ocp1_params_map_count, tvb, offset_m, 2, ENC_BIG_ENDIAN);
        offset_m += 2;
        for(int i = 0; i < item_count; i++) {
            proto_tree *list_tree;
            list_tree = proto_tree_add_subtree_format(p1_tree, tvb, offset_m, 11, ett_ocp1_params_compversion, NULL, "Scheme Item %d", i+1 );
            offset_m += decode_params_OcaMediaCodingSchemeID(tvb, offset_m, list_tree);
            offset_m += decode_params_OcaString(tvb, offset_m, list_tree, "Scheme");
        }
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params_OcaDiagnosticManager(tvbuff_t *tvb, gint offset, gint length, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{
    guint offset_m = offset;

    if(m_idx == 0x01 && request && pcount == 1) {
        /* GetLockStatus (ONo: OcaONo) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 4, ett_ocp1_params, &t1, "Parameter 1 (Object No.)");
        offset_m += decode_params_OcaONo(tvb, offset_m, p1_tree);
    }
    else if(m_idx == 0x01 && !request && pcount == 1) {
        /* GetLockStatus ([out] StatusDescription: OcaString) */
        proto_tree *p1_tree;
        proto_item *t1;

        p1_tree = proto_tree_add_subtree(tree, tvb, offset_m, 2 + tvb_get_guint16(tvb, offset_m, ENC_BIG_ENDIAN), ett_ocp1_params, &t1, "Parameter 1 (Status Description)");
        offset_m += decode_params_OcaString(tvb, offset_m, p1_tree, "Description");
    }
    else {
        proto_tree_add_item(tree, hf_ocp1_params, tvb, offset_m, length, ENC_NA);
        offset_m += length;
    }

    return offset_m - offset;
}

static int
decode_params(tvbuff_t *tvb, gint offset, gint length, guint32 ono, guint16 tree_level, guint16 m_idx, guint8 pcount, bool request, proto_tree *tree)
{

    proto_tree *params_tree;
    proto_item *ti;

    params_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ocp1_params, &ti, "Parameters");

    if(tree_level == 0x01)
        decode_params_OcaRoot(tvb, offset, length, m_idx, pcount, request, params_tree);

    else if(tree_level == 0x03)
        switch (ono) {
                case 0x01:
                    decode_params_OcaDeviceManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x02:
                    decode_params_OcaSecurityManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x03:
                    decode_params_OcaFirmwareManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x04:
                    decode_params_OcaSubscriptionManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x05:
                    decode_params_OcaPowerManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x06:
                    decode_params_OcaNetworkManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x07:
                    decode_params_OcaMediaClockManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x08:
                    decode_params_OcaLibraryManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x09:
                    decode_params_ocaAudioProcessing(tvb, offset, length, params_tree);
                    break;
                case 0x0A:
                    decode_params_OcaDeviceTimeManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x0B:
                    decode_params_OcaTaskManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x0C:
                    decode_params_OcaCodingManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                case 0x0D:
                    decode_params_OcaDiagnosticManager(tvb, offset, length, m_idx, pcount, request, params_tree);
                    break;
                default:
                    proto_tree_add_item(params_tree, hf_ocp1_params, tvb, offset, length, ENC_NA);
                    break;
            }

    else
        proto_tree_add_item(params_tree, hf_ocp1_params, tvb, offset, length, ENC_NA);

    return length;
}

static int
dissect_ocp1_msg_keepalive(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree)
{
    proto_tree *message_tree;
    proto_item *ti;

    message_tree = proto_tree_add_subtree(tree, tvb, offset, length, ett_ocp1_keepalive, &ti, "Keep-Alive Message");

    if (length == 2) {
        proto_tree_add_item(message_tree, hf_ocp1_heartbeat_time_s, tvb, offset, length, ENC_BIG_ENDIAN);
    } else if (length == 4) {
        proto_tree_add_item(message_tree, hf_ocp1_heartbeat_time_ms, tvb, offset, length, ENC_BIG_ENDIAN);
    } else {
        return offset;
    }

    return offset + length;
}

static int
dissect_ocp1_msg_command(tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo, proto_tree *tree, guint msg_counter)
{
    proto_tree *message_tree, *method_tree;
    proto_item *ti, *tf, *t_occ;
    conversation_t *conversation;

    struct oca_request_hash_key request_key, *new_request_key;
    struct oca_request_hash_val *request_val=NULL;


    message_tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_ocp1_keepalive, &ti, "Command Message %d", msg_counter);

    gint offset_m = offset;

    proto_tree_add_item(message_tree, hf_ocp1_message_size, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    proto_tree_add_item(message_tree, hf_ocp1_message_handle, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    t_occ = proto_tree_add_item(message_tree, hf_ocp1_message_occ, tvb, offset_m, 8, ENC_BIG_ENDIAN);
    proto_item_set_generated(t_occ);
    proto_tree_add_item(message_tree, hf_ocp1_message_target_ono, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    tf = proto_tree_add_item(message_tree, hf_ocp1_message_method_id, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    method_tree = proto_item_add_subtree(tf, ett_ocp1_message_method);

    proto_tree_add_item(method_tree, hf_ocp1_message_method_tree_level, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(method_tree, hf_ocp1_message_method_index, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(message_tree, hf_ocp1_message_parameter_count, tvb, offset_m, 1, ENC_BIG_ENDIAN);
    offset_m += 1;

    if (length-(offset_m - offset) > 0) {
        decode_params(tvb, offset_m, length-(offset_m - offset),
            tvb_get_guint32(tvb, offset + 8, ENC_BIG_ENDIAN),
            tvb_get_guint16(tvb, offset + 12, ENC_BIG_ENDIAN),
            tvb_get_guint16(tvb, offset + 14, ENC_BIG_ENDIAN),
            tvb_get_guint8(tvb, offset + 16),
            true, message_tree);
    }

    /* Handle wmem for lookup */
    conversation = find_or_create_conversation(pinfo);
    request_key.conv_index = conversation->conv_index;
    request_key.handle     = tvb_get_guint32(tvb, offset + 4, ENC_BIG_ENDIAN);

    request_val = (struct oca_request_hash_val *) wmem_map_lookup(oca_request_hash_map, &request_key);


    if(!request_val) {
        new_request_key = wmem_new(wmem_file_scope(), struct oca_request_hash_key);
        *new_request_key = request_key;

        request_val = wmem_new(wmem_file_scope(), struct oca_request_hash_val);
        request_val->pnum         = pinfo->num;
        request_val->ono          = tvb_get_guint32(tvb, offset + 8, ENC_BIG_ENDIAN);
        request_val->tree_level   = tvb_get_guint16(tvb, offset + 12, ENC_BIG_ENDIAN);
        request_val->method_index = tvb_get_guint16(tvb, offset + 14, ENC_BIG_ENDIAN);

        wmem_map_insert(oca_request_hash_map, new_request_key, request_val);
    }

    return length;
}

static int
dissect_ocp1_msg_notification(tvbuff_t *tvb, gint offset, gint length, proto_tree *tree, guint msg_counter)
{
    proto_tree *message_tree, *method_tree, *eventdata_tree, *eventid_tree;
    proto_item *ti, *tf, *te, *teid, *t_occ;

    message_tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_ocp1_keepalive, &ti, "Notification Message %d", msg_counter);

    gint offset_m = offset;

    proto_tree_add_item(message_tree, hf_ocp1_message_size, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    t_occ = proto_tree_add_item(message_tree, hf_ocp1_message_occ, tvb, offset_m, 8, ENC_BIG_ENDIAN);
    proto_item_set_generated(t_occ);
    proto_tree_add_item(message_tree, hf_ocp1_message_target_ono, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    tf = proto_tree_add_item(message_tree, hf_ocp1_message_method_id, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    method_tree = proto_item_add_subtree(tf, ett_ocp1_message_method);

    proto_tree_add_item(method_tree, hf_ocp1_message_method_tree_level, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(method_tree, hf_ocp1_message_method_index, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(message_tree, hf_ocp1_message_parameter_count, tvb, offset_m, 1, ENC_BIG_ENDIAN);
    offset_m += 1;

    proto_tree_add_item(message_tree, hf_ocp1_notification_parameter_context, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    eventdata_tree = proto_tree_add_subtree(message_tree, tvb, offset_m, length-(offset_m - offset), ett_ocp1_event_data, &te, "Event Data");
    proto_tree_add_item(eventdata_tree, hf_ocp1_message_emitter_ono, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    teid = proto_tree_add_item(eventdata_tree, hf_ocp1_message_event_id, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    eventid_tree = proto_item_add_subtree(teid, ett_ocp1_event_method);

    proto_tree_add_item(eventid_tree, hf_ocp1_message_event_tree_level, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    proto_tree_add_item(eventid_tree, hf_ocp1_message_event_index, tvb, offset_m, 2, ENC_BIG_ENDIAN);
    offset_m += 2;

    if (length-(offset_m - offset) > 0) {
        decode_params(tvb, offset_m, length-(offset_m - offset),
            tvb_get_guint32(tvb, offset + 4, ENC_BIG_ENDIAN),
            tvb_get_guint16(tvb, offset + 8, ENC_BIG_ENDIAN),
            tvb_get_guint16(tvb, offset + 10, ENC_BIG_ENDIAN),
            tvb_get_guint8(tvb, offset + 12),
            false, eventdata_tree);
    }

    return length;
}

static int
dissect_ocp1_msg_response(tvbuff_t *tvb, gint offset, gint length, packet_info *pinfo, proto_tree *tree, guint msg_counter)
{
    proto_tree *message_tree;
    proto_item *ti, *r_pkt;
    conversation_t *conversation;
    struct oca_request_hash_key request_key;
    struct oca_request_hash_val *request_val=NULL, request_val_empty;

    message_tree = proto_tree_add_subtree_format(tree, tvb, offset, length, ett_ocp1_keepalive, &ti, "Response Message %d", msg_counter);

    gint offset_m = offset;

    proto_tree_add_item(message_tree, hf_ocp1_message_size, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    proto_tree_add_item(message_tree, hf_ocp1_message_handle, tvb, offset_m, 4, ENC_BIG_ENDIAN);
    offset_m += 4;

    proto_tree_add_item(message_tree, hf_ocp1_message_status_code, tvb, offset_m, 1, ENC_BIG_ENDIAN);
    if(tvb_get_guint8(tvb, offset_m) != 0x00) {
        expert_add_info(pinfo, ti, &ei_ocp1_bad_status_code);
    }
    offset_m += 1;

    proto_tree_add_item(message_tree, hf_ocp1_message_parameter_count, tvb, offset_m, 1, ENC_BIG_ENDIAN);
    offset_m += 1;

    /* Find request info */
    conversation = find_or_create_conversation(pinfo);
    request_key.conv_index = conversation->conv_index;
    request_key.handle     = tvb_get_guint32(tvb, offset + 4, ENC_BIG_ENDIAN);

    /* build an empty oca_request_val
     * if wmem lookup fails, reference this one to force the parameter dissectors to fail */
    request_val_empty.method_index = 0;
    request_val_empty.ono = 0;
    request_val_empty.tree_level = 0;
    request_val_empty.pnum = 0;

    request_val = (struct oca_request_hash_val *) wmem_map_lookup(oca_request_hash_map, &request_key);
    if(!request_val) {
        request_val = &request_val_empty;
    }

    if (length-(offset_m - offset) > 0) {
        decode_params(tvb, offset_m, length-(offset_m - offset),
            request_val->ono,
            request_val->tree_level,
            request_val->method_index,
            tvb_get_guint8(tvb, offset + 9),
            false, message_tree);
    }

    /* Add generated/expert info for packet lookup */
    if(request_val) {
        r_pkt = proto_tree_add_uint(message_tree , hf_ocp1_response_to, tvb, 0, 0, request_val->pnum);
        proto_item_set_generated(r_pkt);
    } else {
        expert_add_info(pinfo, ti, &ei_ocp1_handle_fail);
    }


    return length;
}

static int
dissect_ocp1_pdu(tvbuff_t *tvb, packet_info *pinfo, gint offset, proto_tree *tree, guint *pdu_counter)
{

    if (tvb_get_guint8(tvb, offset) != OCP1_SYNC_VAL)
        return offset;

    guint offset_d = offset;                         /* Increment counter for dissection */
    guint offset_m = offset + OCP1_FRAME_HEADER_LEN; /* Set offset to start of first message, will increment to next message later */

    if (tvb_captured_length_remaining(tvb, offset) < OCP1_FRAME_HEADER_LEN)
        return offset;

    guint32 header_pdu_size = tvb_get_guint32(tvb, offset + 3, ENC_BIG_ENDIAN);
    guint8  pdu_type        = tvb_get_guint8(tvb, offset + 7);

    proto_tree *pdu_tree;
    proto_item *ti;

    /* Create trees */
    switch (pdu_type)
    {
        case (OCP1_PDU_TYPE_OCA_CMD):
            pdu_counter[OCP1_PDU_TYPE_OCA_CMD]++;
            pdu_tree = proto_tree_add_subtree(tree, tvb, offset, header_pdu_size + 1, ett_ocp1_pdu, &ti, "Command PDU");
            break;
        case (OCP1_PDU_TYPE_OCA_CMD_RRQ):
            pdu_counter[OCP1_PDU_TYPE_OCA_CMD_RRQ]++;
            pdu_tree = proto_tree_add_subtree(tree, tvb, offset, header_pdu_size + 1, ett_ocp1_pdu, &ti, "CommandRrq PDU");
            break;
        case OCP1_PDU_TYPE_OCA_NTF:
            pdu_counter[OCP1_PDU_TYPE_OCA_NTF]++;
            pdu_tree = proto_tree_add_subtree(tree, tvb, offset, header_pdu_size + 1, ett_ocp1_pdu, &ti, "Notification PDU");
            break;
        case OCP1_PDU_TYPE_OCA_RSP:
            pdu_counter[OCP1_PDU_TYPE_OCA_RSP]++;
            pdu_tree = proto_tree_add_subtree(tree, tvb, offset, header_pdu_size + 1, ett_ocp1_pdu, &ti, "Response PDU");
            break;
        case OCP1_PDU_TYPE_OCA_KEEPALIVE:
            pdu_counter[OCP1_PDU_TYPE_OCA_KEEPALIVE]++;
            pdu_tree = proto_tree_add_subtree(tree, tvb, offset, header_pdu_size + 1, ett_ocp1_pdu, &ti, "Keep-Alive PDU");
            break;
        default:
            pdu_counter[OCP1_PDU_TYPE_ERROR_INDEX]++;
            pdu_tree = proto_tree_add_subtree(tree, tvb, offset, header_pdu_size + 1, ett_ocp1_pdu, &ti, "Invalid Type PDU");
            break;
    }

    /* dissect PDU */
    proto_tree_add_item(pdu_tree, hf_ocp1_sync_value, tvb, offset_d, 1, ENC_BIG_ENDIAN);
    offset_d += 1;

    proto_tree_add_item(pdu_tree, hf_ocp1_protocol_version, tvb, offset_d, 2, ENC_BIG_ENDIAN);
    offset_d += 2;

    proto_tree_add_item(pdu_tree, hf_ocp1_pdu_size, tvb, offset_d, 4, ENC_BIG_ENDIAN);
    offset_d += 4;

    proto_tree_add_item(pdu_tree, hf_ocp1_pdu_type, tvb, offset_d, 1, ENC_BIG_ENDIAN);
    offset_d += 1;

    proto_tree_add_item(pdu_tree, hf_ocp1_message_count, tvb, offset_d, 2, ENC_BIG_ENDIAN);

    guint msg_counter = 1;




    /* dissect PDU messages */
    switch (pdu_type)
    {
        case (OCP1_PDU_TYPE_OCA_CMD || OCP1_PDU_TYPE_OCA_CMD_RRQ):

            while (offset_m < (offset + header_pdu_size + 1)) {
                /* first 4 byte of message is command size (incl. these 4 bytes) */
                dissect_ocp1_msg_command(tvb, offset_m, tvb_get_guint32(tvb, offset_m, ENC_BIG_ENDIAN), pinfo, pdu_tree, msg_counter);
                offset_m += tvb_get_guint32(tvb, offset_m, ENC_BIG_ENDIAN);
                msg_counter++;
            }

            break;
        case OCP1_PDU_TYPE_OCA_NTF:

            while (offset_m < (offset + header_pdu_size + 1)) {
                /* first 4 byte of message is command size (incl. these 4 bytes) */
                dissect_ocp1_msg_notification(tvb, offset_m, tvb_get_guint32(tvb, offset_m, ENC_BIG_ENDIAN), pdu_tree, msg_counter);
                offset_m += tvb_get_guint32(tvb, offset_m, ENC_BIG_ENDIAN);
                msg_counter++;
            }

            break;
        case OCP1_PDU_TYPE_OCA_RSP:

            while (offset_m < (offset + header_pdu_size + 1)) {
                /* first 4 byte of message is response size (incl. these 4 bytes) */
                dissect_ocp1_msg_response(tvb, offset_m, tvb_get_guint32(tvb, offset_m, ENC_BIG_ENDIAN), pinfo, pdu_tree, msg_counter);
                offset_m += tvb_get_guint32(tvb, offset_m, ENC_BIG_ENDIAN);
                msg_counter++;
            }

            break;
        case OCP1_PDU_TYPE_OCA_KEEPALIVE:

            /* Keep-Alive shall only contain one message */
            if (tvb_get_guint16(tvb, offset + 8, ENC_BIG_ENDIAN) != 0x01)
                return 0;

            /* Message length possibe are 2 bytes (sec) or 4 bytes (msec) */
            if (header_pdu_size != 11 && header_pdu_size != 13)
                return 0;

            dissect_ocp1_msg_keepalive(tvb, offset_m, header_pdu_size - 9, pdu_tree);

            break;
        default:
            call_data_dissector(tvb_new_subset_length(tvb, offset + OCP1_FRAME_HEADER_LEN, header_pdu_size + 1 - OCP1_FRAME_HEADER_LEN), pinfo, pdu_tree);
            break;
    }

    return header_pdu_size + 1;
}

static int
dissect_ocp1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCP.1");
    col_clear(pinfo->cinfo, COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_ocp1, tvb, 0, -1, ENC_NA);
    proto_tree *ocp1_tree = proto_item_add_subtree(ti, ett_ocp1);

    guint pdu_counter[OCP1_PDU_TYPE_ERROR_INDEX+1] = {0};

    /* iterate through PDUs */
    guint offset = 0;
    while (offset < tvb_captured_length(tvb)) {

        int len = dissect_ocp1_pdu(tvb, pinfo, offset, ocp1_tree, pdu_counter);
        if(len == 0) return 0;
        offset += len;
    }

    /* Add column info */
    if(pdu_counter[OCP1_PDU_TYPE_OCA_CMD] > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Command (%d)", pdu_counter[OCP1_PDU_TYPE_OCA_CMD]);
    if(pdu_counter[OCP1_PDU_TYPE_OCA_CMD_RRQ] > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "CommandRrq (%d)", pdu_counter[OCP1_PDU_TYPE_OCA_CMD_RRQ]);
    if(pdu_counter[OCP1_PDU_TYPE_OCA_NTF] > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Notification (%d)", pdu_counter[OCP1_PDU_TYPE_OCA_NTF]);
    if(pdu_counter[OCP1_PDU_TYPE_OCA_RSP] > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Response (%d)", pdu_counter[OCP1_PDU_TYPE_OCA_RSP]);
    if(pdu_counter[OCP1_PDU_TYPE_OCA_KEEPALIVE] > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Keep-Alive (%d)", pdu_counter[OCP1_PDU_TYPE_OCA_KEEPALIVE]);
    if(pdu_counter[OCP1_PDU_TYPE_ERROR_INDEX] > 0)
        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "Invalid PDU type (%d)", pdu_counter[OCP1_PDU_TYPE_ERROR_INDEX]);

    return tvb_captured_length(tvb);
}

static guint
get_ocp1_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{

    gboolean another_pdu = TRUE;
    guint size = 0;

    /* concat multiple PDUs into one protocol tree */
    while(another_pdu) {

        guint pdu_size = tvb_get_guint32(tvb, offset + 3, ENC_BIG_ENDIAN) + 1;
        size += pdu_size;

        if (!(tvb_captured_length_remaining(tvb, offset + pdu_size) >= OCP1_FRAME_HEADER_LEN + 1) || pdu_size < OCP1_FRAME_HEADER_LEN - 1)
            another_pdu = FALSE;

        offset += pdu_size;
    }

    return size;

}

static int
dissect_ocp1_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!tvb_bytes_exist(tvb, 0, OCP1_FRAME_HEADER_LEN))
        return 0;

    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, OCP1_FRAME_HEADER_LEN, get_ocp1_message_len, dissect_ocp1, data);
    return tvb_reported_length(tvb);
}

static gboolean
test_ocp1(tvbuff_t *tvb)
{

    /* Heuristics assume PDU start at offset=0
     * Testing for SyncVal + Version at arbitrary position is not enough
     */

    /* Size must be larger than SyncVal + Header = 10 bytes */
    if (tvb_captured_length(tvb) < OCP1_FRAME_HEADER_LEN)
        return FALSE;

    /* PDU size must be larger than header size (without SyncVal) */
    if (tvb_get_guint32(tvb, 3, ENC_BIG_ENDIAN) < OCP1_FRAME_HEADER_LEN - 1)
        return FALSE;

    /* SyncVal must be the first byte */
    if (tvb_get_guint8(tvb, 0) != OCP1_SYNC_VAL)
        return FALSE;

    /* Protocol version must be 0x0001 */
    if (tvb_get_guint16(tvb, 1, ENC_BIG_ENDIAN) != OCP1_PROTO_VER)
        return FALSE;

    /* PDU type can be 0x00-0x04 */
    if (tvb_get_guint8(tvb, 7) > 0x04)
        return FALSE;

    /* Check packet length
        * - PDU's header size can be larger than packet (fragmentation)
        * - packet could be larger then header's PDU size (multiple PDUs)
        *   If the byte after message one is SyncVal again and there are enough remaining bytes
        *   for at least a header, then it smells like OCP.1, really...but don't iterate through every possible PDU
        *   (Header's PDU size field includes header and message length but excludes SyncVal (1 byte))
    */
    guint header_pdu_size = tvb_get_guint32(tvb, 3, ENC_BIG_ENDIAN);
    if (tvb_captured_length(tvb) > header_pdu_size + 1) {
        if (
            tvb_get_guint8(tvb, header_pdu_size + 1) != OCP1_SYNC_VAL &&
            tvb_captured_length(tvb) <= header_pdu_size + 11 /* PDU one (PDU size + SyncVal) + SyncVal-/Header length PDU two = 11 bytes */
        )
            return FALSE;
    }

    return TRUE;
}

static gboolean
dissect_ocp1_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_ocp1(tvb))
        return FALSE;

    dissect_ocp1_tcp(tvb, pinfo, tree, data);

    return (TRUE);
}

static gboolean
dissect_ocp1_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    if (!test_ocp1(tvb))
        return FALSE;

    dissect_ocp1(tvb, pinfo, tree, data);

    return (TRUE);
}

void
proto_register_ocp1(void)
{
    static hf_register_info hf[] = {

        /* PDU */
        { &hf_ocp1_sync_value,
            { "Sync Value", "ocp1.syncval",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_protocol_version,
            { "Protocol Version", "ocp1.version",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_pdu_size,
            { "Size", "ocp1.size",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_pdu_type,
            { "Type", "ocp1.type",
            FT_UINT8, BASE_DEC,
            VALS(pdu_type_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_count,
            { "Message Count", "ocp1.msgcount",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        /* Responses */
        { &hf_ocp1_response_to,
            { "Response to", "ocp1.response_to",
            FT_FRAMENUM, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        /* Heartbeat */
        { &hf_ocp1_heartbeat_time_s,
            { "Heartbeat Time", "ocp1.heartbeat.time",
            FT_UINT16, BASE_DEC | BASE_UNIT_STRING,
            &units_seconds, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_heartbeat_time_ms,
            { "Heartbeat Time", "ocp1.heartbeat.time",
            FT_UINT32, BASE_DEC | BASE_UNIT_STRING,
            &units_milliseconds, 0x0,
            NULL, HFILL }
        },

        /* Common */
        { &hf_ocp1_message_occ,
            { "OCC", "ocp1.occ",
            FT_UINT64, BASE_CUSTOM,
            CF_FUNC(format_occ), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_target_ono,
            { "Target Object No.", "ocp1.tono",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_emitter_ono,
            { "Emitter Object No.", "ocp1.eono",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_parameter_count,
            { "Parameter Count", "ocp1.pcount",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_method_id,
            { "Method ID", "ocp1.mid",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_method_tree_level,
            { "Tree Level", "ocp1.mlevel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_method_index,
            { "Method Index", "ocp1.midx",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_event_id,
            { "Event ID", "ocp1.eid",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_event_tree_level,
            { "Tree Level", "ocp1.elevel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_event_index,
            { "Event Index", "ocp1.eidx",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_size,
            { "Size", "ocp1.msgsize",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_handle,
            { "Handle", "ocp1.handle",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_message_status_code,
            { "Status Code", "ocp1.status",
            FT_UINT8, BASE_DEC,
            VALS(OcaStatus), 0x0,
            NULL, HFILL }
        },

        /* Notification */
        { &hf_ocp1_notification_parameter_context,
            { "Context", "ocp1.context",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        /* Parameter */
        { &hf_ocp1_params,
            { "Parameter Data", "ocp1.params",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_bool,
            { "Boolean", "ocp1.params.bool",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_ono,
            { "Object No.", "ocp1.params.ono",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_event_id,
            { "Event ID", "ocp1.params.eid",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_event_tree_level,
            { "Tree Level", "ocp1.params.elevel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_event_index,
            { "Event Index", "ocp1.params.eidx",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_method_id,
            { "Method ID", "ocp1.params.mid",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_method_tree_level,
            { "Tree Level", "ocp1.params.mlevel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_method_index,
            { "Method Index", "ocp1.params.midx",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_property_id,
            { "Method ID", "ocp1.params.pid",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_property_tree_level,
            { "Tree Level", "ocp1.params.plevel",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_property_index,
            { "Property Index", "ocp1.params.pidx",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_blob,
            { "Blob", "ocp1.params.blob",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_blob_datasize,
            { "Size", "ocp1.params.blob.size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_blob_data,
            { "Data", "ocp1.params.blob.data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_string,
            { "String", "ocp1.params.string",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_string_length,
            { "Length", "ocp1.params.string.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_string_value,
            { "Value", "ocp1.params.string.value",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_ntf_delivery_mode,
            { "Notification Delivery Mode", "ocp1.params.dmode",
            FT_UINT8, BASE_DEC,
            VALS(OcaNotificationDeliveryMode), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_list_count,
            { "List Count", "ocp1.params.lcount",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_map_count,
            { "List Count", "ocp1.params.mcount",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_classid_fields,
            { "Class ID Fields", "ocp1.params.classid.fields",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_classid,
            { "Class ID", "ocp1.params.classid",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_class_version,
            { "Class Version", "ocp1.params.classver",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_imageid,
            { "ID", "ocp1.params.imageid",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_oca_version,
            { "OCA Version", "ocp1.params.ocaver",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_reset_cause,
            { "Reset Cause", "ocp1.params.resetcause",
            FT_UINT8, BASE_DEC,
            VALS(OcaResetCause), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_power_state,
            { "Power State", "ocp1.params.powerstate",
            FT_UINT8, BASE_DEC,
            VALS(OcaPowerState), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_media_clock_type,
            { "Media Clock Type", "ocp1.params.mediaclocktype",
            FT_UINT8, BASE_DEC,
            VALS(OcaMediaClockType), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_component,
            { "Component", "ocp1.params.component",
            FT_UINT16, BASE_DEC,
            VALS(OcaComponent), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_devicestate,
            { "Device State", "ocp1.params.devicestate",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_devicestate_oper,
            { "Operational", "ocp1.params.devicestate.oper",
            FT_BOOLEAN, 16,
            NULL, OCP1_DEVICESTATE_OPER,
            NULL, HFILL }
        },
        { &hf_ocp1_params_devicestate_disabled,
            { "Disabled", "ocp1.params.devicestate.disabled",
            FT_BOOLEAN, 16,
            NULL, OCP1_DEVICESTATE_DISABLED,
            NULL, HFILL }
        },
        { &hf_ocp1_params_devicestate_error,
            { "Error", "ocp1.params.devicestate.error",
            FT_BOOLEAN, 16,
            NULL, OCP1_DEVICESTATE_ERROR,
            NULL, HFILL }
        },
        { &hf_ocp1_params_devicestate_init,
            { "Initializing", "ocp1.params.devicestate.init",
            FT_BOOLEAN, 16,
            NULL, OCP1_DEVICESTATE_INIT,
            NULL, HFILL }
        },
        { &hf_ocp1_params_devicestate_updating,
            { "Updating", "ocp1.params.devicestate.updating",
            FT_BOOLEAN, 16,
            NULL, OCP1_DEVICESTATE_UPDATING,
            NULL, HFILL }
        },
        { &hf_ocp1_params_ocaver_major,
            { "Major", "ocp1.params.ocaver.major",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_ocaver_minor,
            { "Minor", "ocp1.params.ocaver.minor",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_ocaver_build,
            { "Build", "ocp1.params.ocaver.build",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_ocaver_comp,
            { "Component", "ocp1.params.ocaver.component",
            FT_UINT16, BASE_DEC,
            VALS(OcaComponent), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_subscriber_ctx_len,
            { "Max. Subscriber Context Length", "ocp1.params.subscr_ctx_len",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_libvol_id,
            { "Library Volume ID", "ocp1.params.libvolid",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_libvoltype_id,
            { "Library Volume Type ID", "ocp1.params.libvoltype",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_library_count,
            { "Library Count", "ocp1.params.libcount",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_ntp,
            { "NTP Time", "ocp1.params.time_ntp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_NTP_UTC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_ptp_negative,
            { "Negative", "ocp1.params.time_ptp_negative",
            FT_BOOLEAN, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_ptp,
            { "PTP Time", "ocp1.params.time_ptp",
            FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_ptp_seconds,
            { "Seconds", "ocp1.params.time_ptp_seconds",
            FT_UINT64, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_ptp_nanoseconds,
            { "Nanoseconds", "ocp1.params.time_ptp_nanoseconds",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_mode,
            { "Time Mode", "ocp1.params.time_mode",
            FT_UINT8, BASE_DEC,
            VALS(OcaTimeMode), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_units,
            { "Time Units", "ocp1.params.time_units",
            FT_UINT8, BASE_DEC,
            VALS(OcaTimeUnits), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_task_id,
            { "Task ID", "ocp1.params.task_id",
            FT_UINT32, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_task_group_id,
            { "Task Group ID", "ocp1.params.task_group_id",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_time_interval,
            { "Time Interval", "ocp1.params.time_interval",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_start_time,
            { "Start Time", "ocp1.params.start_time",
            FT_UINT64, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_task_command,
            { "Task Command", "ocp1.params.task_command",
            FT_UINT8, BASE_DEC,
            VALS(OcaTaskCommand), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_task_manager_state,
            { "Task Manager State", "ocp1.params.task_mgr_state",
            FT_UINT8, BASE_DEC,
            VALS(OcaTaskManagerState), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_task_state,
            { "Task Manager State", "ocp1.params.task_state",
            FT_UINT8, BASE_DEC,
            VALS(OcaTaskState), 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_task_status_error_code,
            { "Task Manager State", "ocp1.params.task_status_error_code",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_ocp1_params_media_coding_scheme_id,
            { "Media Coding Scheme ID", "ocp1.params.media_coding_scheme_id",
            FT_UINT16, BASE_DEC_HEX,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    static ei_register_info ei[] = {
        { &ei_ocp1_handle_fail,
            { "ocp1.handle_fail", PI_RESPONSE_CODE, PI_WARN,
                "Request to handle not captured", EXPFILL }
        },
        { &ei_ocp1_bad_status_code,
            { "ocp1.bad_status_code", PI_RESPONSE_CODE, PI_ERROR,
                "Status code indicates failed command", EXPFILL }
        }
    };

    static gint *ett[] = {
        &ett_ocp1,
        &ett_ocp1_pdu,
        &ett_ocp1_keepalive,
        &ett_ocp1_message_method,
        &ett_ocp1_event_data,
        &ett_ocp1_event_method,
        &ett_ocp1_params,
        &ett_ocp1_params_event,
        &ett_ocp1_params_method,
        &ett_ocp1_params_property,
        &ett_ocp1_params_blob,
        &ett_ocp1_params_string,
        &ett_ocp1_params_manager_desc,
        &ett_ocp1_params_devicestate,
        &ett_ocp1_params_compversion,
        &ett_ocp1_params_ocaver,
        &ett_ocp1_params_ptp
    };

    oca_request_hash_map = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), oca_handle_hash, oca_handle_equal);

    proto_ocp1 = proto_register_protocol("Open Control Protocol (OCP.1/AES70)", "OCP.1", "ocp1");

    proto_register_field_array(proto_ocp1, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_ocp1 = expert_register_protocol(proto_ocp1);
    expert_register_field_array(expert_ocp1, ei, array_length(ei));
}

void
proto_reg_handoff_ocp1(void)
{

    ocp1_tcp_handle = create_dissector_handle(dissect_ocp1_tcp, proto_ocp1);
    ocp1_udp_handle = create_dissector_handle(dissect_ocp1, proto_ocp1);

    heur_dissector_add("tcp", dissect_ocp1_heur_tcp, "OCP.1 over TCP", "ocp1_tcp", proto_ocp1, HEURISTIC_ENABLE);
    heur_dissector_add("udp", dissect_ocp1_heur_udp, "OCP.1 over UDP", "ocp1_udp", proto_ocp1, HEURISTIC_ENABLE);

}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
