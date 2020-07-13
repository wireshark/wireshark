/* packet-systemd-journal.c
 * Routines for systemd journal export (application/vnd.fdo.journal) dissection
 * Copyright 2018, Gerald Combs <gerald@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Dissector for systemd's mostly-text-based Journal Export Format described
 * at https://www.freedesktop.org/wiki/Software/systemd/export/.
 *
 * Registered MIME type: application/vnd.fdo.journal
 *
 * To do:
 * - Rename systemd_journal to sdjournal? It's easier to type.
 * - Add an extcap module.
 * - Add errno strings.
 * - Pretty-print _CAP_EFFECTIVE
 * - Handle Journal JSON Format? https://www.freedesktop.org/wiki/Software/systemd/json/
 * - Handle raw journal files? https://www.freedesktop.org/wiki/Software/systemd/journal-files/
 */

#include <config.h>

#include <epan/exceptions.h>
#include <epan/packet.h>
#include <epan/expert.h>

#include <wsutil/strtoi.h>

#include "packet-syslog.h"

#define PNAME  "systemd Journal Entry"
#define PSNAME "systemd Journal"
#define PFNAME "systemd_journal"

void proto_reg_handoff_systemd_journal(void);
void proto_register_systemd_journal(void);

/* Initialize the protocol and registered fields */
static int proto_systemd_journal = -1;

// Official entries, listed in
// https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
// as of 2018-08.
static int hf_sj_message = -1;
static int hf_sj_message_id = -1;
static int hf_sj_priority = -1;
static int hf_sj_code_file = -1;
static int hf_sj_code_line = -1;
static int hf_sj_code_func = -1;
static int hf_sj_errno = -1;
static int hf_sj_syslog_facility = -1;
static int hf_sj_syslog_identifier = -1;
static int hf_sj_syslog_pid = -1;

static int hf_sj_pid = -1;
static int hf_sj_uid = -1;
static int hf_sj_gid = -1;
static int hf_sj_comm = -1;
static int hf_sj_exe = -1;
static int hf_sj_cmdline = -1;
static int hf_sj_cap_effective = -1;
static int hf_sj_audit_session = -1;
static int hf_sj_audit_loginuid = -1;
static int hf_sj_systemd_cgroup = -1;
static int hf_sj_systemd_slice = -1;
static int hf_sj_systemd_unit = -1;
static int hf_sj_systemd_user_unit = -1;
static int hf_sj_systemd_session = -1;
static int hf_sj_systemd_owner_uid = -1;

static int hf_sj_selinux_context = -1;
static int hf_sj_source_realtime_timestamp = -1;
static int hf_sj_boot_id = -1;
static int hf_sj_machine_id = -1;
static int hf_sj_systemd_invocation_id = -1;
static int hf_sj_hostname = -1;
static int hf_sj_transport = -1;
static int hf_sj_stream_id = -1;
static int hf_sj_line_break = -1;

static int hf_sj_kernel_device = -1;
static int hf_sj_kernel_subsystem = -1;
static int hf_sj_udev_sysname = -1;
static int hf_sj_udev_devnode = -1;
static int hf_sj_udev_devlink = -1;

static int hf_sj_coredump_unit = -1;
static int hf_sj_coredump_user_unit = -1;
static int hf_sj_object_pid = -1;
static int hf_sj_object_uid = -1;
static int hf_sj_object_gid = -1;
static int hf_sj_object_comm = -1;
static int hf_sj_object_exe = -1;
static int hf_sj_object_cmdline = -1;
static int hf_sj_object_audit_session = -1;
static int hf_sj_object_audit_loginuid = -1;
static int hf_sj_object_cap_effective = -1;
static int hf_sj_object_selinux_context = -1;
static int hf_sj_object_systemd_cgroup = -1;
static int hf_sj_object_systemd_session = -1;
static int hf_sj_object_systemd_owner_uid = -1;
static int hf_sj_object_systemd_unit = -1;
static int hf_sj_object_systemd_user_unit = -1;
static int hf_sj_object_systemd_slice = -1;
static int hf_sj_object_systemd_user_slice = -1;
static int hf_sj_object_systemd_invocation_id = -1;

static int hf_sj_cursor = -1;
static int hf_sj_realtime_timestamp = -1;
static int hf_sj_monotonic_timestamp = -1;

// Unofficial(?) fields. Not listed in the documentation but present in logs.
static int hf_sj_result = -1;
static int hf_sj_source_monotonic_timestamp = -1;
static int hf_sj_journal_name = -1;
static int hf_sj_journal_path = -1;
static int hf_sj_current_use = -1;
static int hf_sj_current_use_pretty = -1;
static int hf_sj_max_use = -1;
static int hf_sj_max_use_pretty = -1;
static int hf_sj_disk_keep_free = -1;
static int hf_sj_disk_keep_free_pretty = -1;
static int hf_sj_disk_available = -1;
static int hf_sj_disk_available_pretty = -1;
static int hf_sj_limit = -1;
static int hf_sj_limit_pretty = -1;
static int hf_sj_available = -1;
static int hf_sj_available_pretty = -1;
static int hf_sj_audit_type = -1;
static int hf_sj_audit_id = -1;
static int hf_sj_audit_field_apparmor = -1;
static int hf_sj_audit_field_operation = -1;
static int hf_sj_audit_field_profile = -1;
static int hf_sj_audit_field_name = -1;
static int hf_sj_seat_id = -1;
static int hf_sj_kernel_usec = -1;
static int hf_sj_userspace_usec = -1;
static int hf_sj_session_id = -1;
static int hf_sj_user_id = -1;
static int hf_sj_leader = -1;
static int hf_sj_job_type = -1;
static int hf_sj_job_result = -1;
static int hf_sj_user_invocation_id = -1;
static int hf_sj_systemd_user_slice = -1;

// Metadata.
static int hf_sj_binary_data_len = -1;
static int hf_sj_unknown_field = -1;
static int hf_sj_unknown_field_name = -1;
static int hf_sj_unknown_field_value = -1;
static int hf_sj_unknown_field_data = -1;
static int hf_sj_unhandled_field_type = -1;

static expert_field ei_unhandled_field_type = EI_INIT;
static expert_field ei_nonbinary_field = EI_INIT;
static expert_field ei_undecoded_field = EI_INIT;

#define MAX_DATA_SIZE 262144 // WTAP_MAX_PACKET_SIZE_STANDARD. Increase if needed.

/* Initialize the subtree pointers */
static gint ett_systemd_journal_entry = -1;
static gint ett_systemd_binary_data = -1;
static gint ett_systemd_unknown_field = -1;

// XXX Use a value_string instead?
typedef struct _journal_field_hf_map {
    int hfid;
    const char *name;
} journal_field_hf_map;

static journal_field_hf_map *jf_to_hf;

static void init_jf_to_hf_map(void) {
    journal_field_hf_map jhmap[] = {
        // Official.
        { hf_sj_message, "MESSAGE=" },
        { hf_sj_message_id, "MESSAGE_ID=" },
        { hf_sj_priority, "PRIORITY=" },
        { hf_sj_code_file, "CODE_FILE=" },
        { hf_sj_code_line, "CODE_LINE=" },
        { hf_sj_code_func, "CODE_FUNC=" },
        { hf_sj_result, "RESULT=" },
        { hf_sj_errno, "ERRNO=" },
        { hf_sj_syslog_facility, "SYSLOG_FACILITY=" },
        { hf_sj_syslog_identifier, "SYSLOG_IDENTIFIER=" },
        { hf_sj_syslog_pid, "SYSLOG_PID=" },

        { hf_sj_pid, "_PID=" },
        { hf_sj_uid, "_UID=" },
        { hf_sj_gid, "_GID=" },
        { hf_sj_comm, "_COMM=" },
        { hf_sj_exe, "_EXE=" },
        { hf_sj_cmdline, "_CMDLINE=" },
        { hf_sj_cap_effective, "_CAP_EFFECTIVE=" },
        { hf_sj_audit_session, "_AUDIT_SESSION=" },
        { hf_sj_audit_loginuid, "_AUDIT_LOGINUID=" },
        { hf_sj_systemd_cgroup, "_SYSTEMD_CGROUP=" },
        { hf_sj_systemd_slice, "_SYSTEMD_SLICE=" },
        { hf_sj_systemd_unit, "_SYSTEMD_UNIT=" },
        { hf_sj_systemd_user_unit, "_SYSTEMD_USER_UNIT=" },
        { hf_sj_systemd_session, "_SYSTEMD_SESSION=" },
        { hf_sj_systemd_owner_uid, "_SYSTEMD_OWNER_UID=" },

        { hf_sj_selinux_context, "_SELINUX_CONTEXT=" },
        { hf_sj_source_realtime_timestamp, "_SOURCE_REALTIME_TIMESTAMP=" },
        { hf_sj_source_monotonic_timestamp, "_SOURCE_MONOTONIC_TIMESTAMP=" },
        { hf_sj_boot_id, "_BOOT_ID=" },
        { hf_sj_machine_id, "_MACHINE_ID=" },
        { hf_sj_systemd_invocation_id, "_SYSTEMD_INVOCATION_ID=" },
        { hf_sj_hostname, "_HOSTNAME=" },
        { hf_sj_transport, "_TRANSPORT=" },
        { hf_sj_stream_id, "_STREAM_ID=" },
        { hf_sj_line_break, "_LINE_BREAK=" },

        { hf_sj_kernel_device, "_KERNEL_DEVICE=" },
        { hf_sj_kernel_subsystem, "_KERNEL_SUBSYSTEM=" },
        { hf_sj_udev_sysname, "_UDEV_SYSNAME=" },
        { hf_sj_udev_devnode, "_UDEV_DEVNODE=" },
        { hf_sj_udev_devlink, "_UDEV_DEVLINK=" },

        { hf_sj_coredump_unit, "COREDUMP_UNIT=" },
        { hf_sj_coredump_user_unit, "COREDUMP_USER_UNIT=" },
        { hf_sj_object_pid, "OBJECT_PID=" },
        { hf_sj_object_uid, "OBJECT_UID=" },
        { hf_sj_object_gid, "OBJECT_GID=" },
        { hf_sj_object_comm, "OBJECT_COMM=" },
        { hf_sj_object_exe, "OBJECT_EXE=" },
        { hf_sj_object_cmdline, "OBJECT_CMDLINE=" },
        { hf_sj_object_audit_session, "OBJECT_AUDIT_SESSION=" },
        { hf_sj_object_audit_loginuid, "OBJECT_AUDIT_LOGINUID=" },
        { hf_sj_object_cap_effective, "OBJECT_CAP_EFFECTIVE=" },
        { hf_sj_object_selinux_context, "OBJECT_SELINUX_CONTEXT=" },
        { hf_sj_object_systemd_cgroup, "OBJECT_SYSTEMD_CGROUP=" },
        { hf_sj_object_systemd_session, "OBJECT_SYSTEMD_SESSION=" },
        { hf_sj_object_systemd_owner_uid, "OBJECT_SYSTEMD_OWNER_UID=" },
        { hf_sj_object_systemd_unit, "OBJECT_SYSTEMD_UNIT=" },
        { hf_sj_object_systemd_user_unit, "OBJECT_SYSTEMD_USER_UNIT=" },
        { hf_sj_object_systemd_slice, "OBJECT_SYSTEMD_SLICE=" },
        { hf_sj_object_systemd_user_slice, "OBJECT_SYSTEMD_USER_SLICE=" },
        { hf_sj_object_systemd_invocation_id, "OBJECT_SYSTEMD_INVOCATION_ID=" },

        { hf_sj_cursor, "__CURSOR=" },
        { hf_sj_realtime_timestamp, "__REALTIME_TIMESTAMP=" },
        { hf_sj_monotonic_timestamp, "__MONOTONIC_TIMESTAMP=" },

        // Unofficial?
        { hf_sj_journal_name, "JOURNAL_NAME=" }, // systemd-journald: Runtime journal (/run/log/journal/) is ...
        { hf_sj_journal_path, "JOURNAL_PATH=" }, // ""
        { hf_sj_current_use, "CURRENT_USE=" }, // ""
        { hf_sj_current_use_pretty, "CURRENT_USE_PRETTY=" }, // ""
        { hf_sj_max_use, "MAX_USE=" }, // ""
        { hf_sj_max_use_pretty, "MAX_USE_PRETTY=" }, // ""
        { hf_sj_disk_keep_free, "DISK_KEEP_FREE=" }, // ""
        { hf_sj_disk_keep_free_pretty, "DISK_KEEP_FREE_PRETTY=" }, // ""
        { hf_sj_disk_available, "DISK_AVAILABLE=" }, // ""
        { hf_sj_disk_available_pretty, "DISK_AVAILABLE_PRETTY=" }, // ""
        { hf_sj_limit, "LIMIT=" }, // ""
        { hf_sj_limit_pretty, "LIMIT_PRETTY=" }, // ""
        { hf_sj_available, "AVAILABLE=" }, // ""
        { hf_sj_available_pretty, "AVAILABLE_PRETTY=" }, // ""
        { hf_sj_code_func, "CODE_FUNCTION=" }, // Dup / alias of CODE_FUNC?
        { hf_sj_systemd_user_unit, "UNIT=" }, // Dup / alias of _SYSTEMD_UNIT?
        { hf_sj_systemd_user_unit, "USER_UNIT=" }, // Dup / alias of _SYSTEMD_USER_UNIT?
        { hf_sj_audit_type, "_AUDIT_TYPE=" },
        { hf_sj_audit_id, "_AUDIT_ID=" },
        { hf_sj_audit_field_apparmor, "_AUDIT_FIELD_APPARMOR=" },
        { hf_sj_audit_field_operation, "_AUDIT_FIELD_OPERATION=" },
        { hf_sj_audit_field_profile, "_AUDIT_FIELD_PROFILE=" },
        { hf_sj_audit_field_name, "_AUDIT_FIELD_NAME=" },
        { hf_sj_seat_id, "SEAT_ID=" },
        { hf_sj_kernel_usec, "KERNEL_USEC=" },
        { hf_sj_userspace_usec, "USERSPACE_USEC" },
        { hf_sj_session_id, "SESSION_ID" },
        { hf_sj_user_id, "USER_ID" },
        { hf_sj_leader, "LEADER" },
        { hf_sj_job_type, "JOB_TYPE" },
        { hf_sj_job_result, "JOB_RESULT" },
        { hf_sj_user_invocation_id, "USER_INVOCATION_ID" },
        { hf_sj_systemd_user_slice, "_SYSTEMD_USER_SLICE=" },
        { 0, NULL }
    };
    jf_to_hf = (journal_field_hf_map*) g_memdup(jhmap, sizeof(jhmap));
}

static void
dissect_sjle_time_usecs(proto_tree *tree, int hf_idx, tvbuff_t *tvb, int offset, int len) {
    guint64 rt_ts = 0;
    char *time_str = tvb_format_text(tvb, offset, len);
    gboolean ok = ws_strtou64(time_str, NULL, &rt_ts);
    if (ok) {
        nstime_t ts;
        ts.secs = (time_t) (rt_ts / 1000000);
        ts.nsecs = (rt_ts % 1000000) * 1000;
        proto_tree_add_time(tree, hf_idx, tvb, offset, len, &ts);
    } else {
        proto_tree_add_expert_format(tree, NULL, &ei_undecoded_field, tvb, offset, len, "Invalid time value %s", time_str);
    }
}

static void
dissect_sjle_uint(proto_tree *tree, int hf_idx, tvbuff_t *tvb, int offset, int len) {
    guint32 uint_val = (guint32) strtoul(tvb_format_text(tvb, offset, len), NULL, 10);
    proto_tree_add_uint(tree, hf_idx, tvb, offset, len, uint_val);
}

static void
dissect_sjle_int(proto_tree *tree, int hf_idx, tvbuff_t *tvb, int offset, int len) {
    gint32 int_val = (gint32) strtol(tvb_format_text(tvb, offset, len), NULL, 10);
    proto_tree_add_int(tree, hf_idx, tvb, offset, len, int_val);
}

/* Dissect a line-based journal export entry */
static int
dissect_systemd_journal_line_entry(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *sje_tree;
    int         offset = 0, next_offset = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
    col_clear(pinfo->cinfo, COL_INFO);
    col_set_str(pinfo->cinfo, COL_INFO, "Journal Entry");

    ti = proto_tree_add_item(tree, proto_systemd_journal, tvb, 0, -1, ENC_NA);
    sje_tree = proto_item_add_subtree(ti, ett_systemd_journal_entry);

    while (tvb_offset_exists(tvb, offset)) {
        int line_len = tvb_find_line_end(tvb, offset, -1, &next_offset, FALSE);
        if (line_len < 3) {
            // Invalid or zero length.
            // XXX Add an expert item for non-empty lines.
            offset = next_offset;
            continue;
        }
        gboolean found = FALSE;
        int eq_off = tvb_find_guint8(tvb, offset, line_len, '=') + 1;
        int val_len = offset + line_len - eq_off;

        for (int i = 0; jf_to_hf[i].name; i++) {
            if (tvb_memeql(tvb, offset, (const guint8*) jf_to_hf[i].name, strlen(jf_to_hf[i].name)) == 0) {
                int hf_idx = jf_to_hf[i].hfid;
                switch (proto_registrar_get_ftype(hf_idx)) {
                case FT_ABSOLUTE_TIME:
                case FT_RELATIVE_TIME:
                    dissect_sjle_time_usecs(sje_tree, hf_idx, tvb, eq_off, val_len);
                    break;
                case FT_UINT32:
                case FT_UINT16:
                case FT_UINT8:
                    dissect_sjle_uint(sje_tree, hf_idx, tvb, eq_off, val_len);
                    break;
                case FT_INT32:
                case FT_INT16:
                case FT_INT8:
                    dissect_sjle_int(sje_tree, hf_idx, tvb, eq_off, val_len);
                    break;
                case FT_STRING:
                    proto_tree_add_item(sje_tree, jf_to_hf[i].hfid, tvb, eq_off, val_len, ENC_UTF_8|ENC_NA);
                    break;
                default:
                {
                    proto_item *expert_ti = proto_tree_add_item(sje_tree, hf_sj_unhandled_field_type, tvb, offset, line_len,
                                                                    ENC_UTF_8|ENC_NA);
                    expert_add_info(pinfo, expert_ti, &ei_unhandled_field_type);
                    break;
                }
                }
                if (hf_idx == hf_sj_message) {
                    col_clear(pinfo->cinfo, COL_INFO);
                    col_add_str(pinfo->cinfo, COL_INFO, (char *) tvb_get_string_enc(wmem_packet_scope(), tvb, eq_off, val_len, ENC_UTF_8));
                }
                found = TRUE;
            }
        }

        if (!found && eq_off > offset + 1) {
            proto_item *unk_ti = proto_tree_add_none_format(sje_tree, hf_sj_unknown_field, tvb, offset, line_len,
                                                            "Unknown text field: %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset, eq_off - offset - 1, ENC_UTF_8));
            proto_tree *unk_tree = proto_item_add_subtree(unk_ti, ett_systemd_unknown_field);
            proto_tree_add_item(unk_tree, hf_sj_unknown_field_name, tvb, offset, eq_off - offset - 1, ENC_UTF_8|ENC_NA);
            proto_tree_add_item(unk_tree, hf_sj_unknown_field_value, tvb, eq_off, val_len, ENC_UTF_8|ENC_NA);
            offset = next_offset;
            continue;
        }

        // Try again, looking for binary fields.
        if (!found) {
            for (int i = 0; jf_to_hf[i].name; i++) {
                int noeql_len = (int) strlen(jf_to_hf[i].name) - 1;
                if (tvb_memeql(tvb, offset, (const guint8 *) jf_to_hf[i].name, (size_t) noeql_len) == 0 && tvb_memeql(tvb, offset+noeql_len, (const guint8 *) "\n", 1) == 0) {
                    int hf_idx = jf_to_hf[i].hfid;
                    guint64 data_len = tvb_get_letoh64(tvb, offset + noeql_len + 1);
                    int data_off = offset + noeql_len + 1 + 8; // \n + data len
                    next_offset = data_off + (int) data_len + 1;
                    if (proto_registrar_get_ftype(hf_idx) == FT_STRING) {
                        proto_item *bin_ti = proto_tree_add_item(sje_tree, hf_idx, tvb, data_off, (int) data_len, ENC_NA);
                        proto_tree *bin_tree = proto_item_add_subtree(bin_ti, ett_systemd_binary_data);
                        proto_tree_add_item(bin_tree, hf_sj_binary_data_len, tvb, offset + noeql_len + 1, 8, ENC_LITTLE_ENDIAN);
                        if (hf_idx == hf_sj_message) {
                            col_clear(pinfo->cinfo, COL_INFO);
                            col_add_str(pinfo->cinfo, COL_INFO, tvb_format_text(tvb, data_off, (int) data_len));
                        }
                    } else {
                        proto_item *unk_ti = proto_tree_add_none_format(sje_tree, hf_sj_unknown_field, tvb, offset, line_len,
                                                                        "Unknown data field: %s", tvb_format_text(tvb, offset, eq_off - offset - 1));
                        proto_tree *unk_tree = proto_item_add_subtree(unk_ti, ett_systemd_unknown_field);
                        proto_item *expert_ti = proto_tree_add_item(unk_tree, hf_sj_unknown_field_name, tvb, offset, offset + noeql_len, ENC_UTF_8|ENC_NA);
                        proto_tree_add_item(unk_tree, hf_sj_unknown_field_data, tvb, data_off, (int) data_len, ENC_UTF_8|ENC_NA);
                        expert_add_info(pinfo, expert_ti, &ei_nonbinary_field);
                    }
                }
            }
        }
        offset = next_offset;
    }

    return offset;
}

/*
 * Register the protocol with Wireshark.
 */
void
proto_register_systemd_journal(void)
{
    expert_module_t *expert_systemd_journal;

    static hf_register_info hf[] = {
        { &hf_sj_message,
          { "Message", "systemd_journal.message",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_message_id,
          { "Message ID", "systemd_journal.message_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_priority,
          { "Priority", "systemd_journal.priority",
            FT_UINT8, BASE_DEC, VALS(syslog_level_vals), 0x0, NULL, HFILL }
        },
        { &hf_sj_code_file,
          { "Code file", "systemd_journal.code_file",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_code_line,
          { "Code line", "systemd_journal.code_line",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_code_func,
          { "Code func", "systemd_journal.code_func",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_errno,
          { "Errno", "systemd_journal.errno",
            FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_syslog_facility,
          { "Syslog facility", "systemd_journal.syslog_facility",
            FT_UINT8, BASE_NONE, VALS(syslog_facility_vals), 0x0, NULL, HFILL }
        },
        { &hf_sj_syslog_identifier,
          { "Syslog identifier", "systemd_journal.syslog_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_syslog_pid,
          { "Syslog PID", "systemd_journal.syslog_pid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_pid,
          { "PID", "systemd_journal.pid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_uid,
          { "UID", "systemd_journal.uid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_gid,
          { "GID", "systemd_journal.gid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_comm,
          { "Command name", "systemd_journal.comm",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_exe,
          { "Executable path", "systemd_journal.exe",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_cmdline,
          { "Command line", "systemd_journal.cmdline",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_cap_effective,
          { "Effective capability", "systemd_journal.cap_effective",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_session,
          { "Audit session", "systemd_journal.audit_session",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_loginuid,
          { "Audit login UID", "systemd_journal.audit_loginuid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_systemd_cgroup,
          { "Systemd cgroup", "systemd_journal.systemd_cgroup",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_slice,
          { "Systemd slice", "systemd_journal.systemd_slice",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_unit,
          { "Systemd unit", "systemd_journal.systemd_unit",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_user_unit,
          { "Systemd user unit", "systemd_journal.systemd_user_unit",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_session,
          { "Systemd session", "systemd_journal.systemd_session",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_owner_uid,
          { "Systemd owner UID", "systemd_journal.systemd_owner_uid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_selinux_context,
          { "SELinux context", "systemd_journal.selinux_context",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_source_realtime_timestamp,
          { "Source realtime timestamp", "systemd_journal.source_realtime_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_boot_id,
          { "Boot ID", "systemd_journal.boot_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_machine_id,
          { "Machine ID", "systemd_journal.machine_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_invocation_id,
          { "Systemd invocation ID", "systemd_journal.systemd_invocation_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_hostname,
          { "Hostname", "systemd_journal.hostname",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_transport,
          { "Transport", "systemd_journal.transport",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_stream_id,
          { "Stream ID", "systemd_journal.stream_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_line_break,
          { "Line break", "systemd_journal.line_break",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_kernel_device,
          { "Kernel device", "systemd_journal.kernel_device",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_kernel_subsystem,
          { "Kernel subsystem", "systemd_journal.kernel_subsystem",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_udev_sysname,
          { "Device tree name", "systemd_journal.udev_sysname",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_udev_devnode,
          { "Device tree node", "systemd_journal.udev_devnode",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_udev_devlink,
          { "Device tree symlink", "systemd_journal.udev_devlink",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_coredump_unit,
          { "Coredump unit", "systemd_journal.coredump_unit",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_coredump_user_unit,
          { "Coredump user unit", "systemd_journal.coredump_user_unit",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_pid,
          { "Object PID", "systemd_journal.object_pid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_uid,
          { "Object UID", "systemd_journal.object_uid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_gid,
          { "Object GID", "systemd_journal.object_gid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_comm,
          { "Object command name", "systemd_journal.object_comm",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_exe,
          { "Object executable path", "systemd_journal.object_exe",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_cmdline,
          { "Object command line", "systemd_journal.object_cmdline",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_audit_session,
          { "Object audit session", "systemd_journal.object_audit_session",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_audit_loginuid,
          { "Object audit login UID", "systemd_journal.object_audit_loginuid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_cap_effective,
          { "Object effective capability", "systemd_journal.object_cap_effective",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_selinux_context,
          { "Object SELinux context", "systemd_journal.object_selinux_context",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_cgroup,
          { "Object systemd cgroup", "systemd_journal.object_systemd_cgroup",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_session,
          { "Object systemd session", "systemd_journal.object_systemd_session",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_owner_uid,
          { "Object systemd owner UID", "systemd_journal.object_systemd_owner_uid",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_unit,
          { "Object systemd unit", "systemd_journal.object_systemd_unit",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_user_unit,
          { "Object systemd user unit", "systemd_journal.object_systemd_user_unit",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_slice,
          { "Object systemd slice", "systemd_journal.object_systemd_slice",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_user_slice,
          { "Object systemd user slice", "systemd_journal.object_systemd_user_slice",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_object_systemd_invocation_id,
          { "Object systemd invocation ID", "systemd_journal.object_systemd_invocation_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_cursor,
          { "Cursor", "systemd_journal.cursor",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_realtime_timestamp,
          { "Realtime Timestamp", "systemd_journal.realtime_timestamp",
            FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_monotonic_timestamp,
          { "Monotonic Timestamp", "systemd_journal.monotonic_timestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_journal_name,
          { "Journal name", "systemd_journal.journal_name",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_journal_path,
          { "Journal path", "systemd_journal.journal_path",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_current_use,
          { "Current use", "systemd_journal.current_use",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_current_use_pretty,
          { "Human readable current use", "systemd_journal.current_use_pretty",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_max_use,
          { "Max use", "systemd_journal.max_use",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_max_use_pretty,
          { "Human readable max use", "systemd_journal.max_use_pretty",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_disk_keep_free,
          { "Disk keep free", "systemd_journal.disk_keep_free",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_disk_keep_free_pretty,
          { "Human readable disk keep free", "systemd_journal.disk_keep_free_pretty",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_disk_available,
          { "Disk available", "systemd_journal.disk_available",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_disk_available_pretty,
          { "Human readable disk available", "systemd_journal.disk_available_pretty",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_limit,
          { "Limit", "systemd_journal.limit",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_limit_pretty,
          { "Human readable limit", "systemd_journal.limit_pretty",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_available,
          { "Available", "systemd_journal.available",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_available_pretty,
          { "Human readable available", "systemd_journal.available_pretty",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_result,
          { "Result", "systemd_journal.result",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_source_monotonic_timestamp,
          { "Source monotonic timestamp", "systemd_journal.source_monotonic_timestamp",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_type,
          { "Audit type", "systemd_journal.audit_type",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_id,
          { "Audit ID", "systemd_journal.audit_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_field_apparmor,
          { "Audit field AppArmor", "systemd_journal.audit_field_apparmor",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_field_operation,
          { "Audit field operation", "systemd_journal.audit_field_operation",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_field_profile,
          { "Audit field profile", "systemd_journal.audit_field_profile",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_audit_field_name,
          { "Audit field name", "systemd_journal.audit_field_name",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_seat_id,
          { "Seat ID", "systemd_journal.seat_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_kernel_usec,
          { "Kernel microseconds", "systemd_journal.kernel_usec",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_userspace_usec,
          { "Userspace microseconds", "systemd_journal.userspace_usec",
            FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_session_id,
          { "Session ID", "systemd_journal.session_id",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_user_id,
          { "User ID", "systemd_journal.user_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_leader,
          { "Leader", "systemd_journal.leader",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_job_type,
          { "Job type", "systemd_journal.job_type",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_job_result,
          { "Job result", "systemd_journal.job_result",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_user_invocation_id,
          { "User invocation ID", "systemd_journal.user_invocation_id",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_systemd_user_slice,
          { "Systemd user slice", "systemd_journal.systemd_user_slice",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },

        { &hf_sj_binary_data_len,
          { "Binary data length", "systemd_journal.binary_data_len",
            FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_unknown_field,
          { "Unknown field", "systemd_journal.field",
            FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_unknown_field_name,
          { "Field name", "systemd_journal.field.name",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_unknown_field_value,
          { "Field value", "systemd_journal.field.value",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_unknown_field_data,
          { "Field data", "systemd_journal.field.data",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_sj_unhandled_field_type,
          { "Field data", "systemd_journal.unhandled_field_type",
            FT_STRING, STR_UNICODE, NULL, 0x0, NULL, HFILL }
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_systemd_journal_entry,
        &ett_systemd_binary_data,
        &ett_systemd_unknown_field
    };

    /* Setup protocol expert items */
    static ei_register_info ei[] = {
        { &ei_unhandled_field_type,
          { "systemd_journal.unhandled_field_type", PI_UNDECODED, PI_ERROR,
            "Unhandled field type", EXPFILL }
        },
        { &ei_nonbinary_field,
          { "systemd_journal.nonbinary_field", PI_UNDECODED, PI_WARN,
            "Field shouldn't be binary", EXPFILL }
        },
        { &ei_undecoded_field,
          { "systemd_journal.undecoded_field", PI_UNDECODED, PI_WARN,
            "Unable to decode field", EXPFILL }
        }
    };

    /* Register the protocol name and description */
    proto_systemd_journal = proto_register_protocol(PNAME, PSNAME, PFNAME);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_systemd_journal, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Required function calls to register expert items */
    expert_systemd_journal = expert_register_protocol(proto_systemd_journal);
    expert_register_field_array(expert_systemd_journal, ei, array_length(ei));

    init_jf_to_hf_map();
}

#define BLOCK_TYPE_SYSTEMD_JOURNAL 0x0000009
void
proto_reg_handoff_systemd_journal(void)
{
    static dissector_handle_t sje_handle = NULL;

    if (!sje_handle) {
        sje_handle = create_dissector_handle(dissect_systemd_journal_line_entry,
                proto_systemd_journal);
    }

    dissector_add_uint("wtap_fts_rec", WTAP_FILE_TYPE_SUBTYPE_SYSTEMD_JOURNAL, sje_handle);
    dissector_add_uint("pcapng.block_type", BLOCK_TYPE_SYSTEMD_JOURNAL, sje_handle);
    // It's possible to ship journal entries over HTTP/HTTPS using
    // systemd-journal-remote. Dissecting them on the wire isn't very
    // useful since it's easy to end up with a packet containing a
    // single, huge reassembled journal with many entries.
    dissector_add_string("media_type", "application/vnd.fdo.journal", sje_handle);
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
