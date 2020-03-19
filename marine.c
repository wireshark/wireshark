/* marine.c
 *
 * API for applying filters and parsing packets without filesystem interaction.
 * by Tom Legkov <tom.legkov@outlook.com>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#ifdef HAVE_GETOPT_H

#include <getopt.h>

#endif

#include <errno.h>

#ifdef _WIN32
# include <winsock2.h>
#endif

#ifndef _WIN32

#include <signal.h>

#endif

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/socket.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/please_report_bug.h>
#include <cli_main.h>
#include <version_info.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>

#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif

#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/decode_as.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>

#ifdef HAVE_LIBPCAP

#include "ui/capture_ui_utils.h"

#endif

#include "ui/taps.h"
#include "ui/util.h"
#include "ui/ws_ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/filter_files.h"
#include "ui/cli/tshark-tap.h"
#include "ui/cli/tap-exportobject.h"
#include "ui/tap_export_pdu.h"
#include "ui/dissect_opts.h"
#include "ui/failure_message.h"

#if defined(HAVE_LIBSMI)
#include "epan/oids.h"
#endif

#include "epan/maxmind_db.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/srt_table.h>
#include <epan/rtd_table.h>
#include <epan/ex-opt.h>
#include <epan/exported_pdu.h>
#include <epan/secrets.h>

#include "capture_opts.h"

#include "caputils/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP

#include "caputils/capture_ifinfo.h"

#ifdef _WIN32
#include "caputils/capture-wpcap.h"
#endif /* _WIN32 */

#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>
#include <ui/capture_info.h>

#endif /* HAVE_LIBPCAP */

#include "log.h"
#include <epan/funnel.h>

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/json_dumper.h>

#include "extcap.h"

#ifdef HAVE_PLUGINS

#include <wsutil/plugins.h>

#endif

#include <wiretap/wtap-int.h>
#include <wiretap/wtap.h>
#include "epan/print.h"

/* Exit codes */
#define INVALID_OPTION 1
#define INVALID_INTERFACE 2
#define INVALID_FILE 2
#define INVALID_FILTER 2
#define INVALID_EXPORT 2
#define INVALID_CAPABILITY 2
#define INVALID_TAP 2
#define INVALID_DATA_LINK 2
#define INVALID_TIMESTAMP_TYPE 2
#define INVALID_CAPTURE 2
#define INIT_FAILED 2

#define LONGOPT_EXPORT_OBJECTS          LONGOPT_BASE_APPLICATION+1
#define LONGOPT_COLOR                   LONGOPT_BASE_APPLICATION+2
#define LONGOPT_NO_DUPLICATE_KEYS       LONGOPT_BASE_APPLICATION+3
#define LONGOPT_ELASTIC_MAPPING_FILTER  LONGOPT_BASE_APPLICATION+4

#if 0
#define tshark_debug(...) g_warning(__VA_ARGS__)
#else
#define tshark_debug(...)
#endif

capture_file cfile;

static guint32 cum_bytes;
static frame_data ref_frame;
static frame_data prev_dis_frame;
static frame_data prev_cap_frame;

static guint32 epan_auto_reset_count = 0;
static gboolean epan_auto_reset = FALSE;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
    WRITE_TEXT,   /* summary or detail text */
    WRITE_XML,    /* PDML or PSML */
    WRITE_FIELDS, /* User defined list of fields */
    WRITE_JSON,   /* JSON */
    WRITE_JSON_RAW,   /* JSON only raw hex */
    WRITE_EK      /* JSON bulk insert to Elasticsearch */
    /* Add CSV and the like here */
} output_action_e;

struct _output_fields { // Required for in-place implementation of static methods
    gboolean print_bom;
    gboolean print_header;
    gchar separator;
    gchar occurrence;
    gchar aggregator;
    GPtrArray *fields;
    GHashTable *field_indicies;
    GPtrArray **field_values;
    gchar quote;
    gboolean includes_col_fields;
};

typedef struct { // Required for in-place implementation of static methods
    output_fields_t *fields;
    epan_dissect_t *edt;
} write_field_data_t;

typedef struct {
    int has_bpf;
    struct bpf_program fcode;
    dfilter_t *dfcode;
    output_fields_t *output_fields;
} packet_filter;

typedef struct {
    char *output;
    int result;
} marine_result;

static GHashTable *packet_filters;
static int *packet_filter_keys[4096];
static gboolean prefs_loaded = FALSE;


static void reset_epan_mem(capture_file *cf, epan_dissect_t *edt, gboolean tree, gboolean visual);


static void format_field_values(output_fields_t *fields, gpointer field_index, gchar *value) {
    guint indx;
    GPtrArray *fv_p;

    if (NULL == value)
        return;

    /* Unwrap change made to disambiguiate zero / null */
    indx = GPOINTER_TO_UINT(field_index) - 1;

    if (fields->field_values[indx] == NULL) {
        fields->field_values[indx] = g_ptr_array_new();
    }

    /* Essentially: fieldvalues[indx] is a 'GPtrArray *' with each array entry */
    /*  pointing to a string which is (part of) the final output string.       */

    fv_p = fields->field_values[indx];

    switch (fields->occurrence) {
        case 'f':
            /* print the value of only the first occurrence of the field */
            if (g_ptr_array_len(fv_p) != 0) {
                /*
                 * This isn't the first occurrence, so the value won't be used;
                 * free it.
                 */
                g_free(value);
                return;
            }
            break;
        case 'l':
            /* print the value of only the last occurrence of the field */
            if (g_ptr_array_len(fv_p) != 0) {
                /*
                 * This isn't the first occurrence, so there's already a
                 * value in the array, which won't be used; free the
                 * first (only) element in the array, and then remove
                 * it - this value will replace it.
                 */
                g_free(g_ptr_array_index(fv_p, 0));
                g_ptr_array_set_size(fv_p, 0);
            }
            break;
        case 'a':
            /* print the value of all accurrences of the field */
            if (g_ptr_array_len(fv_p) != 0) {
                /*
                 * This isn't the first occurrence. so add the "aggregator"
                 * character as a separator between the previous element
                 * and this element.
                 */
                g_ptr_array_add(fv_p, (gpointer) g_strdup_printf("%c", fields->aggregator));
            }
            break;
        default:
            g_assert_not_reached();
            break;
    }

    g_ptr_array_add(fv_p, (gpointer) value);
}

static void proto_tree_get_node_field_values(proto_node *node, gpointer data) {
    write_field_data_t *call_data;
    field_info *fi;
    gpointer field_index;

    call_data = (write_field_data_t *) data;
    fi = PNODE_FINFO(node);

    /* dissection with an invisible proto tree? */
    g_assert(fi);

    field_index = g_hash_table_lookup(call_data->fields->field_indicies, fi->hfinfo->abbrev);
    if (NULL != field_index) {
        format_field_values(call_data->fields, field_index,
                            get_node_field_value(fi, call_data->edt) /* g_ alloc'd string */
        );
    }

    /* Recurse here. */
    if (node->first_child != NULL) {
        proto_tree_children_foreach(node, proto_tree_get_node_field_values,
                                    call_data);
    }
}

static char *
marine_write_specified_fields(packet_filter *filter, epan_dissect_t *edt, char *output) {
    gsize i;
    output_fields_t *fields = filter->output_fields;
    write_field_data_t data;

    data.fields = fields;
    data.edt = edt;

    if (NULL == fields->field_indicies) {
        /* Prepare a lookup table from string abbreviation for field to its index. */
        fields->field_indicies = g_hash_table_new(g_str_hash, g_str_equal);

        i = 0;
        while (i < fields->fields->len) {
            gchar *field = (gchar *) g_ptr_array_index(fields->fields, i);
            /* Store field indicies +1 so that zero is not a valid value,
             * and can be distinguished from NULL as a pointer.
             */
            ++i;
            g_hash_table_insert(fields->field_indicies, field, GUINT_TO_POINTER(i));
        }
    }

    /* Array buffer to store values for this packet              */
    /*  Allocate an array for the 'GPtrarray *' the first time   */
    /*   ths function is invoked for a file;                     */
    /*  Any and all 'GPtrArray *' are freed (after use) each     */
    /*   time (each packet) this function is invoked for a flle. */
    /* XXX: ToDo: use packet-scope'd memory & (if/when implemented) wmem ptr_array */
    if (NULL == fields->field_values)
        fields->field_values = g_new0(GPtrArray*, fields->fields->len);  /* free'd in output_fields_free() */

    proto_tree_children_foreach(edt->tree, proto_tree_get_node_field_values, &data);


    //char *output = (char *) g_malloc0(4096); // todo this can overflow
    int counter = 0;
    for (i = 0; i < fields->fields->len; ++i) {
        if (0 != i) {
            output[counter++] = fields->separator;
        }
        if (NULL != fields->field_values[i]) {
            GPtrArray *fv_p;
            gchar *str;
            gsize j;
            fv_p = fields->field_values[i];
            if (fields->quote != '\0') {
                output[counter++] = fields->quote;
            }

            /* Output the array of (partial) field values */
            for (j = 0; j < g_ptr_array_len(fv_p); j++) {
                str = (gchar *) g_ptr_array_index(fv_p, j);
                for (char *p = str; *p != '\0'; p++) {
                    output[counter++] = *p;
                }
                g_free(str);
            }
            if (fields->quote != '\0') {
                output[counter++] = fields->quote;
            }
            g_ptr_array_free(fv_p, TRUE);  /* get ready for the next packet */
            fields->field_values[i] = NULL;
        }
    }

    output[counter] = '\0';
    return output;
}

void
marine_frame_data_init(frame_data *fdata, guint32 num, int len) {
    fdata->pfd = NULL;
    fdata->num = num;
    fdata->file_off = 0;
    fdata->subnum = 0;
    fdata->passed_dfilter = 0;
    fdata->dependent_of_displayed = 0;
    fdata->encoding = PACKET_CHAR_ENC_CHAR_ASCII;
    fdata->visited = 0;
    fdata->marked = 0;
    fdata->ref_time = 0;
    fdata->ignored = 0;
    fdata->has_ts = len;
    fdata->pkt_len = len;
    fdata->cum_bytes = len;
    fdata->cap_len = len;
    fdata->tsprec = 6;
    //fdata->abs_ts = NULL;
    fdata->has_phdr_comment = 0;
    fdata->has_user_comment = 0;
    fdata->need_colorize = 0;
    fdata->color_filter = NULL;
    fdata->shift_offset.secs = 0;
    fdata->shift_offset.nsecs = 0;
    fdata->frame_ref_num = 0;
    fdata->prev_dis_num = 0;
}


static gboolean
marine_process_packet(capture_file *cf, epan_dissect_t *edt, packet_filter *filter, Buffer *buf, wtap_rec *rec,
                      int len, char *output) {
    frame_data fdata;
    column_info *cinfo;
    gboolean passed;

    /* Count this packet. */
    cf->count++;

    /* If we're not running a display filter and we're not printing any
       packet information, we don't need to do a dissection. This means
       that all packets can be marked as 'passed'. */
    passed = TRUE;
    marine_frame_data_init(&fdata, cf->count, len);

    /* If we're going to print packet information, or we're going to
       run a read filter, or we're going to process taps, set up to
       do a dissection and do so.  (This is the one and only pass
       over the packets, so, if we'll be printing packet information
       or running taps, we'll be doing it here.) */
    if (edt) {
        /* If we're running a filter, prime the epan_dissect_t with that
           filter. */
        if (filter->dfcode)
            epan_dissect_prime_with_dfilter(edt, filter->dfcode);

        /* This is the first and only pass, so prime the epan_dissect_t
           with the hfids postdissectors want on the first pass. */
        prime_epan_dissect_with_postdissector_wanted_hfids(edt);

        col_custom_prime_edt(edt, &cf->cinfo);
        cinfo = NULL;

        //frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
        //                              &cf->provider.ref, cf->provider.prev_dis);
        if (cf->provider.ref == &fdata) {
            ref_frame = fdata;
            cf->provider.ref = &ref_frame;
        }

        epan_dissect_run_with_taps(edt, cf->cd_t, rec,
                                   frame_tvbuff_new_buffer(&cf->provider, &fdata, buf),
                                   &fdata, cinfo);

        /* Run the filter if we have it. */
        if (filter->dfcode)
            passed = dfilter_apply_edt(filter->dfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(&fdata, &cum_bytes);
        /* Process this packet. */
        if (filter->output_fields != NULL) {
            marine_write_specified_fields(filter, edt, output);
        }

        /* this must be set after print_packet() [bug #8160] */
        prev_dis_frame = fdata;
        cf->provider.prev_dis = &prev_dis_frame;
    }

    prev_cap_frame = fdata;
    cf->provider.prev_cap = &prev_cap_frame;

    if (edt) {
        epan_dissect_reset(edt);
        frame_data_destroy(&fdata);
    }
    return passed;
}

static int
marine_inner_dissect_packet(capture_file *cf, packet_filter *filter, const unsigned char *data, int len, char *output) {
    wtap_rec rec;
    Buffer buf;
    epan_dissect_t *edt = NULL;

    if (filter->has_bpf) {
        struct pcap_pkthdr *hdr = (struct pcap_pkthdr*) malloc(sizeof(struct pcap_pkthdr));
        hdr->len = len;
        hdr->caplen = len;
        if (!pcap_offline_filter(&filter->fcode, hdr, data)) {
            free(hdr);
            return 0;
        }
        free(hdr);
    }

    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514); // TODO support larger packets?

    // Copy the data into an epan buffer
    memcpy(ws_buffer_start_ptr(&buf), data, len);

    // Fake the rec structure for internal dissection
    (&rec)->rec_type = REC_TYPE_PACKET;
    (&rec)->presence_flags = WTAP_HAS_CAP_LEN;
    (&rec)->rec_header.packet_header.caplen = len;
    (&rec)->rec_header.packet_header.len = len;
    (&rec)->rec_header.packet_header.pkt_encap = 1;
    (&rec)->rec_header.ft_specific_header.record_len = len;
    (&rec)->rec_header.ft_specific_header.record_type = len;
    (&rec)->rec_header.syscall_header.record_type = len;
    (&rec)->rec_header.syscall_header.byte_order = len;


    /* The protocol tree will be "visible", i.e., printed, only if we're
       printing packet details, which is true if we're printing stuff
       ("print_packet_info" is true) and we're in verbose mode
       ("packet_details" is true). */
    edt = epan_dissect_new(cf->epan, TRUE, TRUE);

    /*
     * Force synchronous resolution of IP addresses; we're doing only
     * one pass, so we can't do it in the background and fix up past
     * dissections.
     */
    set_resolution_synchrony(TRUE); // TODO can we remove c-ares?

    reset_epan_mem(cf, edt, 1, 0); // TODO configure autoreset / reset count

    int passed = marine_process_packet(cf, edt, filter, &buf, &rec, len, output);

    if (edt)
        epan_dissect_free(edt);

    ws_buffer_free(&buf);
    wtap_rec_cleanup(&rec);
    return passed;
}

marine_result* marine_dissect_packet(int filter_id, unsigned char *data, int len) {
    marine_result* result = (marine_result *) malloc(sizeof(marine_result));
    result->output = NULL;

    if (!packet_filter_keys[filter_id]) {
        result->result = -1; // TODO export to const
    } else {
        int *key = packet_filter_keys[filter_id];
        packet_filter *filter = (packet_filter *) g_hash_table_lookup(packet_filters, key);
        char *output = filter->output_fields == NULL ? NULL : (char *)g_malloc0(4096); // TODO export to const
        int passed = marine_inner_dissect_packet(&cfile, filter, data, len, output);
        if (passed) {
            result->result = 1;
            result->output = output;
        } else {
            if (output != NULL) {
                free(output);
            }
            result->result = 0;
        }
    }
    return result;
}

int marine_add_filter(char *bpf, char *dfilter, char **fields, int fields_len, char **err_msg) {
    // TODO make the error codes consts
    struct bpf_program fcode;
    dfilter_t *dfcode = NULL;
    output_fields_t *packet_output_fields = NULL;
    int has_bpf = FALSE;

    if (bpf != NULL) {
        has_bpf = TRUE;
        pcap_t *pc;
        pc = pcap_open_dead(DLT_EN10MB, MIN_PACKET_SIZE);
        if (pc != NULL) {
            if (pcap_compile(pc, &fcode, bpf, 0, 0) == -1) {
                *err_msg = strdup("Failed compiling the BPF");
                pcap_close(pc);
                return -1;
            }
            pcap_close(pc);
        }
    }

    if (dfilter != NULL) {
        if (!dfilter_compile(dfilter, &dfcode, err_msg)) {
            return -2;
        }
    }

    if (fields_len > 0) {
        packet_output_fields = output_fields_new();
        packet_output_fields->separator = '\t'; // TODO make const/configurable
        packet_output_fields->quote = '"';

        for (int i = 0; i < fields_len; i++) {
            output_fields_add(packet_output_fields, fields[i]);
        }

        GSList *it = NULL;
        GSList *invalid_fields = output_fields_valid(packet_output_fields);
        if (invalid_fields != NULL) {
            *err_msg = (char *) g_malloc0(1024);
            strcat(*err_msg, "Some fields aren't valid:\n");
            for (it = invalid_fields; it != NULL; it = g_slist_next(it)) {
                strcat(*err_msg, "\t");
                strcat(*err_msg, (gchar *) it->data); // TODO: with long field names, this allows buffer overflow
            }
            output_fields_free(packet_output_fields);
            g_slist_free(invalid_fields);
            return -3;
        }
    }

    int size = g_hash_table_size(packet_filters);
    int *key = g_new0 (gint, 1);
    *key = size;
    packet_filter *filter = (packet_filter *) malloc(sizeof(packet_filter));
    filter->has_bpf = has_bpf;
    filter->fcode = fcode;
    filter->dfcode = dfcode;
    filter->output_fields = packet_output_fields;
    g_hash_table_insert(packet_filters, key, filter);
    packet_filter_keys[size] = key;
    return size;
}

wtap *
marine_wtap_open_offline(void) {
    wtap *wth;
    wtap_block_t shb;

    wth = (wtap *) g_malloc0(sizeof(struct wtap));
    wth->ispipe = FALSE;
    wth->file_encap = 1;
    wth->subtype_sequential_close = NULL;
    wth->subtype_close = NULL;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->priv = NULL;
    wth->wslua_data = NULL;
    wth->shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
    shb = wtap_block_create(WTAP_BLOCK_NG_SECTION);
    if (shb)
        g_array_append_val(wth->shb_hdrs, shb);

    wth->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

    wtap_block_t descr = wtap_block_create(WTAP_BLOCK_IF_DESCR);
    wtapng_if_descr_mandatory_t *descr_mand = (wtapng_if_descr_mandatory_t *) wtap_block_get_mandatory_data(descr);

    descr_mand->wtap_encap = wth->file_encap;
    if (wth->file_type_subtype == WTAP_FILE_TYPE_SUBTYPE_PCAP_NSEC) {
        descr_mand->time_units_per_second = 1000000000; // nanosecond resolution
        wtap_block_add_uint8_option(descr, OPT_IDB_TSRESOL, 9);
        descr_mand->tsprecision = WTAP_TSPREC_NSEC;
    } else {
        descr_mand->time_units_per_second = 1000000; // default microsecond resolution
        descr_mand->tsprecision = WTAP_TSPREC_USEC;
    }
    descr_mand->snap_len = wth->snapshot_length;

    descr_mand->num_stat_entries = 0;
    descr_mand->interface_statistics = NULL;
    g_array_append_val(wth->interface_data, descr);

    return wth;
}

static const nstime_t *
marine_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num) {
    if (prov->ref && prov->ref->num == frame_num)
        return &prov->ref->abs_ts;

    if (prov->prev_dis && prov->prev_dis->num == frame_num)
        return &prov->prev_dis->abs_ts;

    if (prov->prev_cap && prov->prev_cap->num == frame_num)
        return &prov->prev_cap->abs_ts;

    if (prov->frames) {
        frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

        return (fd) ? &fd->abs_ts : NULL;
    }

    return NULL;
}

static epan_t *
marine_epan_new(capture_file *cf) {
    static const struct packet_provider_funcs funcs = {
            marine_get_frame_ts,
            cap_file_provider_get_interface_name,
            cap_file_provider_get_interface_description,
            NULL,
    };

    return epan_new(&cf->provider, &funcs);
}

void
marine_cf_open(capture_file *cf) {
    wtap *wth;

    wth = marine_wtap_open_offline();

    cf->provider.wth = wth;
    cf->f_datalen = 0;
    cf->is_tempfile = FALSE;
    cf->unsaved_changes = FALSE;

    cf->cd_t = 1; // TODO support other encaps
    cf->open_type = 0;
    cf->count = 0;
    cf->drops_known = FALSE;
    cf->drops = 0;
    cf->snap = wtap_snapshot_length(cf->provider.wth);
    nstime_set_zero(&cf->elapsed_time);
    cf->provider.ref = NULL;
    cf->provider.prev_dis = NULL;
    cf->provider.prev_cap = NULL;
    epan_free(cf->epan);
    cf->epan = marine_epan_new(cf);

    wtap_set_cb_new_ipv4(cf->provider.wth, add_ipv4_name);
    wtap_set_cb_new_ipv6(cf->provider.wth, (wtap_new_ipv6_callback_t) add_ipv6_name);
    wtap_set_cb_new_secrets(cf->provider.wth, secrets_wtap_callback);
}

int init_marine(void) {
    // TODO: look at epan_auto_reset
    e_prefs *prefs_p;

    /* Set the C-language locale to the native environment. */
    setlocale(LC_ALL, "");

    /*
     * Get credential information for later use, and drop privileges
     * before doing anything else.
     * Let the user know if anything happened.
     */
    init_process_policies();
    relinquish_special_privs_perm();

    wtap_init(TRUE);

    /* Register all dissectors */
    if (!epan_init(NULL, NULL, TRUE)) {
        return 1;
    }

    /* we register the plugin taps before the other taps because
       stats_tree taps plugins will be registered as tap listeners
       by stats_tree_stat.c and need to registered before that */
#ifdef HAVE_PLUGINS
    register_all_plugin_tap_listeners();
#endif
    extcap_register_preferences();
    /* Register all tap listeners. */
    for (tap_reg_t *t = tap_reg_listener; t->cb_func != NULL; t++) {
        t->cb_func();
    }

    /* Load libwireshark settings from the current profile. */
    prefs_p = epan_load_settings();
    prefs_loaded = TRUE;

    read_filter_list(CFILTER_LIST);

    cap_file_init(&cfile);

    /* Notify all registered modules that have had any of their preferences
       changed either from one of the preferences file or from the command
       line that their preferences have changed. */
    prefs_apply_all();

    /* We can also enable specified taps for export object */
    start_exportobjects();

    if (!setup_enabled_and_disabled_protocols()) {
        return 2;
    }

    /* Build the column format array */
    build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

    marine_cf_open(&cfile);

    packet_filters = g_hash_table_new(g_int_hash, g_int_equal);
    return 0;
}

void destroy_marine(void) {
    for (unsigned int i = 0; i < g_hash_table_size(packet_filters); i++) {
        int *key = packet_filter_keys[i];
        if (!key) {
            break;
        }
        packet_filter *filter = (packet_filter *) g_hash_table_lookup(packet_filters, key);
        if (filter->has_bpf) {
            pcap_freecode(&filter->fcode);
        }
        if (filter->dfcode) {
            dfilter_free(filter->dfcode);
        }
        if (filter->output_fields) {
            output_fields_free(filter->output_fields);
        }
    }

    reset_tap_listeners();
    funnel_dump_all_text_windows();
    epan_free(cfile.epan);
    epan_cleanup();
    extcap_cleanup();

    col_cleanup(&cfile.cinfo);
    free_filter_lists();
    wtap_cleanup();
    free_progdirs();
    g_hash_table_destroy(packet_filters);
}

void marine_free(marine_result *ptr) {
    if (ptr != NULL) {
        if (ptr->output != NULL) {
            free(ptr->output);
        }
        free(ptr);
    }
}

static void reset_epan_mem(capture_file *cf, epan_dissect_t *edt, gboolean tree, gboolean visual) {
    if (!epan_auto_reset || (cf->count < epan_auto_reset_count))
        return;

    fprintf(stderr, "resetting session.\n");

    epan_dissect_cleanup(edt);
    epan_free(cf->epan);

    cf->epan = marine_epan_new(cf);
    epan_dissect_init(edt, cf->epan, tree, visual);
    cf->count = 0;
}
