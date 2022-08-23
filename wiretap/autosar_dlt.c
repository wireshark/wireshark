/* autosar_dlt.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for DLT file format as defined by AUTOSAR et. al.
 * Copyright (c) 2022-2022 by Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Sources for specification:
 * https://www.autosar.org/fileadmin/user_upload/standards/classic/21-11/AUTOSAR_SWS_DiagnosticLogAndTrace.pdf
 * https://www.autosar.org/fileadmin/user_upload/standards/foundation/21-11/AUTOSAR_PRS_LogAndTraceProtocol.pdf
 * https://github.com/COVESA/dlt-viewer
 */

#include <config.h>
#include <errno.h>
#include "autosar_dlt.h"

#include "file_wrappers.h"
#include "wtap-int.h"

static const guint8 dlt_magic[] = { 'D', 'L', 'T', 0x01 };

static int autosar_dlt_file_type_subtype = -1;


void register_autosar_dlt(void);
static gboolean autosar_dlt_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info, gint64 *data_offset);
static gboolean autosar_dlt_seek_read(wtap *wth, gint64 seek_off, wtap_rec* rec, Buffer *buf, int *err, gchar **err_info);
static void autosar_dlt_close(wtap *wth);


typedef struct autosar_dlt_blockheader {
    guint8  magic[4];
    guint32 timestamp_s;
    guint32 timestamp_us;
    guint8  ecu_id[4];
} autosar_dlt_blockheader_t;

typedef struct autosar_dlt_itemheader {
    guint8  header_type;
    guint8  counter;
    guint16 length;
} autosar_dlt_itemheader_t;


typedef struct autosar_dlt_data {
    GHashTable *ecu_to_iface_ht;
    guint32     next_interface_id;
} autosar_dlt_t;

typedef struct autosar_dlt_params {
    wtap           *wth;
    wtap_rec       *rec;
    Buffer         *buf;
    FILE_T          fh;

    autosar_dlt_t  *dlt_data;
} autosar_dlt_params_t;

static gint
autosar_dlt_calc_key(guint8 ecu[4]) {
    return (gint)(ecu[0] << 24 | ecu[1] << 16 | ecu[2] << 8 | ecu[3]);
}

static guint32
autosar_dlt_add_interface(autosar_dlt_params_t *params, guint8 ecu[4]) {
    wtap_block_t int_data = wtap_block_create(WTAP_BLOCK_IF_ID_AND_INFO);
    wtapng_if_descr_mandatory_t *if_descr_mand = (wtapng_if_descr_mandatory_t*)wtap_block_get_mandatory_data(int_data);

    if_descr_mand->wtap_encap = WTAP_ENCAP_AUTOSAR_DLT;
    wtap_block_add_string_option(int_data, OPT_IDB_NAME, (gchar *)ecu, 4);
    if_descr_mand->time_units_per_second = 1000 * 1000 * 1000;
    if_descr_mand->tsprecision = WTAP_TSPREC_NSEC;
    wtap_block_add_uint8_option(int_data, OPT_IDB_TSRESOL, 9);
    if_descr_mand->snap_len = WTAP_MAX_PACKET_SIZE_STANDARD;
    if_descr_mand->num_stat_entries = 0;
    if_descr_mand->interface_statistics = NULL;
    wtap_add_idb(params->wth, int_data);

    if (params->wth->file_encap == WTAP_ENCAP_UNKNOWN) {
        params->wth->file_encap = if_descr_mand->wtap_encap;
    } else {
        if (params->wth->file_encap != if_descr_mand->wtap_encap) {
            params->wth->file_encap = WTAP_ENCAP_PER_PACKET;
        }
    }

    gint32 key = autosar_dlt_calc_key(ecu);
    guint32 iface_id = params->dlt_data->next_interface_id++;
    g_hash_table_insert(params->dlt_data->ecu_to_iface_ht, GINT_TO_POINTER(key), GUINT_TO_POINTER(iface_id));

    return iface_id;
}

static guint32
autosar_dlt_lookup_interface(autosar_dlt_params_t *params, guint8 ecu[4]) {
    gint32 key = autosar_dlt_calc_key(ecu);

    if (params->dlt_data->ecu_to_iface_ht == NULL) {
        return 0;
    }

    gpointer iface = NULL;
    gboolean found = g_hash_table_lookup_extended(params->dlt_data->ecu_to_iface_ht, GINT_TO_POINTER(key), NULL, &iface);

    if (found) {
        return GPOINTER_TO_UINT(iface);
    } else {
        return autosar_dlt_add_interface(params, ecu);
    }
}

static void
fix_endianness_autosar_dlt_blockheader(autosar_dlt_blockheader_t *header) {
    header->timestamp_s = GUINT32_FROM_LE(header->timestamp_s);
    header->timestamp_us = GUINT32_FROM_LE(header->timestamp_us);
}

static void
fix_endianness_autosar_dlt_itemheader(autosar_dlt_itemheader_t *header) {
    header->length = GUINT16_FROM_BE(header->length);
}

static gboolean
autosar_dlt_read_block(autosar_dlt_params_t *params, gint64 start_pos, int *err, gchar **err_info) {
    autosar_dlt_blockheader_t header;
    autosar_dlt_itemheader_t  item_header;

    while (1) {
        params->buf->first_free = params->buf->start;

        if (!wtap_read_bytes_or_eof(params->fh, &header, sizeof header, err, err_info)) {
            if (*err == WTAP_ERR_SHORT_READ) {
                *err = WTAP_ERR_BAD_FILE;
                g_free(*err_info);
                *err_info = ws_strdup_printf("AUTOSAR DLT: Capture file cut short! Cannot find storage header at pos 0x%" PRIx64 "!", start_pos);
            }
            return FALSE;
        }

        fix_endianness_autosar_dlt_blockheader(&header);

        if (memcmp(header.magic, dlt_magic, sizeof(dlt_magic))) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("AUTOSAR DLT: Bad capture file! Object magic is not DLT\\x01 at pos 0x%" PRIx64 "!", start_pos);
            return FALSE;
        }

        /* Set to the byte after the magic. */
        guint64 current_start_of_item = file_tell(params->fh) - sizeof header + 4;

        if (!wtap_read_bytes_or_eof(params->fh, &item_header, sizeof item_header, err, err_info)) {
            *err = WTAP_ERR_BAD_FILE;
            g_free(*err_info);
            *err_info = ws_strdup_printf("AUTOSAR DLT: Capture file cut short! Not enough bytes for item header at pos 0x%" PRIx64 "!", start_pos);
            return FALSE;
        }

        fix_endianness_autosar_dlt_itemheader(&item_header);

        if (file_seek(params->fh, current_start_of_item, SEEK_SET, err) < 0) {
            return FALSE;
        }

        ws_buffer_assure_space(params->buf, (gsize)(item_header.length + sizeof header));

        /* Creating AUTOSAR DLT Encapsulation Header:
         * guint32   time_s
         * guint32   time_us
         * guint8[4] ecuname
         * guint8[1] 0x00 (termination)
         * guint8[3] reserved
         */
        void *tmpbuf = g_malloc0(sizeof header);
        if (!wtap_read_bytes_or_eof(params->fh, tmpbuf, sizeof header - 4, err, err_info)) {
            /* this would have been caught before ...*/
            *err = WTAP_ERR_BAD_FILE;
            g_free(*err_info);
            *err_info = ws_strdup_printf("AUTOSAR DLT: Internal Error! Not enough bytes for storage header at pos 0x%" PRIx64 "!", start_pos);
            return FALSE;
        }
        ws_buffer_append(params->buf, tmpbuf, (gsize)(sizeof header));
        g_free(tmpbuf);

        tmpbuf = g_try_malloc0(item_header.length);
        if (tmpbuf == NULL) {
            *err = ENOMEM;  /* we assume we're out of memory */
            return FALSE;
        }

        if (!wtap_read_bytes_or_eof(params->fh, tmpbuf, item_header.length, err, err_info)) {
            *err = WTAP_ERR_BAD_FILE;
            g_free(*err_info);
            *err_info = ws_strdup_printf("AUTOSAR DLT: Capture file cut short! Not enough bytes for item at pos 0x%" PRIx64 "!", start_pos);
            return FALSE;
        }
        ws_buffer_append(params->buf, tmpbuf, (gsize)(item_header.length));
        g_free(tmpbuf);

        params->rec->rec_type = REC_TYPE_PACKET;
        params->rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
        params->rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN | WTAP_HAS_INTERFACE_ID;
        params->rec->tsprec = WTAP_TSPREC_USEC;
        params->rec->ts.secs = header.timestamp_s;
        params->rec->ts.nsecs = header.timestamp_us * 1000;

        params->rec->rec_header.packet_header.caplen = (guint32)(item_header.length + sizeof header);
        params->rec->rec_header.packet_header.len = (guint32)(item_header.length + sizeof header);
        params->rec->rec_header.packet_header.pkt_encap = WTAP_ENCAP_AUTOSAR_DLT;
        params->rec->rec_header.packet_header.interface_id = autosar_dlt_lookup_interface(params, header.ecu_id);

        return TRUE;
    }

    return FALSE;
}

static gboolean autosar_dlt_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info, gint64 *data_offset) {
    autosar_dlt_params_t dlt_tmp;

    dlt_tmp.wth = wth;
    dlt_tmp.fh = wth->fh;
    dlt_tmp.rec = rec;
    dlt_tmp.buf = buf;
    dlt_tmp.dlt_data = (autosar_dlt_t *)wth->priv;

    *data_offset = file_tell(wth->fh);

    if (!autosar_dlt_read_block(&dlt_tmp, *data_offset, err, err_info)) {
        ws_debug("couldn't read packet block (data_offset is %" PRId64 ")", *data_offset);
        return FALSE;
    }

    return TRUE;
}

static gboolean autosar_dlt_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info) {
    autosar_dlt_params_t dlt_tmp;

    dlt_tmp.wth = wth;
    dlt_tmp.fh = wth->random_fh;
    dlt_tmp.rec = rec;
    dlt_tmp.buf = buf;
    dlt_tmp.dlt_data = (autosar_dlt_t *)wth->priv;

    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    if (!autosar_dlt_read_block(&dlt_tmp, seek_off, err, err_info)) {
        ws_debug("couldn't read packet block (seek_off: %" PRId64 ") (err=%d).", seek_off, *err);
        return FALSE;
    }

    return TRUE;
}

static void autosar_dlt_close(wtap *wth) {
    autosar_dlt_t *dlt = (autosar_dlt_t *)wth->priv;

    if (dlt != NULL && dlt->ecu_to_iface_ht != NULL) {
        g_hash_table_destroy(dlt->ecu_to_iface_ht);
        dlt->ecu_to_iface_ht = NULL;
    }

    g_free(dlt);
    wth->priv = NULL;

    return;
}

wtap_open_return_val
autosar_dlt_open(wtap *wth, int *err, gchar **err_info) {
    guint8 magic[4];
    autosar_dlt_t *dlt;

    ws_debug("opening file");

    if (!wtap_read_bytes_or_eof(wth->fh, &magic, sizeof magic, err, err_info)) {
        ws_debug("wtap_read_bytes_or_eof() failed, err = %d.", *err);
        if (*err == 0 || *err == WTAP_ERR_SHORT_READ) {
            *err = 0;
            g_free(*err_info);
            *err_info = NULL;
            return WTAP_OPEN_NOT_MINE;
        }
        return WTAP_OPEN_ERROR;
    }

    if (memcmp(magic, dlt_magic, sizeof(dlt_magic))) {
        return WTAP_OPEN_NOT_MINE;
    }

    file_seek(wth->fh, 0, SEEK_SET, err);

    dlt = g_new(autosar_dlt_t, 1);
    dlt->ecu_to_iface_ht = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);
    dlt->next_interface_id = 0;

    wth->priv = (void *)dlt;
    wth->file_encap = WTAP_ENCAP_UNKNOWN;
    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_UNKNOWN;
    wth->subtype_read = autosar_dlt_read;
    wth->subtype_seek_read = autosar_dlt_seek_read;
    wth->subtype_close = autosar_dlt_close;
    wth->file_type_subtype = autosar_dlt_file_type_subtype;

    return WTAP_OPEN_MINE;
}

/* Options for interface blocks. */
static const struct supported_option_type interface_block_options_supported[] = {
    /* No comments, just an interface name. */
    { OPT_IDB_NAME, ONE_OPTION_SUPPORTED }
};

static const struct supported_block_type dlt_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED },
    { WTAP_BLOCK_IF_ID_AND_INFO, MULTIPLE_BLOCKS_SUPPORTED, OPTION_TYPES_SUPPORTED(interface_block_options_supported) },
};

static const struct file_type_subtype_info dlt_info = {
        "AUTOSAR DLT Logfile", "dlt", "dlt", NULL,
        FALSE, BLOCKS_SUPPORTED(dlt_blocks_supported),
        NULL, NULL, NULL
};

void register_autosar_dlt(void)
{
    autosar_dlt_file_type_subtype = wtap_register_file_type_subtype(&dlt_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("DLT", autosar_dlt_file_type_subtype);
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
