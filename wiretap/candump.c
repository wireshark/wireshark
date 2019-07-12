/* candump.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Support for candump log file format
 * Copyright (c) 2019 by Maksim Salau <maksim.salau@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>
#include <wtap-int.h>
#include <file_wrappers.h>
#include <epan/exported_pdu.h>
#include <wsutil/tempfile.h>
#include <wsutil/os_version_info.h>
#include <string.h>
#include <inttypes.h>
#include "candump.h"
#include "candump_priv.h"

static gboolean candump_read(wtap *wth, wtap_rec *rec, Buffer *buf,
                             int *err, gchar **err_info,
                             gint64 *data_offset);
static gboolean candump_seek_read(wtap *wth, gint64 seek_off,
                                  wtap_rec *rec, Buffer *buf,
                                  int *err, gchar **err_info);
static void candump_close(wtap *wth);

static gboolean
candump_add_packet(wtap_dumper *wdh, const msg_t *msg, int *err, char **err_info)
{
    static const char *can_proto_name    = "can-hostendian";
    static const char *canfd_proto_name  = "canfd";
    const char        *proto_name        = msg->is_fd ? canfd_proto_name : can_proto_name;
    guint              proto_name_length = (guint)strlen(proto_name) + 1;
    guint              header_length;
    guint              packet_length;
    guint              frame_length;

    guint8    buf[128];
    wtap_rec  rec;

    /* Adjust proto name length to be aligned on 4 byte boundary */
    proto_name_length += (proto_name_length % 4) ? (4 - (proto_name_length % 4)) : 0;

    header_length = 4 + proto_name_length + 4;
    frame_length  = msg->is_fd ? sizeof(canfd_frame_t) : sizeof(can_frame_t);
    packet_length = header_length + frame_length;

    memset(buf, 0, sizeof(buf));
    buf[1] = EXP_PDU_TAG_PROTO_NAME;
    buf[3] = proto_name_length;
    memcpy(buf + 4, proto_name, strlen(proto_name));

    if (msg->is_fd)
    {
        canfd_frame_t canfd_frame;

        memset(&canfd_frame, 0, sizeof(canfd_frame));
        canfd_frame.can_id = msg->id;
        canfd_frame.flags  = msg->flags;
        canfd_frame.len    = msg->data.length;
        memcpy(canfd_frame.data, msg->data.data, msg->data.length);

        memcpy(buf + header_length, (guint8 *)&canfd_frame, sizeof(canfd_frame));
    }
    else
    {
        can_frame_t can_frame;

        memset(&can_frame, 0, sizeof(can_frame));
        can_frame.can_id  = msg->id;
        can_frame.can_dlc = msg->data.length;
        memcpy(can_frame.data, msg->data.data, msg->data.length);

        memcpy(buf + header_length, (guint8 *)&can_frame, sizeof(can_frame));
    }

    memset(&rec, 0, sizeof(rec));
    rec.rec_type       = REC_TYPE_PACKET;
    rec.presence_flags = WTAP_HAS_TS;
    rec.ts             = msg->ts;
    rec.tsprec         = WTAP_TSPREC_USEC;

    rec.rec_header.packet_header.caplen = packet_length;
    rec.rec_header.packet_header.len    = packet_length;

    return wtap_dump(wdh, &rec, buf, err, err_info);
}

static gchar *
candump_dump(GSList *packets, int *err, char **err_info)
{
    gchar        *filename;
    int           import_file_fd;
    wtap_dumper  *wdh;
    GSList       *packet;

    /* pcapng defs */
    GArray                      *shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
    wtap_block_t                 shb_hdr;
    wtapng_iface_descriptions_t *idb_inf  = NULL;
    wtap_block_t                 int_data;
    wtapng_if_descr_mandatory_t *int_data_mand;
    GString                     *os_info_str;
    gsize                        opt_len;
    gchar                       *opt_str  = NULL;

    static const gchar *opt_comment = "File converted to Exported PDU format during opening";
    static const gchar *if_name     = "Fake IF";

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Creating a temporary file\n", G_STRFUNC);
#endif
    import_file_fd = create_tempfile(&filename, "Wireshark_PDU_candump_", NULL);

    /* Now open a file and dump to it */
    /* Create data for SHB */
    os_info_str = g_string_new("");
    get_os_version_info(os_info_str);

    shb_hdr = wtap_block_create(WTAP_BLOCK_NG_SECTION);
    /* options */
    wtap_block_add_string_option(shb_hdr, OPT_COMMENT, opt_comment,
                                 strlen(opt_comment));
    /*
     * UTF-8 string containing the name of the operating system used to create
     * this section.
     */
    opt_len = os_info_str->len;
    opt_str = g_string_free(os_info_str, FALSE);
    if (opt_str)
    {
        wtap_block_add_string_option(shb_hdr, OPT_SHB_OS, opt_str, opt_len);
        g_free(opt_str);
    }

    /*
     * UTF-8 string containing the name of the application used to create
     * this section. Avoid the precise version (get_appname_and_version) to
     * avoid wiretap rebuilds when only the version changes.
     */
    wtap_block_add_string_option_format(shb_hdr, OPT_SHB_USERAPPL, "Wireshark %s", VERSION);

    /* Add header to the array */
    g_array_append_val(shb_hdrs, shb_hdr);

    /* Create fake IDB info */
    idb_inf = g_new(wtapng_iface_descriptions_t, 1);
    idb_inf->interface_data = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));

    /* create the fake interface data */
    int_data                             = wtap_block_create(WTAP_BLOCK_IF_DESCR);
    int_data_mand                        = (wtapng_if_descr_mandatory_t *)wtap_block_get_mandatory_data(int_data);
    int_data_mand->wtap_encap            = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    int_data_mand->time_units_per_second = 1000000; /* default microsecond resolution */
    int_data_mand->snap_len              = WTAP_MAX_PACKET_SIZE_STANDARD;

    wtap_block_add_string_option(int_data, OPT_IDB_NAME, if_name, strlen(if_name));
    int_data_mand->num_stat_entries     = 0; /* Number of ISB:s */
    int_data_mand->interface_statistics = NULL;

    g_array_append_val(idb_inf->interface_data, int_data);

    const wtap_dump_params params = {
        .encap    = WTAP_ENCAP_WIRESHARK_UPPER_PDU,
        .snaplen  = WTAP_MAX_PACKET_SIZE_STANDARD,
        .shb_hdrs = shb_hdrs,
        .idb_inf  = idb_inf,
    };

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Opening the temporary file for writing\n", G_STRFUNC);
#endif
    wdh = wtap_dump_fdopen(import_file_fd, WTAP_FILE_TYPE_SUBTYPE_PCAPNG,
                           WTAP_UNCOMPRESSED, &params, err);

    if (!wdh)
        goto error_open;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Writing packet data into the file\n", G_STRFUNC);
#endif
    /* OK we've opened a new pcapng file and written the headers, time to do the packets */
    for (packet = packets; packet; packet = g_slist_next(packet))
    {
        if (!candump_add_packet(wdh, (msg_t *)packet->data, err, err_info))
            goto error_write;
    }

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Closing the file\n", G_STRFUNC);
#endif
    /* Close the written file */
    if (!wtap_dump_close(wdh, err))
        goto error_write;

    goto exit;

error_write:
    wtap_dump_close(wdh, err);
    ws_unlink(filename);
error_open:
    g_free(filename);
    filename = NULL;
exit:
    wtap_block_array_free(shb_hdrs);
    wtap_free_idb_info(idb_inf);

    return filename;
}

static wtap_open_return_val
candump_parse(candump_priv_t **priv, wtap *wth, int *err, char **err_info)
{
    GSList *packets;
    gchar  *filename;
    wtap   *fh;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Trying candump file decoder\n", G_STRFUNC);
#endif
    packets = run_candump_parser(wth->fh, err, err_info);

    if (!packets)
        return WTAP_OPEN_NOT_MINE;

    if (*err)
    {
        g_slist_free_full(packets, g_free);
        return WTAP_OPEN_ERROR;
    }

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Creating a PCAPNG file with data we've just read\n", G_STRFUNC);
#endif
    /* Dump packets into a temporary file */
    filename = candump_dump(packets, err, err_info);
    g_slist_free_full(packets, g_free);

    if (!filename)
        return WTAP_OPEN_ERROR;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Opening the newly created file\n", G_STRFUNC);
#endif
    /* Now open the file for reading */
    fh = wtap_open_offline(filename, WTAP_TYPE_AUTO,
                           err, err_info,
                           (wth->random_fh ? TRUE : FALSE));

    if (!fh)
    {
        g_free(filename);
        return WTAP_OPEN_ERROR;
    }

    *priv = g_new0(candump_priv_t, 1);

    (*priv)->tmp_file     = fh;
    (*priv)->tmp_filename = filename;

#ifdef CANDUMP_DEBUG
    ws_debug_printf("%s: Ok\n", G_STRFUNC);
#endif
    return WTAP_OPEN_MINE;
}

wtap_open_return_val
candump_open(wtap *wth, int *err, char **err_info)
{
    wtap_open_return_val  ret;
    candump_priv_t       *priv = NULL;

    ret = candump_parse(&priv, wth, err, err_info);

    if (ret != WTAP_OPEN_MINE)
        return ret;

    if (!priv)
        return WTAP_OPEN_ERROR;

    /* Copy header section block from the temp file */
    wtap_block_copy(g_array_index(wth->shb_hdrs, wtap_block_t, 0), g_array_index(priv->tmp_file->shb_hdrs, wtap_block_t, 0));

    wth->priv              = priv;
    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;
    wth->file_encap        = priv->tmp_file->file_encap;
    wth->file_tsprec       = priv->tmp_file->file_tsprec;
    wth->subtype_read      = candump_read;
    wth->subtype_seek_read = candump_seek_read;
    wth->subtype_close     = candump_close;
    wth->snapshot_length   = 0;

    return WTAP_OPEN_MINE;
}

static gboolean
candump_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info,
             gint64 *data_offset)
{
    candump_priv_t *priv = (candump_priv_t *)wth->priv;

    return wtap_read(priv->tmp_file, rec, buf, err, err_info, data_offset);

}

static gboolean
candump_seek_read(wtap *wth , gint64 seek_off, wtap_rec *rec,
                  Buffer *buf, int *err, gchar **err_info)
{
    candump_priv_t *priv = (candump_priv_t *)wth->priv;

    return wtap_seek_read(priv->tmp_file, seek_off, rec, buf, err, err_info);
}

static void candump_close(wtap *wth)
{
    candump_priv_t *priv = (candump_priv_t *)wth->priv;

    wtap_close(priv->tmp_file);
    ws_unlink(priv->tmp_filename);
    g_free(priv->tmp_filename);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
