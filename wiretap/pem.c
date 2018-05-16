/* pem.c
 *
 * Implements loading of files in the format specified by RFC 7468.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "pem.h"

#include "file_wrappers.h"
#include "wtap-int.h"

#include <wsutil/buffer.h>

#include <glib.h>

#include <string.h>

/* 128 bytes should be enough to contain any line. Strictly speaking, 64 is
   enough, but we provide some leeway to accomodate nonconformant producers and
   trailing whitespace. The 2 extra bytes are for the trailing newline and NUL
   terminator. */
#define MAX_LINE_LENGTH (128 + 2)

/* based on the `label` production in RFC 7468 */
#define RE_LABEL "([!-,.-~]([-\\s]?[!-,.-~])*)?"

struct pem_priv {
    GRegex *re_blank_line;
    GRegex *re_pre_eb;
    GRegex *re_post_eb;
    GRegex *re_base64;
};

static char *read_complete_text_line(char line[MAX_LINE_LENGTH], FILE_T fh, int *err, gchar **err_info)
{
    char *line_end;

    if (!(line_end = file_getsp(line, MAX_LINE_LENGTH, fh))) {
        *err = file_error(fh, err_info);
        return NULL;
    }

    if (strlen(line) != (size_t)(line_end - line)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("unexpected NUL inside a line");
        return NULL;
    }

    if (line_end[-1] != '\n' && !file_eof(fh)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("overlong line");
        return NULL;
    }

    return line_end;
}

static gboolean pem_read_value(wtap *wth, FILE_T fh, wtap_rec *rec,
                               Buffer *buf, int *err, gchar **err_info)
{
    struct pem_priv *priv = (struct pem_priv *)wth->priv;

    char line[MAX_LINE_LENGTH];

    // skip blank lines
    do {
        if (!read_complete_text_line(line, fh, err, err_info)) return FALSE;
    } while (g_regex_match(priv->re_blank_line, line, (GRegexMatchFlags)0, NULL));

    if (!g_regex_match(priv->re_pre_eb, line, (GRegexMatchFlags)0, NULL)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = g_strdup("invalid pre-encapsulation boundary");
        return FALSE;
    }

    gint base64_state = 0;
    guint base64_save = 0;

    ws_buffer_clean(buf);

    for (; ; ) {
        char *line_end = read_complete_text_line(line, fh, err, err_info);
        if (!line_end) {
            if (*err == 0) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup("missing post-encapsulation boundary");
            }
            return FALSE;
        }

        if (g_regex_match(priv->re_post_eb, line, (GRegexMatchFlags)0, NULL))
            break;

        if (!g_regex_match(priv->re_base64, line, (GRegexMatchFlags)0, NULL)) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("invalid base64 line");
            return FALSE;
        }

        guchar decoded[(sizeof(line) / 4) * 3 + 3];
        guint32 decoded_size = (guint32) g_base64_decode_step(
            line, line_end - line, decoded, &base64_state, &base64_save);

        if ((guint32)ws_buffer_length(buf) > G_MAXUINT32 - decoded_size) {
            // we can't set the packet length if this happens
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("encoded value too large");
            return FALSE;
        }

        ws_buffer_append(buf, decoded, decoded_size);
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = 0;
    rec->rec_header.packet_header.len =
        rec->rec_header.packet_header.caplen =
        (guint32)ws_buffer_length(buf);

    return TRUE;
}

static gboolean pem_read(wtap *wth, int *err, gchar **err_info, gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return pem_read_value(wth, wth->fh, &wth->rec, wth->rec_data, err, err_info);
}

static gboolean pem_seek_read(wtap *wth, gint64 seek_off, wtap_rec *rec,
                              Buffer *buf, int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    return pem_read_value(wth, wth->random_fh, rec, buf, err, err_info);
}

static void pem_close(wtap *wth)
{
    struct pem_priv *priv = (struct pem_priv *)wth->priv;

    g_regex_unref(priv->re_blank_line);
    g_regex_unref(priv->re_pre_eb);
    g_regex_unref(priv->re_post_eb);
    g_regex_unref(priv->re_base64);
}

wtap_open_return_val pem_open(wtap *wth, int *err, gchar **err_info)
{
    static const char expected_magic[] = "-----BEGIN ";
    char actual_magic[sizeof(expected_magic) - 1];

    if (!wtap_read_bytes(wth->fh, &actual_magic, sizeof(actual_magic), err, err_info)) {
        if (*err == WTAP_ERR_SHORT_READ)
            return WTAP_OPEN_NOT_MINE;
        return WTAP_OPEN_ERROR;
    }

    if (memcmp(expected_magic, actual_magic, sizeof(actual_magic)) != 0)
        return WTAP_OPEN_NOT_MINE;

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_PEM;
    wth->file_encap = WTAP_ENCAP_BER;

    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;

    struct pem_priv *priv = g_new0(struct pem_priv, 1);

    priv->re_blank_line = g_regex_new("^\\s*$", G_REGEX_RAW, (GRegexMatchFlags)0, NULL);

    priv->re_pre_eb = g_regex_new("^-----BEGIN " RE_LABEL "-----\\s*$",
        (GRegexCompileFlags)(G_REGEX_RAW | G_REGEX_NO_AUTO_CAPTURE),
        (GRegexMatchFlags)0, NULL);
    priv->re_post_eb = g_regex_new("^-----END " RE_LABEL "-----\\s*$",
        (GRegexCompileFlags)(G_REGEX_RAW | G_REGEX_NO_AUTO_CAPTURE),
        (GRegexMatchFlags)0, NULL);

    priv->re_base64 = g_regex_new("^[\\sA-Za-z0-9+/]*(=\\s*(=\\s*)?)?$",
        (GRegexCompileFlags)(G_REGEX_RAW | G_REGEX_NO_AUTO_CAPTURE),
        (GRegexMatchFlags)0, NULL);

    wth->priv = priv;

    wth->subtype_read = pem_read;
    wth->subtype_seek_read = pem_seek_read;
    wth->subtype_close = pem_close;

    if (!priv->re_blank_line || !priv->re_pre_eb || !priv->re_post_eb || !priv->re_base64) {
        *err = WTAP_ERR_INTERNAL;
        *err_info = g_strdup("failed to initialize reader");
        return WTAP_OPEN_ERROR;
    }

    return WTAP_OPEN_MINE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
