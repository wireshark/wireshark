/* moq.c
 * Wiretap reader for Serialization of MoQ Objects to Files.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include "moq.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>

#include <wtap_module.h>
#include <file_wrappers.h>
#include <wsutil/wsjson.h>
#include <wsutil/exported_pdu_tlvs.h>

#define MOQ_MAX_METADATA_SIZE (50 * 1024 * 1024)
#define MOQ_MAX_OBJECT_SIZE   (64 * 1024 * 1024)

typedef struct {
    char *metadata;
    size_t metadata_len;
    char *data_path;
    uint64_t data_offset;
    uint32_t data_length;
    int64_t receive_time_ms;
} moq_record_t;

typedef struct {
    GPtrArray *records;
    char *base_dir;
    Buffer epdu_header;
    uint32_t next_record;
} moq_priv_t;

static int moq_file_type_subtype = -1;

static bool
moq_get_integer(char *buf, jsmntok_t *object, const char *key, int64_t *value)
{
    return json_get_int(buf, object, key, value);
}

static void
moq_record_free(gpointer data)
{
    moq_record_t *record = (moq_record_t *)data;
    if (record != NULL) {
        g_free(record->metadata);
        g_free(record->data_path);
        g_free(record);
    }
}

/* Only accept a data file in the same directory as the metadata file. This
 * intentionally disallows subdirectories and absolute paths, avoiding path
 * traversal and symlink-based escapes from the capture directory. */
static char *
moq_resolve_data_path(const char *base_dir, const char *name)
{
    if (name == NULL || name[0] == '\0' || g_path_is_absolute(name) ||
        strchr(name, '/') != NULL || strchr(name, '\\') != NULL ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        return NULL;
    }
    return g_build_filename(base_dir, name, NULL);
}

static bool
moq_read_record(wtap *wth, moq_record_t *record, wtap_rec *rec,
                int *err, char **err_info)
{
    moq_priv_t *priv = (moq_priv_t *)wth->priv;
    FILE_T data_fp;
    uint8_t *object_data = NULL;
    uint8_t metadata_len[4];
    uint32_t epdu_len;
    int64_t file_size;
    int io_err = 0;

    data_fp = file_open(record->data_path);
    if (data_fp == NULL) {
        *err = errno != 0 ? errno : WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("MoQ data file could not be opened: %s", record->data_path);
        return false;
    }
    if (file_seek(data_fp, 0, SEEK_END, &io_err) < 0 || (file_size = file_tell(data_fp)) < 0 ||
        record->data_offset > (uint64_t)file_size || record->data_length > (uint64_t)file_size - record->data_offset ||
        file_seek(data_fp, (int64_t)record->data_offset, SEEK_SET, &io_err) < 0) {
        file_close(data_fp);
        *err = io_err != 0 ? io_err : WTAP_ERR_BAD_FILE;
        *err_info = g_strdup_printf("MoQ data range is outside file: %s", record->data_path);
        return false;
    }
    if (record->data_length > 0) {
        object_data = (uint8_t *)g_malloc(record->data_length);
        if (file_read(object_data, record->data_length, data_fp) != (int)record->data_length) {
            g_free(object_data);
            file_close(data_fp);
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf("MoQ data range is truncated: %s", record->data_path);
            return false;
        }
    }
    file_close(data_fp);

    ws_buffer_assure_space(&rec->data, (size_t)record->metadata_len + record->data_length + 4 + ws_buffer_length(&priv->epdu_header));
    ws_buffer_append(&rec->data, ws_buffer_start_ptr(&priv->epdu_header), ws_buffer_length(&priv->epdu_header));
    metadata_len[0] = (uint8_t)(record->metadata_len >> 24);
    metadata_len[1] = (uint8_t)(record->metadata_len >> 16);
    metadata_len[2] = (uint8_t)(record->metadata_len >> 8);
    metadata_len[3] = (uint8_t)record->metadata_len;
    ws_buffer_append(&rec->data, metadata_len, sizeof(metadata_len));
    ws_buffer_append(&rec->data, (const uint8_t *)record->metadata, record->metadata_len);
    if (record->data_length > 0)
        ws_buffer_append(&rec->data, object_data, record->data_length);
    g_free(object_data);

    epdu_len = (uint32_t)ws_buffer_length(&priv->epdu_header);
    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->presence_flags |= WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec->ts.secs = (time_t)(record->receive_time_ms / 1000);
    rec->ts.nsecs = (int32_t)((record->receive_time_ms % 1000) * 1000000);
    if (rec->ts.nsecs < 0) {
        rec->ts.secs--;
        rec->ts.nsecs += 1000000000;
    }
    rec->rec_header.packet_header.caplen = epdu_len + 4 + (uint32_t)record->metadata_len + record->data_length;
    rec->rec_header.packet_header.len = rec->rec_header.packet_header.caplen;
    return true;
}

static bool
moq_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *offset)
{
    moq_priv_t *priv = (moq_priv_t *)wth->priv;
    if (priv->next_record >= priv->records->len) {
        *err = 0;
        return false;
    }
    *offset = priv->next_record;
    moq_record_t *record = (moq_record_t *)g_ptr_array_index(priv->records, priv->next_record++);
    return moq_read_record(wth, record, rec, err, err_info);
}

static bool
moq_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec, int *err, char **err_info)
{
    moq_priv_t *priv = (moq_priv_t *)wth->priv;
    if (seek_off < 0 || (uint64_t)seek_off >= priv->records->len) {
        *err = WTAP_ERR_BAD_FILE;
        return false;
    }
    return moq_read_record(wth,
        (moq_record_t *)g_ptr_array_index(priv->records, (guint)seek_off), rec, err, err_info);
}

static void
moq_close(wtap *wth)
{
    moq_priv_t *priv = (moq_priv_t *)wth->priv;
    if (priv != NULL) {
        g_ptr_array_free(priv->records, TRUE);
        g_free(priv->base_dir);
        ws_buffer_free(&priv->epdu_header);
        g_free(priv);
        wth->priv = NULL;
    }
}

wtap_open_return_val
moq_open(wtap *wth, int *err, char **err_info)
{
    int64_t file_size;
    char *json_buf = NULL;
    jsmntok_t *tokens = NULL;
    int token_count;
    int bytes_read;
    moq_priv_t *priv = NULL;

    file_size = wtap_file_size(wth, err);
    if (file_size < 0) return WTAP_OPEN_ERROR;
    if (file_size == 0 || file_size > MOQ_MAX_METADATA_SIZE) return WTAP_OPEN_NOT_MINE;

    json_buf = (char *)g_malloc((size_t)file_size + 1);
    bytes_read = file_read((uint8_t *)json_buf, (unsigned int)file_size, wth->fh);
    if (bytes_read < 0) {
        *err = file_error(wth->fh, err_info);
        g_free(json_buf);
        return WTAP_OPEN_ERROR;
    }
    json_buf[bytes_read] = '\0';
    token_count = json_parse_len(json_buf, (size_t)bytes_read, NULL, 0);
    if (token_count <= 0) {
        g_free(json_buf);
        return WTAP_OPEN_NOT_MINE;
    }
    tokens = g_new0(jsmntok_t, token_count);
    if (json_parse_len(json_buf, (size_t)bytes_read, tokens, (unsigned int)token_count) < 0 ||
        tokens[0].type != JSMN_ARRAY) {
        g_free(tokens);
        g_free(json_buf);
        return WTAP_OPEN_NOT_MINE;
    }

    priv = g_new0(moq_priv_t, 1);
    priv->records = g_ptr_array_new_with_free_func(moq_record_free);
    priv->base_dir = g_path_get_dirname(wth->pathname);
    ws_buffer_init(&priv->epdu_header, 64);
    wtap_buffer_append_epdu_string(&priv->epdu_header, EXP_PDU_TAG_DISSECTOR_NAME, "moq_file");
    wtap_buffer_append_epdu_end(&priv->epdu_header);

    jsmntok_t *item = json_get_array_index(&tokens[0], 0);
    int count = json_get_array_len(&tokens[0]);
    for (int i = 0; i < count && item != NULL; i++, item = json_get_next_object(item)) {
        int64_t data_offset = 0, data_length = 0, receive_time = 0;
        /* The json_get_*() helpers below NUL-terminate values in place in
         * json_buf, so take a pristine copy of this item's metadata first. */
        size_t item_len = (size_t)(item->end - item->start);
        char *item_metadata = g_strndup(json_buf + item->start, item_len);
        char *data_file = json_get_string(json_buf, item, "dataFile");
        if (data_file == NULL || !moq_get_integer(json_buf, item, "dataOffset", &data_offset) ||
            !moq_get_integer(json_buf, item, "dataLength", &data_length) ||
            data_offset < 0 || data_length < 0 || data_length > MOQ_MAX_OBJECT_SIZE) {
            /* json_get_string() returns a pointer into json_buf. */
            g_free(item_metadata);
            continue;
        }
        (void)moq_get_integer(json_buf, item, "receiveTime", &receive_time);
        char *data_path = moq_resolve_data_path(priv->base_dir, data_file);
        /* data_file is borrowed from json_buf; do not free it. */
        if (data_path == NULL) {
            g_free(item_metadata);
            continue;
        }

        moq_record_t *record = g_new0(moq_record_t, 1);
        record->metadata_len = item_len;
        record->metadata = item_metadata;
        record->data_path = data_path;
        record->data_offset = (uint64_t)data_offset;
        record->data_length = (uint32_t)data_length;
        record->receive_time_ms = receive_time;
        g_ptr_array_add(priv->records, record);
    }

    g_free(tokens);
    g_free(json_buf);
    if (priv->records->len == 0) {
        g_ptr_array_free(priv->records, TRUE);
        g_free(priv->base_dir);
        ws_buffer_free(&priv->epdu_header);
        g_free(priv);
        return WTAP_OPEN_NOT_MINE;
    }
    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_ptr_array_free(priv->records, TRUE);
        g_free(priv->base_dir);
        ws_buffer_free(&priv->epdu_header);
        g_free(priv);
        return WTAP_OPEN_ERROR;
    }

    wth->priv = priv;
    wth->subtype_close = moq_close;
    wth->subtype_read = moq_read;
    wth->subtype_seek_read = moq_seek_read;
    wth->file_type_subtype = moq_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_WIRESHARK_UPPER_PDU;
    wth->file_tsprec = WTAP_TSPREC_MSEC;
    wth->snapshot_length = 0;
    return WTAP_OPEN_MINE;
}

static const struct supported_block_type moq_blocks_supported[] = {
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info moq_info = {
    "MoQ Object File", "moq", "moq", "moq",
    false, BLOCKS_SUPPORTED(moq_blocks_supported), NULL, NULL, NULL
};

void register_moq(void)
{
    moq_file_type_subtype = wtap_register_file_type_subtype(&moq_info);
}
