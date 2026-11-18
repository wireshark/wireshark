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
#define MOQ_READ_CHUNK_SIZE   (64 * 1024)

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
    int io_err = 0;

    /* An object with no data needs nothing from the data file. Otherwise,
     * don't check the range against the file's size first: getting the
     * size of a compressed file by seeking to its end decompresses all of
     * it. A range past the end fails the seek or the read.
     *
     * Set *err_info only with an error whose message uses it (and frees
     * it); the message for an errno value doesn't.
     *
     * XXX - the message for an errno value names the file being read,
     * i.e. the metadata file (or "the standard input"), even though the
     * error is with the data file. */
    if (record->data_length > 0) {
        data_fp = file_open(record->data_path);
        if (data_fp == NULL) {
            if (errno != 0) {
                *err = errno;
            } else {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("MoQ data file could not be opened: %s", record->data_path);
            }
            return false;
        }
        if (file_seek(data_fp, (int64_t)record->data_offset, SEEK_SET, &io_err) < 0) {
            /* The seek can fail with an error from reading the file
             * (e.g., decompressing it), which comes with its own
             * err_info, or with an errno value, which doesn't. */
            int file_err = file_error(data_fp, err_info);
            file_close(data_fp);
            if (file_err != 0) {
                *err = file_err;
            } else if (io_err != 0) {
                *err = io_err;
            } else {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("MoQ data range is outside file: %s", record->data_path);
            }
            return false;
        }
        object_data = (uint8_t *)g_malloc(record->data_length);
        if (file_read(object_data, record->data_length, data_fp) != (int)record->data_length) {
            g_free(object_data);
            io_err = file_error(data_fp, err_info);
            file_close(data_fp);
            if (io_err != 0) {
                *err = io_err;
            } else {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("MoQ data range is outside file or truncated: %s", record->data_path);
            }
            return false;
        }
        file_close(data_fp);
    }

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
    char *json_buf = NULL;
    size_t buf_size, buf_len;
    size_t max_size;
    jsmntok_t *tokens = NULL;
    unsigned max_tokens;
    int token_count;
    int bytes_read;
    jsmn_parser parser;
    moq_priv_t *priv = NULL;
    wtap_open_return_val ret = WTAP_OPEN_NOT_MINE;

    /*
     * Read the metadata, a JSON array of at most MOQ_MAX_METADATA_SIZE
     * bytes, in growing chunks, passing each to the JSON parser as we
     * go, so that we stop reading as soon as it isn't an array or isn't
     * valid JSON. (Don't size the buffer from the file's size: that's
     * the compressed size for a compressed file.)
     */
    jsmn_init(&parser);
    /*
     * On a pipe, read no more than the I/O routines guarantee we can
     * seek back over (see below). Read one more byte than the maximum
     * otherwise, so that a full read means the metadata is too large.
     */
    max_size = (size_t)MOQ_MAX_METADATA_SIZE + 1;
    if (wth->ispipe) {
        max_size = MIN(max_size, file_bufsize(wth->fh));
    }
    buf_size = MIN((size_t)MOQ_READ_CHUNK_SIZE, max_size);
    buf_len = 0;
    json_buf = (char *)g_malloc(buf_size + 1);
    max_tokens = 16;
    tokens = g_new(jsmntok_t, max_tokens);
    for (;;) {
        bytes_read = file_read((uint8_t *)json_buf + buf_len, (unsigned int)(buf_size - buf_len), wth->fh);
        if (bytes_read < 0) {
            *err = file_error(wth->fh, err_info);
            ret = WTAP_OPEN_ERROR;
            goto fail;
        }
        /*
         * JSON text can't contain a NUL byte (not even in a string,
         * where control characters must be escaped), and the parser
         * stops at one as if it were the end of the data, so that we'd
         * keep reading more in vain.
         */
        if (memchr(json_buf + buf_len, '\0', (size_t)bytes_read) != NULL) {
            goto fail;
        }
        bool first_chunk = (buf_len == 0);
        buf_len += (size_t)bytes_read;
        bool at_eof = (buf_len < buf_size);

        /* Parse what we've read, giving the parser more tokens as needed. */
        for (;;) {
            token_count = jsmn_parse(&parser, json_buf, buf_len, tokens, max_tokens);
            if (token_count != JSMN_ERROR_NOMEM) {
                break;
            }
            if (tokens[0].type != JSMN_ARRAY) {
                goto fail;
            }
            /* Each token starts at a different byte, so there can't be
             * more tokens than bytes. */
            unsigned new_max = (unsigned)MIN((size_t)max_tokens * 2, buf_len + 1);
            if (new_max <= max_tokens) {
                /* Shouldn't happen. */
                goto fail;
            }
            max_tokens = new_max;
            tokens = g_renew(jsmntok_t, tokens, max_tokens);
        }
        if (token_count == JSMN_ERROR_INVAL) {
            /* Not valid JSON. */
            goto fail;
        }
        if (parser.toknext > 0 && tokens[0].type != JSMN_ARRAY) {
            goto fail;
        }
        if (first_chunk) {
            if (parser.toknext == 0) {
                /* Nothing but whitespace (or one long string or
                 * primitive), so not an array. */
                goto fail;
            }
            if (!file_iscompressed(wth->fh)) {
                int64_t file_size = wtap_file_size(wth, err);
                if (file_size < 0) {
                    ret = WTAP_OPEN_ERROR;
                    goto fail;
                }
                if (file_size > MOQ_MAX_METADATA_SIZE) {
                    goto fail;
                }
            }
        }
        if (at_eof) {
            break;
        }
        if (wth->ispipe && buf_size >= max_size) {
            /*
             * We have to read and parse all the metadata before deciding
             * whether it's ours. On a pipe, reading more could read past
             * what the I/O routines buffer, after which neither we nor
             * the open routines tried after us (which start by seeking
             * back to the beginning) could seek back, so give up; the
             * JSON reader can read it as plain JSON.
             *
             * XXX - that means larger MoQ metadata read from a pipe is
             * silently shown as plain JSON, without its objects. Find a
             * way to tell the user that (see the same comment in
             * netlog.c). Following metadata that is appended to as new
             * data files are written would also need the metadata parsed
             * as a stream, which might fit better in an extcap.
             */
            goto fail;
        }
        if (buf_size >= max_size) {
            /* Too large */
            goto fail;
        }
        buf_size = MIN(buf_size * 2, max_size);
        json_buf = (char *)g_realloc(json_buf, buf_size + 1);
    }
    if (token_count < 0) {
        /* The file ends with the array (or something in it) not
         * closed, or in the middle of a string or primitive. */
        goto fail;
    }
    json_buf[buf_len] = '\0';

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

fail:
    g_free(tokens);
    g_free(json_buf);
    return ret;
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
