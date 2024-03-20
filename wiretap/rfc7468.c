/* rfc7468.c
 *
 * Implements loading of files in the format specified by RFC 7468.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "rfc7468.h"

#include "file_wrappers.h"
#include "wtap-int.h"

#include <wsutil/buffer.h>

#include <glib.h>

#include <string.h>

static int rfc7468_file_type_subtype = -1;

void register_rfc7468(void);

enum line_type {
    LINE_TYPE_PREEB,
    LINE_TYPE_POSTEB,
    LINE_TYPE_OTHER,
};

const char PREEB_BEGIN[] = "-----BEGIN ";
#define PREEB_BEGIN_LEN (sizeof PREEB_BEGIN - 1)
const char POSTEB_BEGIN[] = "-----END ";
#define POSTEB_BEGIN_LEN (sizeof POSTEB_BEGIN - 1)

static bool rfc7468_read_line(FILE_T fh, enum line_type *line_type, Buffer *buf,
    int* err, char** err_info)
{
    /* Make the chunk size large enough that most lines can fit in a single chunk.
       Strict RFC 7468 syntax only allows up to 64 characters per line, but we provide
       some leeway to accommodate nonconformant producers and explanatory text.
       The 3 extra bytes are for the trailing CR+LF and NUL terminator. */
    char line_chunk[128 + 3];
    char *line_chunk_end;

    if (!(line_chunk_end = file_getsp(line_chunk, sizeof line_chunk, fh))) {
        *err = file_error(fh, err_info);
        return false;
    }

    // First chunk determines the line type.
    if (memcmp(line_chunk, PREEB_BEGIN, PREEB_BEGIN_LEN) == 0)
        *line_type = LINE_TYPE_PREEB;
    else if (memcmp(line_chunk, POSTEB_BEGIN, POSTEB_BEGIN_LEN) == 0)
        *line_type = LINE_TYPE_POSTEB;
    else
        *line_type = LINE_TYPE_OTHER;

    for (;;) {
        size_t line_chunk_len = line_chunk_end - line_chunk;
        if (line_chunk_len > INT_MAX - ws_buffer_length(buf)) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup_printf(
                "File contains an encoding larger than the maximum of %d bytes",
                INT_MAX);
            return false;
        }

        ws_buffer_append(buf, line_chunk, line_chunk_len);

        if (line_chunk_end[-1] == '\n' || file_eof(fh))
            break;

        if (!(line_chunk_end = file_getsp(line_chunk, sizeof line_chunk, fh))) {
            *err = file_error(fh, err_info);
            return false;
        }
    }

    return true;
}

static bool rfc7468_read_impl(FILE_T fh, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info)
{
    ws_buffer_clean(buf);

    bool saw_preeb = false;

    for (;;) {
        enum line_type line_type;

        if (!rfc7468_read_line(fh, &line_type, buf, err, err_info)) {
            if (*err != 0 || !saw_preeb) return false;

            *err = WTAP_ERR_BAD_FILE;
            *err_info = g_strdup("Missing post-encapsulation boundary at end of file");
            return false;
        }

        if (saw_preeb) {
            if (line_type == LINE_TYPE_POSTEB) break;
        } else {
            if (line_type == LINE_TYPE_PREEB) saw_preeb = true;
        }
    }

    rec->rec_type = REC_TYPE_PACKET;
    rec->presence_flags = 0;
    rec->ts.secs = 0;
    rec->ts.nsecs = 0;
    rec->rec_header.packet_header.caplen = (uint32_t)ws_buffer_length(buf);
    rec->rec_header.packet_header.len = (uint32_t)ws_buffer_length(buf);

    return true;
}

static bool rfc7468_read(wtap *wth, wtap_rec *rec, Buffer *buf,
    int *err, char **err_info, int64_t *data_offset)
{
    *data_offset = file_tell(wth->fh);

    return rfc7468_read_impl(wth->fh, rec, buf, err, err_info);
}

static bool rfc7468_seek_read(wtap *wth, int64_t seek_off, wtap_rec *rec,
    Buffer *buf, int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) < 0)
        return false;

    return rfc7468_read_impl(wth->random_fh, rec, buf, err, err_info);
}

wtap_open_return_val rfc7468_open(wtap *wth, int *err, char **err_info)
{
    /* To detect whether this file matches our format, we need to find the
       first pre-encapsulation boundary, which may be located anywhere in the file,
       since it may be preceded by explanatory text. However, we don't want to
       read the entire file to find it, since the file may be huge, and detection
       needs to be fast. Therefore, we'll assume that if the boundary exists,
       it's located within a small initial chunk of the file. The size of
       the chunk was chosen arbitrarily. */
    char initial_chunk[2048];
    int initial_chunk_size = file_read(&initial_chunk, sizeof initial_chunk, wth->fh);

    if (initial_chunk_size < 0) {
        *err = file_error(wth->fh, err_info);
        return WTAP_OPEN_ERROR;
    }

    char *chunk_end_ptr = initial_chunk + initial_chunk_size;

    // Try to find a line that starts with PREEB_BEGIN in the initial chunk.
    for (char *line_ptr = initial_chunk; ; ) {
        if ((unsigned)(chunk_end_ptr - line_ptr) < PREEB_BEGIN_LEN)
            return WTAP_OPEN_NOT_MINE;

        if (memcmp(line_ptr, PREEB_BEGIN, PREEB_BEGIN_LEN) == 0)
            break;

        // Try next line.
        char *lf_ptr = memchr(line_ptr, '\n', chunk_end_ptr - line_ptr);
        if (!lf_ptr)
            return WTAP_OPEN_NOT_MINE;
        line_ptr = lf_ptr + 1;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    wth->file_type_subtype = rfc7468_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_RFC7468;

    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;

    wth->subtype_read = rfc7468_read;
    wth->subtype_seek_read = rfc7468_seek_read;

    return WTAP_OPEN_MINE;
}

static const struct supported_block_type rfc7468_blocks_supported[] = {
    /*
     * We provide one "packet" for each encoded structure in the file,
     * and don't support any options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info rfc7468_info = {
    "RFC 7468 files", "rfc7468", NULL, NULL,
    false, BLOCKS_SUPPORTED(rfc7468_blocks_supported),
    NULL, NULL, NULL
};

void register_rfc7468(void)
{
    rfc7468_file_type_subtype = wtap_register_file_type_subtype(&rfc7468_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("RFC7468",
                                                   rfc7468_file_type_subtype);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
