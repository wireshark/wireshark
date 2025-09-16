/* json.c
 *
 * Copyright 2015, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "json.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/wsjson.h>

/*
 * This reads an arbitrary, possibly large JSON object.
 * For JSON log data, see json_lines.c.
 */

/* Maximum size of json file. */
#define MAX_FILE_SIZE  (50*1024*1024)

static int json_file_type_subtype = -1;

void register_json(void);

wtap_open_return_val json_open(wtap *wth, int *err, char **err_info)
{
    int64_t filesize;
    uint8_t* filebuf;
    int bytes_read;

    /* XXX checking the full file contents might be a bit expensive, maybe
     * resort to simpler heuristics like '{' or '[' (with some other chars)? */
    if ((filesize = wtap_file_size(wth, err)) == -1)
        return WTAP_OPEN_ERROR;

    if (filesize > MAX_FILE_SIZE) {
        /* Avoid allocating space for an immensely-large file. */
        filesize = MAX_FILE_SIZE;
    }

    filebuf = (uint8_t*)g_malloc0(filesize);
    if (!filebuf)
        return WTAP_OPEN_ERROR;

    bytes_read = file_read(filebuf, (unsigned int) filesize, wth->fh);
    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(wth->fh, err_info);
        g_free(filebuf);
        return WTAP_OPEN_ERROR;
    }
    if (bytes_read == 0) {
        /* empty file, not *anybody's* */
        g_free(filebuf);
        return WTAP_OPEN_NOT_MINE;
    }

    /* We could reduce the maximum size to read and accept if the parser
     * returns JSMN_ERROR_PART (i.e., only fail on JSMN_ERROR_INVAL as we
     * shouldn't get JSMN_ERROR_NOMEM if tokens is NULL.) That way we
     * could handle bigger files without testing the entire file.
     * packet-json shows excess unparsed data at the end with the
     * data-text-lines dissector.
     */
    if (json_parse_len(filebuf, bytes_read, NULL, 0) < 0) {
        g_free(filebuf);
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        g_free(filebuf);
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = json_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_JSON;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = wtap_full_file_read;
    wth->subtype_seek_read = wtap_full_file_seek_read;
    wth->snapshot_length = 0;

    g_free(filebuf);
    return WTAP_OPEN_MINE;
}

static const struct supported_block_type json_blocks_supported[] = {
    /*
     * This is a file format that we dissect, so we provide only one
     * "packet" with the file's contents, and don't support any
     * options.
     */
    { WTAP_BLOCK_PACKET, ONE_BLOCK_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info json_info = {
    "JavaScript Object Notation", "json", "json", NULL,
    false, BLOCKS_SUPPORTED(json_blocks_supported),
    NULL, NULL, NULL
};

void register_json(void)
{
    json_file_type_subtype = wtap_register_file_type_subtype(&json_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("JSON",
                                                   json_file_type_subtype);
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
