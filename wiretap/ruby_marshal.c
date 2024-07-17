/* ruby_marshal.c
 *
 * Routines for reading a binary file containing a ruby marshal object
 *
 * Copyright 2018, Dario Lombardo <lomato@gmail.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "ruby_marshal.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

static int ruby_marshal_file_type_subtype = -1;

void register_ruby_marshal(void);

static bool is_ruby_marshal(const uint8_t* filebuf)
{
    if (filebuf[0] != RUBY_MARSHAL_MAJOR)
        return false;
    if (filebuf[1] != RUBY_MARSHAL_MINOR)
        return false;
    switch (filebuf[2]) {
        case '0':
        case 'T':
        case 'F':
        case 'i':
        case ':':
        case '"':
        case 'I':
        case '[':
        case '{':
        case 'f':
        case 'c':
        case 'm':
        case 'S':
        case '/':
        case 'o':
        case 'C':
        case 'e':
        case ';':
        case '@':
            return true;
        default:
            return false;
    }
}

wtap_open_return_val ruby_marshal_open(wtap *wth, int *err, char **err_info)
{
    /* The size of this buffer should match the expectations of is_ruby_marshal */
    uint8_t filebuf[3];
    int bytes_read;

    bytes_read = file_read(filebuf, sizeof(filebuf), wth->fh);
    if (bytes_read < 0) {
        /* Read error. */
        *err = file_error(wth->fh, err_info);
        return WTAP_OPEN_ERROR;
    }

    if (bytes_read != sizeof(filebuf) || !is_ruby_marshal(filebuf)) {
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = ruby_marshal_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_RUBY_MARSHAL;
    wth->file_tsprec = WTAP_TSPREC_SEC;
    wth->subtype_read = wtap_full_file_read;
    wth->subtype_seek_read = wtap_full_file_seek_read;
    wth->snapshot_length = 0;

    return WTAP_OPEN_MINE;
}

static const struct supported_block_type ruby_marshal_blocks_supported[] = {
    /*
     * We support packet blocks, with no comments or other options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info ruby_marshal_info = {
    "Ruby marshal files", "ruby_marshal", NULL, NULL,
    false, BLOCKS_SUPPORTED(ruby_marshal_blocks_supported),
    NULL, NULL, NULL
};

void register_ruby_marshal(void)
{
    ruby_marshal_file_type_subtype = wtap_register_file_type_subtype(&ruby_marshal_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("RUBY_MARSHAL",
                                                   ruby_marshal_file_type_subtype);
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
