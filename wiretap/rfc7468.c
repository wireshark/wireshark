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

/* 128 bytes should be enough to contain any line. Strictly speaking, 64 is
   enough, but we provide some leeway to accomodate nonconformant producers and
   trailing whitespace. The 2 extra bytes are for the trailing newline and NUL
   terminator. */
#define MAX_LINE_LENGTH (128 + 2)

static char *read_complete_text_line(char line[MAX_LINE_LENGTH], FILE_T fh, int *err, gchar **err_info)
{
    char *line_end;

    if (!(line_end = file_getsp(line, MAX_LINE_LENGTH, fh))) {
        *err = file_error(fh, err_info);
        return NULL;
    }

    if (strlen(line) != (size_t)(line_end - line)) {
        *err = 0;
        return NULL;
    }

    if (line_end[-1] != '\n' && !file_eof(fh)) {
        *err = 0;
        return NULL;
    }

    return line_end;
}

//
// Arbitrary value - we don't want to read all of a huge non-RFC 7468 file
// only to find no pre-encapsulation boundary.
//
#define MAX_EXPLANATORY_TEXT_LINES	20

wtap_open_return_val rfc7468_open(wtap *wth, int *err, gchar **err_info)
{
    gboolean found_preeb;
    static const char preeb_begin[] = "-----BEGIN ";
    char line[MAX_LINE_LENGTH];

    //
    // Skip up to MAX_EXPLANATORY_TEXT_LINES worth of lines that don't
    // look like pre-encapsulation boundaries.
    //
    found_preeb = FALSE;
    for (unsigned int i = 0; i < MAX_EXPLANATORY_TEXT_LINES; i++) {
        if (!read_complete_text_line(line, wth->fh, err, err_info)) {
            if (*err == 0 || *err == WTAP_ERR_SHORT_READ)
                return WTAP_OPEN_NOT_MINE;
            return WTAP_OPEN_ERROR;
        }

        // Does the line look like a pre-encapsulation boundary?
        if (memcmp(line, preeb_begin, sizeof preeb_begin - 1) == 0) {
            // Yes.
            found_preeb = TRUE;
            break;
        }
    }
    if (!found_preeb)
        return WTAP_OPEN_NOT_MINE;

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1)
        return WTAP_OPEN_ERROR;

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_RFC7468;
    wth->file_encap = WTAP_ENCAP_RFC7468;

    wth->snapshot_length = 0;
    wth->file_tsprec = WTAP_TSPREC_SEC;

    wth->subtype_read = wtap_full_file_read;
    wth->subtype_seek_read = wtap_full_file_seek_read;

    return WTAP_OPEN_MINE;
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
