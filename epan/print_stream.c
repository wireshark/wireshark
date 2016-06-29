/* print_stream.c
 * Routines for print streams.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

#include <glib.h>

#include <epan/print_stream.h>

#include <epan/ps.h>

#include <wsutil/file_util.h>

static FILE *
open_print_dest(gboolean to_file, const char *dest)
{
    FILE *fh;

    /* Open the file or command for output */
    if (to_file)
        fh = ws_fopen(dest, "w");
    else
        fh = popen(dest, "w");

    return fh;
}

static gboolean
close_print_dest(gboolean to_file, FILE *fh)
{
    /* Close the file or command */
    if (to_file)
        return (fclose(fh) == 0);
    else
        return (pclose(fh) == 0);
}

/* Some formats need stuff at the beginning of the output */
gboolean
print_preamble(print_stream_t *self, gchar *filename, const char *version_string)
{
    return self->ops->print_preamble ? (self->ops->print_preamble)(self, filename, version_string) : TRUE;
}

gboolean
print_line(print_stream_t *self, int indent, const char *line)
{
    return (self->ops->print_line)(self, indent, line);
}

/* Insert bookmark */
gboolean
print_bookmark(print_stream_t *self, const gchar *name, const gchar *title)
{
    return self->ops->print_bookmark ? (self->ops->print_bookmark)(self, name, title) : TRUE;
}

gboolean
new_page(print_stream_t *self)
{
    return self->ops->new_page ? (self->ops->new_page)(self) : TRUE;
}

/* Some formats need stuff at the end of the output */
gboolean
print_finale(print_stream_t *self)
{
    return self->ops->print_finale ? (self->ops->print_finale)(self) : TRUE;
}

gboolean
destroy_print_stream(print_stream_t *self)
{
    return self->ops->destroy ? (self->ops->destroy)(self) : TRUE;
}

typedef struct {
    gboolean  to_file;
    FILE     *fh;
} output_text;

#define MAX_INDENT    160

static gboolean
print_line_text(print_stream_t *self, int indent, const char *line)
{
    static char  spaces[MAX_INDENT];
    size_t ret;

    output_text *output = (output_text *)self->data;
    unsigned int num_spaces;

    /* should be space, if NUL -> initialize */
    if (!spaces[0]) {
        int i;

        for (i = 0; i < MAX_INDENT; i++)
            spaces[i] = ' ';
    }

    /* Prepare the tabs for printing, depending on tree level */
    num_spaces = indent * 4;
    if (num_spaces > MAX_INDENT)
        num_spaces = MAX_INDENT;

    ret = fwrite(spaces, 1, num_spaces, output->fh);
    if (ret == num_spaces) {
        gchar *tty_out = NULL;

        if (self->isatty && self->to_codeset) {
            /* XXX Allocating a fresh buffer every line probably isn't the
             * most efficient way to do this. However, this has the side
             * effect of scrubbing invalid output.
             */
            tty_out = g_convert_with_fallback(line, -1, self->to_codeset, "UTF-8", "?", NULL, NULL, NULL);
        }

        if (tty_out) {
#ifdef _WIN32
            DWORD out_len = (DWORD) wcslen((wchar_t *) tty_out);
            WriteConsoleW((HANDLE)_get_osfhandle(_fileno(output->fh)), tty_out, out_len, &out_len, NULL);
#else
            fputs(tty_out, output->fh);
#endif
            g_free(tty_out);
        } else {
            fputs(line, output->fh);
        }
        putc('\n', output->fh);
    }
    return !ferror(output->fh);
}

static gboolean
new_page_text(print_stream_t *self)
{
    output_text *output = (output_text *)self->data;

    fputs("\f", output->fh);
    return !ferror(output->fh);
}

static gboolean
destroy_text(print_stream_t *self)
{
    output_text *output = (output_text *)self->data;
    gboolean     ret;

    ret = close_print_dest(output->to_file, output->fh);
    g_free(output);
    g_free(self);
    return ret;
}

static const print_stream_ops_t print_text_ops = {
    NULL,            /* preamble */
    print_line_text,
    NULL,            /* bookmark */
    new_page_text,
    NULL,            /* finale */
    destroy_text
};

static print_stream_t *
print_stream_text_alloc(gboolean to_file, FILE *fh)
{
    print_stream_t *stream;
    output_text    *output;
#ifndef _WIN32
    const gchar *charset;
    gboolean is_utf8;
#endif

    output          = (output_text *)g_malloc(sizeof *output);
    output->to_file = to_file;
    output->fh      = fh;
    stream          = (print_stream_t *)g_malloc0(sizeof (print_stream_t));
    stream->ops     = &print_text_ops;
    stream->isatty  = ws_isatty(ws_fileno(fh));
    stream->data    = output;

#ifndef _WIN32
    /* Is there a more reliable way to do this? */
    is_utf8 = g_get_charset(&charset);
    if (!is_utf8) {
        stream->to_codeset = charset;
    }
#else
    stream->to_codeset = "UTF-16LE";
#endif

    return stream;
}

print_stream_t *
print_stream_text_new(gboolean to_file, const char *dest)
{
    FILE *fh;

    fh = open_print_dest(to_file, dest);
    if (fh == NULL)
        return NULL;

    return print_stream_text_alloc(to_file, fh);
}

print_stream_t *
print_stream_text_stdio_new(FILE *fh)
{
    return print_stream_text_alloc(TRUE, fh);
}

typedef struct {
    gboolean  to_file;
    FILE     *fh;
} output_ps;

#define MAX_PS_LINE_LENGTH 256

static
void ps_clean_string(char *out, const char *in, int outbuf_size)
{
    int  rd, wr;
    char c;

    if (in == NULL) {
        out[0] = '\0';
        return;
    }

    for (rd = 0, wr = 0 ; wr < outbuf_size; rd++, wr++ ) {
        c = in[rd];
        switch (c) {
        case '(':
        case ')':
        case '\\':
            out[wr] = '\\';
            out[++wr] = c;
            break;

        default:
            out[wr] = c;
            break;
        }

        if (c == 0) {
            break;
        }
    }
}

static gboolean
print_preamble_ps(print_stream_t *self, gchar *filename, const char *version_string)
{
    output_ps *output = (output_ps *)self->data;
    char       psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

    print_ps_preamble(output->fh);

    fputs("%% the page title\n", output->fh);
    ps_clean_string(psbuffer, filename, MAX_PS_LINE_LENGTH);
    fprintf(output->fh, "/ws_pagetitle (%s - Wireshark %s) def\n", psbuffer, version_string);
    fputs("\n", output->fh);
    return !ferror(output->fh);
}

static gboolean
print_line_ps(print_stream_t *self, int indent, const char *line)
{
    output_ps *output = (output_ps *)self->data;
    char       psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

    ps_clean_string(psbuffer, line, MAX_PS_LINE_LENGTH);
    fprintf(output->fh, "%d (%s) putline\n", indent, psbuffer);
    return !ferror(output->fh);
}

static gboolean
print_bookmark_ps(print_stream_t *self, const gchar *name, const gchar *title)
{
    output_ps *output = (output_ps *)self->data;
    char       psbuffer[MAX_PS_LINE_LENGTH]; /* static sized buffer! */

    /*
     * See the Adobe "pdfmark reference":
     *
     *  http://partners.adobe.com/asn/acrobat/docs/pdfmark.pdf
     *
     * The pdfmark stuff tells code that turns PostScript into PDF
     * things that it should do.
     *
     * The /OUT stuff creates a bookmark that goes to the
     * destination with "name" as the name and "title" as the title.
     *
     * The "/DEST" creates the destination.
     */
    ps_clean_string(psbuffer, title, MAX_PS_LINE_LENGTH);
    fprintf(output->fh, "[/Dest /%s /Title (%s)   /OUT pdfmark\n", name,
          psbuffer);
    fputs("[/View [/XYZ -4 currentpoint matrix currentmatrix matrix defaultmatrix\n",
          output->fh);
    fputs("matrix invertmatrix matrix concatmatrix transform exch pop 20 add null]\n",
          output->fh);
    fprintf(output->fh, "/Dest /%s /DEST pdfmark\n", name);
    return !ferror(output->fh);
}

static gboolean
new_page_ps(print_stream_t *self)
{
    output_ps *output = (output_ps *)self->data;

    fputs("formfeed\n", output->fh);
    return !ferror(output->fh);
}

static gboolean
print_finale_ps(print_stream_t *self)
{
    output_ps *output = (output_ps *)self->data;

    print_ps_finale(output->fh);
    return !ferror(output->fh);
}

static gboolean
destroy_ps(print_stream_t *self)
{
    output_ps *output = (output_ps *)self->data;
    gboolean   ret;

    ret = close_print_dest(output->to_file, output->fh);
    g_free(output);
    g_free(self);
    return ret;
}

static const print_stream_ops_t print_ps_ops = {
    print_preamble_ps,
    print_line_ps,
    print_bookmark_ps,
    new_page_ps,
    print_finale_ps,
    destroy_ps
};

static print_stream_t *
print_stream_ps_alloc(gboolean to_file, FILE *fh)
{
    print_stream_t *stream;
    output_ps      *output;

    output          = (output_ps *)g_malloc(sizeof *output);
    output->to_file = to_file;
    output->fh      = fh;
    stream          = (print_stream_t *)g_malloc(sizeof (print_stream_t));
    stream->ops     = &print_ps_ops;
    stream->data    = output;

    return stream;
}

print_stream_t *
print_stream_ps_new(gboolean to_file, const char *dest)
{
    FILE *fh;

    fh = open_print_dest(to_file, dest);
    if (fh == NULL)
        return NULL;

    return print_stream_ps_alloc(to_file, fh);
}

print_stream_t *
print_stream_ps_stdio_new(FILE *fh)
{
    return print_stream_ps_alloc(TRUE, fh);
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
