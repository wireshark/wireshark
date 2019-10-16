/* print_stream.c
 * Routines for print streams.
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif /* ENABLE_VIRTUAL_TERMINAL_PROCESSING */
#else
#include <stdlib.h> /* for getenv() */
#include <unistd.h> /* for isatty() */
#endif

#include <glib.h>

#include <epan/print_stream.h>

#include <epan/ps.h>

#include <wsutil/file_util.h>

#define TERM_SGR_RESET "\x1B[0m"  /* SGR - reset */
#define TERM_CSI_EL    "\x1B[K"   /* EL - Erase in Line (to end of line) */

typedef enum {
    COLOR_NONE,
#ifdef _WIN32
    COLOR_CONSOLE,
#endif
    COLOR_24BIT_ESCAPE
} color_type_t;

typedef struct {
    gboolean     to_file;
    FILE        *fh;
    gboolean     isatty;
    const char  *to_codeset;
    color_type_t color_type;
#ifdef _WIN32
    WORD         csb_attrs;
    DWORD        console_mode;
#endif
} output_text;

#ifdef _WIN32
/*
 * The classic Windows Console offers 1-bit color, so you can't set
 * the red, green, or blue intensities, you can only set
 * "{foreground, background} contains {red, green, blue}". So
 * include red, green or blue if the numeric intensity is high
 * enough.
 */
static void
set_color_console(FILE *fh, const color_t *fg, const color_t *bg)
{
    /* default to white foreground, black background */
    WORD win_fg_color = FOREGROUND_RED|FOREGROUND_BLUE|FOREGROUND_GREEN;
    WORD win_bg_color = 0;

    if (fg) {
        if (((fg->red >> 8) & 0xff) >= 0x80)
        {
            win_fg_color |= FOREGROUND_RED;
        }
        else
        {
            win_fg_color &= (~FOREGROUND_RED);
        }
        if (((fg->green >> 8) & 0xff) >= 0x80)
        {
            win_fg_color |= FOREGROUND_GREEN;
        }
        else
        {
            win_fg_color &= (~FOREGROUND_GREEN);
        }
        if (((fg->blue >> 8) & 0xff) >= 0x80)
        {
            win_fg_color |= FOREGROUND_BLUE;
        }
        else
        {
            win_fg_color &= (~FOREGROUND_BLUE);
        }
    }

    if (bg) {
        if (((bg->red >> 8) & 0xff) >= 0x80)
        {
            win_bg_color |= BACKGROUND_RED;
        }
        else
        {
            win_bg_color &= (~BACKGROUND_RED);
        }
        if (((bg->green >> 8) & 0xff) >= 0x80)
        {
            win_bg_color |= BACKGROUND_GREEN;
        }
        else
        {
            win_bg_color &= (~BACKGROUND_GREEN);
        }
        if (((bg->blue >> 8) & 0xff) >= 0x80)
        {
            win_bg_color |= BACKGROUND_BLUE;
        }
        else
        {
            win_bg_color &= (~BACKGROUND_BLUE);
        }
    }

    SetConsoleTextAttribute((HANDLE)_get_osfhandle(_fileno(fh)), win_fg_color|win_bg_color);
}
#endif

/*
 * Use the SGR escape sequences to specify a 24-bit color.
 */
static void
set_color_24bit_escape(FILE *fh, const color_t *fg, const color_t *bg)
{
    /*
     * Use the "select character foreground colour" and "select character
     * background colour" options to the Select Graphic Rendition control
     * sequence; those are reserved in ECMA-48, and are specified in ISO
     * standard 8613-6/ITU-T Recommendation T.416, "Open Document Architecture
     * (ODA) and Interchange Format: Chararcter Content Architectures",
     * section 13.1.8 "Select Graphic Rendition (SGR)".  We use the
     * "direct colour in RGB space" option, with a parameter value of 2.
     *
     * Those sequences are supported by some UN*X terminal emulators; some
     * support either : or ; as a separator, others require a ;.
     *
     * For more than you ever wanted to know about all of this, see
     *
     *    https://github.com/termstandard/colors
     *
     * and
     *
     *    https://gist.github.com/XVilka/8346728
     *
     * including the discussion following it, and
     *
     *    https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
     *
     * They are also supported by versions of the Windows Console that
     * allow setting the ENABLE_VIRTUAL_TERMINAL_PROCESSING mode; that
     * mode tells the console to interpret escape sequences written
     * to it.
     */
    if (fg) {
        fprintf(fh, "\x1B[38;2;%u;%u;%um",
                (fg->red   >> 8) & 0xff,
                (fg->green >> 8) & 0xff,
                (fg->blue  >> 8) & 0xff);
    }

    if (bg) {
        fprintf(fh, "\x1B[48;2;%u;%u;%um",
                (bg->red   >> 8) & 0xff,
                (bg->green >> 8) & 0xff,
                (bg->blue  >> 8) & 0xff);
    }
}

#ifdef _WIN32
static void
do_color_eol_console(print_stream_t *self)
{
    output_text *output = (output_text *)self->data;
    FILE *fh = output->fh;

    SetConsoleTextAttribute((HANDLE)_get_osfhandle(_fileno(fh)), output->csb_attrs);
    fprintf(fh, "\n");
}
#endif

static void
do_color_eol_24bit_escape(print_stream_t *self)
{
    output_text *output = (output_text *)self->data;
    FILE *fh = output->fh;

    /*
     * Emit CSI EL to extend current background color all the way to EOL,
     * otherwise we get a ragged right edge of color wherever the newline
     * occurs.  It's not perfect in every terminal emulator, but it generally
     * works.
     */
    fprintf(fh, "%s\n%s", TERM_CSI_EL, TERM_SGR_RESET);
}

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

gboolean
print_line_color(print_stream_t *self, int indent, const char *line, const color_t *fg, const color_t *bg)
{
    if (self->ops->print_line_color)
        return (self->ops->print_line_color)(self, indent, line, fg, bg);
    else
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
    return (self && self->ops && self->ops->destroy) ? (self->ops->destroy)(self) : TRUE;
}

#define MAX_INDENT    160

/* returns TRUE if the print succeeded, FALSE if there was an error */
static gboolean
print_line_color_text(print_stream_t *self, int indent, const char *line, const color_t *fg, const color_t *bg)
{
    static char spaces[MAX_INDENT];
    size_t ret;
    output_text *output = (output_text *)self->data;
    unsigned int num_spaces;
    gboolean emit_color = output->isatty && (fg != NULL || bg != NULL);

    /* should be space, if NUL -> initialize */
    if (!spaces[0])
        memset(spaces, ' ', sizeof(spaces));

    if (emit_color) {
        switch (output->color_type) {

        case COLOR_NONE:
            break;

#ifdef _WIN32
        case COLOR_CONSOLE:
            set_color_console(output->fh, fg, bg);
            break;
#endif

        case COLOR_24BIT_ESCAPE:
            set_color_24bit_escape(output->fh, fg, bg);
            if (ferror(output->fh))
                return FALSE;
            break;
        }
    }

    /* Prepare the tabs for printing, depending on tree level */
    num_spaces = indent * 4;
    if (num_spaces > MAX_INDENT)
        num_spaces = MAX_INDENT;

    ret = fwrite(spaces, 1, num_spaces, output->fh);
    if (ret == num_spaces) {
        if (output->isatty && output->to_codeset) {
            /* XXX Allocating a fresh buffer every line probably isn't the
             * most efficient way to do this. However, this has the side
             * effect of scrubbing invalid output.
             */
            gchar *tty_out;

            tty_out = g_convert_with_fallback(line, -1, output->to_codeset, "UTF-8", "?", NULL, NULL, NULL);

            if (tty_out) {
#ifdef _WIN32
                /*
                 * We mapped to little-endian UTF-16, so write to the
                 * console using the Unicode API.
                 */
                DWORD out_len = (DWORD) wcslen((wchar_t *) tty_out);
                WriteConsoleW((HANDLE)_get_osfhandle(_fileno(output->fh)), tty_out, out_len, &out_len, NULL);
#else
                fputs(tty_out, output->fh);
#endif
                g_free(tty_out);
            } else {
                fputs(line, output->fh);
            }
        } else {
            /*
             * Either we're not writing to a terminal/console or we are
             * but we're just writing UTF-8 there.
             */
            fputs(line, output->fh);
        }


        if (emit_color) {
            switch (output->color_type) {

            case COLOR_NONE:
                putc('\n', output->fh);
                break;

#ifdef _WIN32
            case COLOR_CONSOLE:
                do_color_eol_console(self);
                break;
#endif

            case COLOR_24BIT_ESCAPE:
                do_color_eol_24bit_escape(self);
                break;
            }
        } else
            putc('\n', output->fh);
    }

    return !ferror(output->fh);
}

static gboolean
print_line_text(print_stream_t *self, int indent, const char *line)
{
    return print_line_color_text(self, indent, line, NULL, NULL);
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

    switch (output->color_type) {

    case COLOR_NONE:
        break;

#ifdef _WIN32
    case COLOR_CONSOLE:
        /* Restore the default text attribute. */
        SetConsoleTextAttribute((HANDLE)_get_osfhandle(_fileno(output->fh)), output->csb_attrs);
        break;
#endif

    case COLOR_24BIT_ESCAPE:
        /* Reset the color to the default */
        fprintf(output->fh, "%s", TERM_SGR_RESET);
        fflush(output->fh);

#ifdef _WIN32
        /*
         * Restore the console mode before we changed it.
         * We must do that *after* sending escape sequences,
         * as this may disable escape sequence processing.
         */
        SetConsoleMode((HANDLE)_get_osfhandle(_fileno(output->fh)), output->console_mode);
#endif
        break;
    }

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
    destroy_text,
    print_line_color_text,
};

static print_stream_t *
print_stream_text_alloc(gboolean to_file, FILE *fh)
{
    print_stream_t *stream;
    output_text    *output;

    output          = (output_text *)g_malloc(sizeof *output);
    output->to_file = to_file;
    output->fh      = fh;

#ifdef _WIN32
    /*
     * On Windows, "_isatty()", which is what ws_isatty() wraps,
     * "determines whether fd is associated with a character device
     * (a terminal, console, printer, or serial port)".
     *
     * We specifically want to know if it's assciated with a *console*,
     * as, if it is, we'll be using console-specific APIs.
     */
    CONSOLE_SCREEN_BUFFER_INFO csb_info;
    DWORD console_mode;

    if (GetConsoleScreenBufferInfo((HANDLE)_get_osfhandle(_fileno(fh)),
        &csb_info)) {
        /*
         * The console-specific API GetConsoleScreenBufferInfo() succeeded,
         * so we'll assume this is a console.
         */
        output->isatty = TRUE;
        output->csb_attrs = csb_info.wAttributes;

        /*
         * Map to little-endian UTF-16; we'll be doing Unicode-API
         * writes to the console, and that expects the standard flavor
         * of Unicode on Windows, which is little-endian UTF-16.
         */
        output->to_codeset = "UTF-16LE";

        /*
         * As indicated above, the classic Windows Console only offers
         * 1-bit color, set through special console APIs.
         *
         * The console in Windows 10 version 1511 (TH2), build 10586, and
         * later supports SGR escape sequences:
         *
         *  http://www.nivot.org/blog/post/2016/02/04/Windows-10-TH2-(v1511)-Console-Host-Enhancements
         *
         * but only supports 16 colors.  The "undocumented" 0x04 bit to
         * which they refer is documented in the current version of the
         * SetConsoleMode() documentation:
         *
         *   https://docs.microsoft.com/en-us/windows/console/setconsolemode
         *
         * as ENABLE_VIRTUAL_TERMINAL_PROCESSING, saying
         *
         *   When writing with WriteFile or WriteConsole, characters are
         *   parsed for VT100 and similar control character sequences that
         *   control cursor movement, color/font mode, and other operations
         *   that can also be performed via the existing Console APIs. For
         *   more information, see Console Virtual Terminal Sequences.
         *
         * Console Virtual Terminal Sequences:
         *
         *   https://docs.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences
         *
         * documents all the escape sequences the Console supports.  It
         * currently seems to indicate that the ODA versions with 24-bit
         * color are supported but select the closest color from the
         * 16-color palette.
         *
         * The console in Windows 10 builds 14931 (a preview version of
         * Windows 10 version 1703) and later supports SGR RGB sequences:
         *
         *   https://devblogs.microsoft.com/commandline/24-bit-color-in-the-windows-console/
         *
         * That page says:
         *
         *   Thanks to our ability to run Linux apps and scripts using our
         *   new Bash on Ubuntu on Windows environment atop the Windows
         *   Subsystem for Linux (WSL), we can use some Linux scripts and
         *   tools to demonstrate the Console's new 24-bit color support:
         *
         * which suggests that, with that version, whatever escape sequences
         * work on UN*Xes also work on Windows, so maybe they support full
         * 24-bit color with the ODA sequences.
         *
         * So, if ENABLE_VIRTUAL_TERMINAL_PROCESSING is already set on
         * the console, or if it isn't but we can set it, we use the SGR
         * sequences to set colors, otherwise, we just use the
         * SetConsoleTextAttribute calls.
         */
        GetConsoleMode((HANDLE)_get_osfhandle(_fileno(fh)), &output->console_mode);
        if (output->console_mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) {
            /*
             * It's already enabled; assume that means we can use the
             * 24-bit color escape sequences (although the console might
             * not support full 24-bit color, and would map the 24-bit
             * color to the closest color in a smaller palette).
             */
            output->color_type = COLOR_24BIT_ESCAPE;
        } else {
            /*
             * See if we can enable it.
             */
            console_mode = output->console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING;
            if (!SetConsoleMode((HANDLE)_get_osfhandle(_fileno(fh)), console_mode)) {
                /*
                 * We can't - use console-mode color.
                 *
                 * It's not documented which error is returned if
                 * you try to set a mode bit that's not supported,
                 * but, at least on Windows 7, ERROR_INVALID_PARAMETER
                 * is returned if you try to set
                 * ENABLE_VIRTUAL_TERMINAL_PROCESSING.
                 *
                 * We could check for that error and report other
                 * errors as failures.
                 */
                output->color_type = COLOR_CONSOLE;
            } else {
                /* We can - use 24-bit color */
                output->color_type = COLOR_24BIT_ESCAPE;
            }
        }
    } else {
        /*
         * GetConsoleScreenBufferInfo() failed; it's not documented
         * whether a particular error means "not a console", so we'll
         * just assume this means it's not a console.
         *
         * The error we see on Windows 7 is ERROR_INVALID_HANDLE, but
         * "invalid" is vague enough that I'm not sure we should
         * treat that as meaning "not a console and everything else
         * as being an error that we should report.
         */
        output->isatty = FALSE;

        /*
         * This is not used if we're not on a console, as we're not doing
         * coloring.
         */
        output->csb_attrs = 0;
    }
#else
    /*
     * On UN*X, isatty() tests "whether fildes, an open file descriptor,
     * is associated with a terminal device", to quote the Single UNIX
     * Specification, and the documentation for UN*Xes that haven't
     * been tested against the SUS validation suite say similar things.
     * It does *not* just test whether it's associated with a character
     * device that may or may not be a terminal device, so it's what we
     * want on UN*X.
     */
    output->isatty = isatty(ws_fileno(fh));
    if (output->isatty) {
        const gchar *charset;
        gboolean is_utf8;

        /* Is there a more reliable way to do this? */
        is_utf8 = g_get_charset(&charset);
        if (!is_utf8) {
            /*
             * The local character set isn't UTF-8, so arrange to
             * map from UTF-8 to that character set before printing
             * on the terminal.
             */
            output->to_codeset = charset;
        } else {
            /*
             * The local character set is UTF-8, so no mapping is
             * necessary.
             */
            output->to_codeset = NULL;
        }

        /*
         * Not all UN*X terminal emulators support the 24-bit color SGR
         * sequences (for example, macOS Terminal currently doesn't).
         *
         * As per
         *
         *    https://github.com/termstandard/colors
         *
         * terminfo currently doesn't have a flag to indicate 24-bit
         * color support - a future release will - so we can't use
         * that to determine if the terminal emulator (or terminal)
         * supports it.
         *
         * That page notes that some terminal emulators set the
         * COLORTERM environment variable either to "truecolor"
         * or "24bit" if 24-bit color is supported; we use that
         * test for now.
         *
         * XXX - if there are terminal emulators that use the 24-bit
         * color escape sequences but don't set COLORTERM, add code
         * here to look at other environment variables to try to
         * recognize them.
         *
         * XXX - fall back on 8-color or 256-color support if we can
         * somehow determine that 24-bit color support isn't available
         * but 8-color or 256-color support is?
         */
        char *colorterm = getenv("COLORTERM");
        if (colorterm != NULL &&
            (strcmp(colorterm, "truecolor") == 0 || strcmp(colorterm, "24bit") == 0))
            output->color_type = COLOR_24BIT_ESCAPE;
        else
            output->color_type = COLOR_NONE;
    }
#endif
    if (!output->isatty) {
        /*
         * OK, this was determined *not* to be a terminal, so we won't
         * be doing coloring or mapping from UTF-8 to a local character
         * set.
         */
        output->to_codeset = NULL;
        output->color_type = COLOR_NONE;
    }

    stream          = (print_stream_t *)g_malloc(sizeof (print_stream_t));
    stream->ops     = &print_text_ops;
    stream->data    = output;

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
    destroy_ps,
    NULL, /* print_line_color */
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
