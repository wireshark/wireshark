/* print_win32.c
 * Printing support for MSWindows
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002, Jeffrey C. Foster <jfoste@woodward.com>
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
 *
 *
 * This original code was from the Technet Article Q139652 :
 * HOWTO: Print a Document
 * You can now find it at http://support.microsoft.com/kb/139652
 */

#include <string.h>
#include <stdio.h>

#include <windows.h>
#include <commdlg.h>

#include <winspool.h>

#include "print_win32.h"
#include "wsutil/file_util.h"
/*
Some thoughts about a GTK win32 printer dialog:

"EnumPrinters()", asking for information level 2 - the PRINTER_INFO_2
structure contains a pLocation string pointer, along with other
information.

"PrinterProperties", could be used to show a native printer property page?!?

See

    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/gdi/prntspol_62ia.asp

for information on printer APIs.

*/
static BOOL CALLBACK abort_proc(HDC hDC, int Error);
static HDC get_printer_dc(short *width, short *height);
static void init_doc_struct(DOCINFO* di, char* docname);
static void print_file(const char* file_name, HDC hdc, int width, int height);

void print_mswin(const char *file_name)
{
    HDC     hDC;
    DOCINFO di;
    short int width, height;

    HWND hWndParent = HWND_DESKTOP; /* would be better to be a real window */

    /* Need a printer DC to print to. */
    hDC = get_printer_dc(&width, &height);

    /* Did you get a good DC?, Cancel will return NULL also, so what to do? */
    if (!hDC) {
        return;
    }

    /* You always have to use an AbortProc(). */
    if (SetAbortProc(hDC, abort_proc) == SP_ERROR) {
        MessageBox(NULL, "Error setting up AbortProc",
                   "Error", MB_APPLMODAL | MB_OK);
        return;
    }

    /* Init the DOCINFO and start the document. */
    init_doc_struct(&di, "MyDoc");
    StartDoc(hDC, &di);

    /* Print one page. */
    StartPage(hDC);
    print_file(file_name, hDC, width, height);
    EndPage(hDC);

    /* Indicate end of document. */
    EndDoc(hDC);

    /* Clean up */
    DeleteDC(hDC);
}

/* Obtain printer device context */
static HDC get_printer_dc(short *width, short *height)
{
    PRINTDLG pdlg;
    PDEVMODE returnedDevmode;

    /*
     * XXX - can this be done without a Windows print dialog?
     *
     * "CreateDC()" creates a device context, and you can
     * apparently specify WINSPL16 as the driver name on
     * Windows OT, or the name of a "print provider", such as
     * "WINSPOOL" on Windows NT, to get a context for a printer.
     *
     * The device name would be the printer name as shown by the
     * Print Manager; is there a way to enumerate those?
     */

    /* Initialize the PRINTDLG structure. */
    memset(&pdlg, 0, sizeof(PRINTDLG));
    pdlg.lStructSize = sizeof(PRINTDLG);
    /* Set the flag to return printer DC. */
    pdlg.Flags =
        PD_RETURNDC |           /* return the device context we need */
        PD_NOPAGENUMS |         /* disable the "Pages" radio button */
        PD_NOSELECTION |        /* disable the "Selection" radio button */
        PD_USEDEVMODECOPIESANDCOLLATE;  /* let device print multiple pages */

    /* Invoke the printer dialog box. */
    if (PrintDlg(&pdlg)) {
        /* http://msdn.microsoft.com/en-us/library/windows/desktop/dd162931%28v=vs.85%29.aspx */
        returnedDevmode = (PDEVMODE)GlobalLock(pdlg.hDevMode);

        if (returnedDevmode == NULL) {
            if (pdlg.hDevMode)
                GlobalFree(pdlg.hDevMode);
            if (pdlg.hDevNames)
                GlobalFree(pdlg.hDevNames);
            return NULL;
        }

        if (returnedDevmode->dmOrientation == DMORIENT_LANDSCAPE) {
            *width = returnedDevmode->dmPaperLength;
            *height = returnedDevmode->dmPaperWidth;
        }
        else {  /* assume DMORIENT_PORTRAIT */
            *width = returnedDevmode->dmPaperWidth;
            *height = returnedDevmode->dmPaperLength;
        }

        GlobalUnlock(pdlg.hDevMode);

        if (pdlg.hDevMode)
            GlobalFree(pdlg.hDevMode);
        if (pdlg.hDevNames)
            GlobalFree(pdlg.hDevNames);
    }

    /* hDC member of the PRINTDLG structure contains the printer DC. */
    return pdlg.hDC;
}

/* The Abort Procedure */
static BOOL CALLBACK abort_proc(HDC hDC, int Error)
{
    MSG   msg;
    while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    return TRUE;
}

/* Initialize DOCINFO structure */
static void init_doc_struct(DOCINFO* di, char* docname)
{
    /* Always zero it before using it. */
    memset(di, 0, sizeof(DOCINFO));
    /* Fill in the required members. */
    di->cbSize = sizeof(DOCINFO);
    di->lpszDocName = docname;
}

/* Drawing on the DC */
static void print_file(const char *file_name, HDC hdc, int width, int height)
{
    #define MAX_BUF_SIZE 1024   /* An arbitrary maximum */
    #define X_OFFSET 5
    #define Y_OFFSET 5

    FILE* fh1;
    size_t results;
    int cnt=0, y_pos = Y_OFFSET, y_cnt = 0;
    char buf[MAX_BUF_SIZE];
    char ch;
    TEXTMETRIC tm;
    int max_chars_per_line, max_lines_per_page;

    SetMapMode(hdc, MM_LOMETRIC);
    GetTextMetrics(hdc, &tm);
    max_chars_per_line = MIN(width / (tm.tmMaxCharWidth + 1), MAX_BUF_SIZE);
    max_lines_per_page = height / (tm.tmHeight + 1);

    SetMapMode(hdc, MM_TEXT);
    GetTextMetrics(hdc, &tm);

    fh1 = ws_fopen(file_name, "r");
    if (!fh1) {
        MessageBox(NULL, "Open failed on input file",
                   "Error", MB_APPLMODAL | MB_OK);
        return;
    }

    while ((results = fread(&ch, 1, 1, fh1)) != 0) {
        /* end of page (form feed)? */
        if (ch == 0x0c) {
            /* send buffer */
            buf[cnt] = 0;
            TextOut(hdc, X_OFFSET,y_pos, buf, (int) strlen(buf));
            y_pos += tm.tmHeight;
            cnt = 0;

            /* reset page */
            EndPage(hdc);
            StartPage(hdc);
            y_pos = Y_OFFSET;
            y_cnt = 0;
            continue;
        }

        /* end of line (line feed)? */
        if (ch == 0x0a) {
            /* send buffer */
            buf[cnt] = 0;
            TextOut(hdc, X_OFFSET,y_pos, buf, (int) strlen(buf));
            y_pos += tm.tmHeight;
            cnt = 0;
            /* last line on page? -> reset page */
            if (++y_cnt == max_lines_per_page) {
                EndPage(hdc);
                StartPage(hdc);
                y_pos = Y_OFFSET;
                y_cnt = 0;
            }
            continue;
        }

        /* buffer full? */
        if (cnt == (max_chars_per_line - 1)) {
            /* send buffer */
            buf[cnt] = 0;
            TextOut(hdc, X_OFFSET, y_pos, buf, (int) strlen(buf));
            y_pos += tm.tmHeight;
            cnt = 0;
            /* last line on page? -> reset page */
            if (++y_cnt == max_lines_per_page) {
                EndPage(hdc);
                StartPage(hdc);
                y_pos = Y_OFFSET;
                y_cnt = 0;
            }
        }

        buf[cnt++] = ch;
    } /* while */

    /* Print the remaining text if needed */
    if (cnt > 0) {
        buf[cnt] = 0;
        TextOut(hdc, 0,y_pos, buf, (int) strlen(buf));
    }

    fclose(fh1);
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

