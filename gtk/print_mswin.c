/* print_mswin.c
 * Printing support for MSWindows
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * This original code was from the Technet Article Q139652 :
 *	 HOWTO: Print a Document
 */


#include <string.h>
#include <stdio.h>

#include <windows.h>
#include <commdlg.h>

#ifdef __WIN32__
#include <winspool.h>
#endif

#include "print_mswin.h"

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
BOOL CALLBACK abort_proc( HDC hDC, int Error );
HDC get_printer_dc(void);
void init_doc_struct( DOCINFO* di, char* docname);
void print_file( char* file_name, HDC hdc);

void print_mswin(char *file_name)

   {
       HDC        hDC;
       DOCINFO    di;

	HWND hWndParent = HWND_DESKTOP;	/* would be better to be a real window */

       /* Need a printer DC to print to. */
       hDC = get_printer_dc();

       /* Did you get a good DC?, Cancel will return NULL also, so what to do? */
       if( !hDC)
       {
           return;
       }

       /* You always have to use an AbortProc(). */
       if( SetAbortProc( hDC, abort_proc ) == SP_ERROR )
       {
           MessageBox( NULL, "Error setting up AbortProc",
                                       "Error", MB_APPLMODAL | MB_OK);
           return;
       }

       /* Init the DOCINFO and start the document. */
       init_doc_struct( &di, "MyDoc");
       StartDoc( hDC, &di );

       /* Print one page. */
       StartPage( hDC );
       print_file(file_name, hDC );
       EndPage( hDC );

       /* Indicate end of document. */
       EndDoc( hDC );

       /* Clean up */
       DeleteDC( hDC );
   }

   /*===============================*/
   /* Obtain printer device context */
   /* ==============================*/
   HDC get_printer_dc(void)
   {
       PRINTDLG pdlg;

       /*
        * XXX - can this be done without a Windows print dialog?
        *
        * "CreateDC()" creates a device context, and you can
        * apparently specify WINSPL16 as the driver name on
        * Windows OT, or ther name of a "print provider", such as
        * "WINSPOOL" on Windows NT, to get a context for a printer.
        *
        * The device name would be the printer name as shown by the
        * Print Manager; is there a way to enumerate those?
        */

       /* Initialize the PRINTDLG structure. */
       memset( &pdlg, 0, sizeof( PRINTDLG ) );
       pdlg.lStructSize = sizeof( PRINTDLG );
       /* Set the flag to return printer DC. */
       pdlg.Flags =  
           /* return the device context we need */
           PD_RETURNDC |        
           /* disable the "Pages" radio button */
           PD_NOPAGENUMS |      
           /* disable the "Selection" radio button */
           PD_NOSELECTION |     
           /* let device print multiple pages (if requested) */
           PD_USEDEVMODECOPIESANDCOLLATE; 

       /* Invoke the printer dialog box. */
       PrintDlg( &pdlg );

       /* hDC member of the PRINTDLG structure contains the printer DC. */
       return pdlg.hDC;
   }

   /*===============================*/
   /* The Abort Procudure           */
   /* ==============================*/
   BOOL CALLBACK abort_proc( HDC hDC, int Error )
   {
       MSG   msg;
       while( PeekMessage( &msg, NULL, 0, 0, PM_REMOVE ) )
       {
           TranslateMessage( &msg );
           DispatchMessage( &msg );
       }
       return TRUE;
   }

   /*===============================*/
   /* Initialize DOCINFO structure  */
   /* ==============================*/
   void init_doc_struct( DOCINFO* di, char* docname)
   {
       /* Always zero it before using it. */
       memset( di, 0, sizeof( DOCINFO ) );
       /* Fill in the required members. */
       di->cbSize = sizeof( DOCINFO );
       di->lpszDocName = docname;
   }

   /*===============================*/
   /* Drawing on the DC             */
   /* ==============================*/
void print_file( char *file_name, HDC hdc) {

    #define max_buf_size 1024
    #define max_lines 66
    #define y_offset 5
    #define x_offset 5

    FILE* fh1;
    int results, cnt=0, y_pos = y_offset, y_cnt = 0;
    char buf[ max_buf_size];
    char ch;
    TEXTMETRIC tm;

    GetTextMetrics(hdc, &tm);
    SetMapMode (hdc, MM_TEXT);


    fh1 = fopen( file_name, "r" );
    if( !fh1 )
        perror( "open failed on input file" );

     else {
	while ((results = fread( &ch, 1, 1, fh1 )) != 0) {

/* if end of line send buffer and more y position */

	    if ( ch == 0x0a){
                buf[ cnt] = 0;
		TextOut(hdc, x_offset,y_pos, buf, strlen(buf));
		y_pos += tm.tmHeight;
		cnt = 0;
		if ( ++y_cnt == max_lines){
       /* Print one page. */
 		    EndPage( hdc );
		    StartPage( hdc );
		    y_pos = y_offset;
                    y_cnt = 0;
		}

/* if line buffer is full, dump it */
 	    }else { if ( cnt == ( max_buf_size - 1)) {
	        buf[ cnt] = 0;
                TextOut(hdc, x_offset, y_pos, buf, strlen(buf));
                y_pos += tm.tmHeight;
                cnt = 0;

 	        if ( ++y_cnt == max_lines){
       /* Print one page. */
 	            EndPage( hdc );
		    StartPage( hdc );
                    y_pos = y_offset;
		    y_cnt = 0;
	        }
	    }

	    buf[ cnt++] = ch;
        }
    }
/*XXX  need feof test here ? */

/* Print the last text if needed */
    if ( cnt > 0) {
	buf[ cnt] = 0;
	TextOut(hdc, 0,y_pos, buf, strlen(buf));
    }
    fclose(fh1);
}
}
