/* Reorder the frames from an input dump file, and write to output dump file.
 * Martin Mathieson and Jakub Jawadzki
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "wtap.h"

#ifndef HAVE_GETOPT
#include "wsutil/wsgetopt.h"
#endif

/* Show command-line usage */
static void usage(void)
{
    fprintf(stderr, "Reordercap %s"
#ifdef SVNVERSION
	  " (" SVNVERSION " from " SVNPATH ")"
#endif
	  "\n", VERSION);
    fprintf(stderr, "Reorder timestamps of input file frames into output file.\n");
    fprintf(stderr, "See http://www.wireshark.org for more information.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: reordercap [options] <infile> <outfile>\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -n        don't write to output file if the input file is ordered.\n");
}

/* Remember where this frame was in the file */
typedef struct FrameRecord_t {
    gint64               offset;
    guint32              length;
    guint                num;

    struct wtap_nstime   time;
} FrameRecord_t;


/**************************************************/
/* Debugging only                                 */

/* Enable this symbol to see debug output */
/* #define REORDER_DEBUG */

#ifdef REORDER_DEBUG
#define DEBUG_PRINT printf
#else
#define DEBUG_PRINT(...)
#endif
/**************************************************/


static void
frame_write(FrameRecord_t *frame, wtap *wth, wtap_dumper *pdh)
{
    union wtap_pseudo_header pseudo_header;
    int    err;
    gchar  *errinfo;
    const struct wtap_pkthdr *phdr;
    guint8 buf[65535];
    struct wtap_pkthdr new_phdr;

    DEBUG_PRINT("\nDumping frame (offset=%" G_GINT64_MODIFIER "u, length=%u)\n", 
                frame->offset, frame->length);

    /* Re-read the first frame from the stored location */
    wtap_seek_read(wth,
                   frame->offset,
                   &pseudo_header,
                   buf,
                   frame->length,
                   &err,
                   &errinfo);
    DEBUG_PRINT("re-read: err is %d, buf is (%s)\n", err, buf);

    /* Get packet header */
    /* XXX, this might not work */
    phdr = wtap_phdr(wth);

    /* Copy, and set length and timestamp from item. */
    new_phdr = *phdr;
    new_phdr.len = frame->length;
    new_phdr.caplen = frame->length;
    new_phdr.ts = frame->time;

    /* Dump frame to outfile */
    if (!wtap_dump(pdh, &new_phdr, &pseudo_header, buf, &err)) {
        printf("Error (%s) writing frame to outfile\n", wtap_strerror(err));
        exit(1);
    }
}

/* Comparing timestamps between 2 frames.
   -1 if (t1 < t2)
   0  if (t1 == t2)
   1  if (t1 > t2)
*/
static int
frames_compare(gconstpointer a, gconstpointer b)
{
    const FrameRecord_t *frame1 = *(const FrameRecord_t **) a;
    const FrameRecord_t *frame2 = *(const FrameRecord_t **) b;

    const struct wtap_nstime *time1 = &frame1->time;
    const struct wtap_nstime *time2 = &frame2->time;

    if (time1->secs > time2->secs)
        return 1;
    if (time1->secs < time2->secs)
        return -1;

    /* time1->secs == time2->secs */
    if (time1->nsecs > time2->nsecs)
        return 1;
    if (time1->nsecs < time2->nsecs)
        return -1;

    /* time1->nsecs == time2->nsecs */

    if (frame1->num > frame2->num)
        return 1;
    if (frame1->num < frame2->num)
        return -1;
    return 0;
}


/********************************************************************/
/* Main function.                                                   */
/********************************************************************/
int main(int argc, char *argv[])
{
    wtap *wth = NULL;
    wtap_dumper *pdh = NULL;
    int err;
    gchar *err_info;
    gint64 data_offset;
    const struct wtap_pkthdr *phdr;
    guint wrong_order_count = 0;
    gboolean write_output_regardless = TRUE;
    guint i;

    GPtrArray *frames;
    FrameRecord_t *prevFrame = NULL;

    int opt;
    int file_count;
    char *infile;
    char *outfile;

    /* Process the options first */
    while ((opt = getopt(argc, argv, "n")) != -1) {
        switch (opt) {
            case 'n':
                write_output_regardless = FALSE;
                break;
            case '?':
                usage();
                exit(1);
        }
    }

    /* Remaining args are file names */
    file_count = argc - optind;
    if (file_count == 2) {
        infile = argv[optind];
        outfile = argv[optind+1];
    }
    else {
        usage();
        exit(1);
    }

    /* Open infile */
    wth = wtap_open_offline(infile, &err, &err_info, TRUE);
    if (wth == NULL) {
        printf("reorder: Can't open %s: %s\n", infile, wtap_strerror(err));
        exit(1);
    }
    DEBUG_PRINT("file_type is %u\n", wtap_file_type(wth));

    /* Open outfile (same filetype/encap as input file) */
    pdh = wtap_dump_open(outfile, wtap_file_type(wth), wtap_file_encap(wth), 65535, FALSE, &err);
    if (pdh == NULL) {
        printf("Failed to open output file: (%s) - error %s\n", outfile, wtap_strerror(err));
        exit(1);
    }

    /* Allocate the array of frame pointers. */
    frames = g_ptr_array_new();

    /* Read each frame from infile */
    while (wtap_read(wth, &err, &err_info, &data_offset)) {
        FrameRecord_t *newFrameRecord;

        phdr = wtap_phdr(wth);

        newFrameRecord = g_slice_new(FrameRecord_t);
        newFrameRecord->num = frames->len + 1;
        newFrameRecord->offset = data_offset;
        newFrameRecord->length = phdr->len;
        newFrameRecord->time = phdr->ts;

        if (prevFrame && frames_compare(&newFrameRecord, &prevFrame) < 0) {
           wrong_order_count++;
        }

        g_ptr_array_add(frames, newFrameRecord);
        prevFrame = newFrameRecord;
    }
    printf("%u frames, %u out of order\n", frames->len, wrong_order_count);

    /* Sort the frames */
    if (wrong_order_count > 0) {
        g_ptr_array_sort(frames, frames_compare);
    }

    /* Write out each sorted frame in turn */
    for (i = 0; i < frames->len; i++) {
        FrameRecord_t *frame = frames->pdata[i];

        /* Avoid writing if already sorted and configured to */
        if (write_output_regardless || (wrong_order_count > 0)) {
            frame_write(frame, wth, pdh);
        }
        g_slice_free(FrameRecord_t, frame);
    }

    if (!write_output_regardless && (wrong_order_count == 0)) {
        printf("Not writing output file because input file is already in order!\n");
    }

    /* Free the whole array */
    g_ptr_array_free(frames, TRUE);

    /* Close outfile */
    if (!wtap_dump_close(pdh, &err)) {
        printf("Error closing %s: %s\n", outfile, wtap_strerror(err));
        exit(1);
    }

    /* Finally, close infile */
    wtap_fdclose(wth);

    return 0;
}

