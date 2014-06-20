/* Reorder the frames from an input dump file, and write to output dump file.
 * Martin Mathieson and Jakub Jawadzki
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

#include "version.h"

static void
print_version(FILE *output)
{
  fprintf(output, "Reordercap %s"
#ifdef GITVERSION
      " (" GITVERSION " from " GITBRANCH ")"
#endif
      "\n", VERSION);
}

/* Show command-line usage */
static void
usage(gboolean is_error)
{
    FILE *output;

    if (!is_error) {
        output = stdout;
    }
    else {
        output = stderr;
    }

    print_version(output);
    fprintf(output, "Reorder timestamps of input file frames into output file.\n");
    fprintf(output, "See http://www.wireshark.org for more information.\n");
    fprintf(output, "\n");
    fprintf(output, "Usage: reordercap [options] <infile> <outfile>\n");
    fprintf(output, "\n");
    fprintf(output, "Options:\n");
    fprintf(output, "  -n        don't write to output file if the input file is ordered.\n");
    fprintf(output, "  -h        display this help and exit.\n");
}

/* Remember where this frame was in the file */
typedef struct FrameRecord_t {
    gint64       offset;
    guint        num;

    nstime_t     time;
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
frame_write(FrameRecord_t *frame, wtap *wth, wtap_dumper *pdh, Buffer *buf,
            const char *infile)
{
    int    err;
    gchar  *err_info;
    struct wtap_pkthdr phdr;

    memset(&phdr, 0, sizeof(struct wtap_pkthdr));

    DEBUG_PRINT("\nDumping frame (offset=%" G_GINT64_MODIFIER "u)\n",
                frame->offset);


    /* Re-read the first frame from the stored location */
    if (!wtap_seek_read(wth, frame->offset, &phdr, buf, &err, &err_info)) {
        if (err != 0) {
            /* Print a message noting that the read failed somewhere along the line. */
            fprintf(stderr,
                    "reordercap: An error occurred while re-reading \"%s\": %s.\n",
                    infile, wtap_strerror(err));
            switch (err) {

            case WTAP_ERR_UNSUPPORTED:
            case WTAP_ERR_UNSUPPORTED_ENCAP:
            case WTAP_ERR_BAD_FILE:
                fprintf(stderr, "(%s)\n", err_info);
                g_free(err_info);
                break;
            }
            exit(1);
        }
    }

    /* Copy, and set length and timestamp from item. */
    /* TODO: remove when wtap_seek_read() will read phdr */
    phdr.ts = frame->time;

    /* Dump frame to outfile */
    if (!wtap_dump(pdh, &phdr, buffer_start_ptr(buf), &err)) {
        fprintf(stderr, "reordercap: Error (%s) writing frame to outfile\n",
                wtap_strerror(err));
        exit(1);
    }
}

/* Comparing timestamps between 2 frames.
   negative if (t1 < t2)
   zero     if (t1 == t2)
   positive if (t1 > t2)
*/
static int
frames_compare(gconstpointer a, gconstpointer b)
{
    const FrameRecord_t *frame1 = *(const FrameRecord_t *const *) a;
    const FrameRecord_t *frame2 = *(const FrameRecord_t *const *) b;

    const nstime_t *time1 = &frame1->time;
    const nstime_t *time2 = &frame2->time;

    return nstime_cmp(time1, time2);
}


/********************************************************************/
/* Main function.                                                   */
/********************************************************************/
int
main(int argc, char *argv[])
{
    wtap *wth = NULL;
    wtap_dumper *pdh = NULL;
    Buffer buf;
    int err;
    gchar *err_info;
    gint64 data_offset;
    const struct wtap_pkthdr *phdr;
    guint wrong_order_count = 0;
    gboolean write_output_regardless = TRUE;
    guint i;
    wtapng_section_t            *shb_hdr;
    wtapng_iface_descriptions_t *idb_inf;

    GPtrArray *frames;
    FrameRecord_t *prevFrame = NULL;

    int opt;
    int file_count;
    char *infile;
    char *outfile;

    /* Process the options first */
    while ((opt = getopt(argc, argv, "hnv")) != -1) {
        switch (opt) {
            case 'n':
                write_output_regardless = FALSE;
                break;
            case 'h':
                usage(FALSE);
                exit(0);
            case 'v':
                print_version(stdout);
                exit(0);
            case '?':
                usage(TRUE);
                exit(1);
        }
    }

    /* Remaining args are file names */
    file_count = argc - optind;
    if (file_count == 2) {
        infile  = argv[optind];
        outfile = argv[optind+1];
    }
    else {
        usage(TRUE);
        exit(1);
    }

    /* Open infile */
    /* TODO: if reordercap is ever changed to give the user a choice of which
       open_routine reader to use, then the following needs to change. */
    wth = wtap_open_offline(infile, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (wth == NULL) {
        fprintf(stderr, "reordercap: Can't open %s: %s\n", infile,
                wtap_strerror(err));
        switch (err) {

        case WTAP_ERR_UNSUPPORTED:
        case WTAP_ERR_UNSUPPORTED_ENCAP:
        case WTAP_ERR_BAD_FILE:
            fprintf(stderr, "(%s)\n", err_info);
            g_free(err_info);
            break;
        }
        exit(1);
    }
    DEBUG_PRINT("file_type_subtype is %u\n", wtap_file_type_subtype(wth));

    shb_hdr = wtap_file_get_shb_info(wth);
    idb_inf = wtap_file_get_idb_info(wth);

    /* Open outfile (same filetype/encap as input file) */
    pdh = wtap_dump_open_ng(outfile, wtap_file_type_subtype(wth), wtap_file_encap(wth),
                            65535, FALSE, shb_hdr, idb_inf, &err);
    g_free(idb_inf);
    if (pdh == NULL) {
        fprintf(stderr, "reordercap: Failed to open output file: (%s) - error %s\n",
                outfile, wtap_strerror(err));
        g_free(shb_hdr);
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
        if (phdr->presence_flags & WTAP_HAS_TS) {
            newFrameRecord->time = phdr->ts;
        } else {
            nstime_set_unset(&newFrameRecord->time);
        }

        if (prevFrame && frames_compare(&newFrameRecord, &prevFrame) < 0) {
           wrong_order_count++;
        }

        g_ptr_array_add(frames, newFrameRecord);
        prevFrame = newFrameRecord;
    }
    if (err != 0) {
      /* Print a message noting that the read failed somewhere along the line. */
      fprintf(stderr,
              "reordercap: An error occurred while reading \"%s\": %s.\n",
              infile, wtap_strerror(err));
      switch (err) {

      case WTAP_ERR_UNSUPPORTED:
      case WTAP_ERR_UNSUPPORTED_ENCAP:
      case WTAP_ERR_BAD_FILE:
          fprintf(stderr, "(%s)\n", err_info);
          g_free(err_info);
          break;
      }
    }

    printf("%u frames, %u out of order\n", frames->len, wrong_order_count);

    /* Sort the frames */
    if (wrong_order_count > 0) {
        g_ptr_array_sort(frames, frames_compare);
    }

    /* Write out each sorted frame in turn */
    buffer_init(&buf, 1500);
    for (i = 0; i < frames->len; i++) {
        FrameRecord_t *frame = (FrameRecord_t *)frames->pdata[i];

        /* Avoid writing if already sorted and configured to */
        if (write_output_regardless || (wrong_order_count > 0)) {
            frame_write(frame, wth, pdh, &buf, infile);
        }
        g_slice_free(FrameRecord_t, frame);
    }
    buffer_free(&buf);

    if (!write_output_regardless && (wrong_order_count == 0)) {
        printf("Not writing output file because input file is already in order!\n");
    }

    /* Free the whole array */
    g_ptr_array_free(frames, TRUE);

    /* Close outfile */
    if (!wtap_dump_close(pdh, &err)) {
        fprintf(stderr, "reordercap: Error closing %s: %s\n", outfile,
                wtap_strerror(err));
        g_free(shb_hdr);
        exit(1);
    }
    g_free(shb_hdr);

    /* Finally, close infile */
    wtap_fdclose(wth);

    return 0;
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
