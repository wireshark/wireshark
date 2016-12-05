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

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <wiretap/wtap.h>

#ifndef HAVE_GETOPT_LONG
#include "wsutil/wsgetopt.h"
#endif

#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <ws_version_info.h>
#include <wiretap/wtap_opttypes.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_err.h>

/* Show command-line usage */
static void
print_usage(FILE *output)
{
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

    nstime_t     frame_time;
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
frame_write(FrameRecord_t *frame, wtap *wth, wtap_dumper *pdh,
            struct wtap_pkthdr *phdr, Buffer *buf, const char *infile)
{
    int    err;
    gchar  *err_info;

    DEBUG_PRINT("\nDumping frame (offset=%" G_GINT64_MODIFIER "u)\n",
                frame->offset);


    /* Re-read the frame from the stored location */
    if (!wtap_seek_read(wth, frame->offset, phdr, buf, &err, &err_info)) {
        if (err != 0) {
            /* Print a message noting that the read failed somewhere along the line. */
            fprintf(stderr,
                    "reordercap: An error occurred while re-reading \"%s\": %s.\n",
                    infile, wtap_strerror(err));
            if (err_info != NULL) {
                fprintf(stderr, "(%s)\n", err_info);
                g_free(err_info);
            }
            exit(1);
        }
    }

    /* Copy, and set length and timestamp from item. */
    /* TODO: remove when wtap_seek_read() fills in phdr,
       including time stamps, for all file types  */
    phdr->ts = frame->frame_time;

    /* Dump frame to outfile */
    if (!wtap_dump(pdh, phdr, ws_buffer_start_ptr(buf), &err, &err_info)) {
        fprintf(stderr, "reordercap: Error (%s) writing frame to outfile\n",
                wtap_strerror(err));
        if (err_info != NULL) {
            fprintf(stderr, "(%s)\n", err_info);
            g_free(err_info);
        }
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

    const nstime_t *time1 = &frame1->frame_time;
    const nstime_t *time2 = &frame2->frame_time;

    return nstime_cmp(time1, time2);
}

#ifdef HAVE_PLUGINS
/*
 *  Don't report failures to load plugins because most (non-wiretap) plugins
 *  *should* fail to load (because we're not linked against libwireshark and
 *  dissector plugins need libwireshark).
 */
static void
failure_message(const char *msg_format _U_, va_list ap _U_)
{
    return;
}
#endif

/********************************************************************/
/* Main function.                                                   */
/********************************************************************/
int
main(int argc, char *argv[])
{
    GString *comp_info_str;
    GString *runtime_info_str;
    char *init_progfile_dir_error;
    wtap *wth = NULL;
    wtap_dumper *pdh = NULL;
    struct wtap_pkthdr dump_phdr;
    Buffer buf;
    int err;
    gchar *err_info;
    gint64 data_offset;
    const struct wtap_pkthdr *phdr;
    guint wrong_order_count = 0;
    gboolean write_output_regardless = TRUE;
    guint i;
    GArray                      *shb_hdrs = NULL;
    wtapng_iface_descriptions_t *idb_inf = NULL;
    GArray                      *nrb_hdrs = NULL;

    GPtrArray *frames;
    FrameRecord_t *prevFrame = NULL;

    int opt;
    static const struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {0, 0, 0, 0 }
    };
    int file_count;
    char *infile;
    const char *outfile;

    /* Get the compile-time version information string */
    comp_info_str = get_compiled_version_info(NULL, NULL);

    /* Get the run-time version information string */
    runtime_info_str = get_runtime_version_info(NULL);

    /* Add it to the information to be reported on a crash. */
    ws_add_crash_info("Reordercap (Wireshark) %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    init_progfile_dir_error = init_progfile_dir(argv[0], main);
    if (init_progfile_dir_error != NULL) {
        fprintf(stderr,
                "reordercap: Can't get pathname of directory containing the reordercap program: %s.\n",
                init_progfile_dir_error);
        g_free(init_progfile_dir_error);
    }

    wtap_init();

#ifdef HAVE_PLUGINS
    /* Register wiretap plugins */
    init_report_err(failure_message,NULL,NULL,NULL);

    /* Scan for plugins.  This does *not* call their registration routines;
        that's done later. */
    scan_plugins();

    /* Register all libwiretap plugin modules. */
    register_all_wiretap_modules();
#endif

    /* Process the options first */
    while ((opt = getopt_long(argc, argv, "hnv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'n':
                write_output_regardless = FALSE;
                break;
            case 'h':
                printf("Reordercap (Wireshark) %s\n"
                       "Reorder timestamps of input file frames into output file.\n"
                       "See https://www.wireshark.org for more information.\n",
                       get_ws_vcs_version_info());
                print_usage(stdout);
                exit(0);
            case 'v':
                show_version("Reordercap (Wireshark)", comp_info_str, runtime_info_str);
                g_string_free(comp_info_str, TRUE);
                g_string_free(runtime_info_str, TRUE);
                exit(0);
            case '?':
                print_usage(stderr);
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
        print_usage(stderr);
        exit(1);
    }

    /* Open infile */
    /* TODO: if reordercap is ever changed to give the user a choice of which
       open_routine reader to use, then the following needs to change. */
    wth = wtap_open_offline(infile, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (wth == NULL) {
        fprintf(stderr, "reordercap: Can't open %s: %s\n", infile,
                wtap_strerror(err));
        if (err_info != NULL) {
            fprintf(stderr, "(%s)\n", err_info);
            g_free(err_info);
        }
        exit(1);
    }
    DEBUG_PRINT("file_type_subtype is %d\n", wtap_file_type_subtype(wth));

    shb_hdrs = wtap_file_get_shb_for_new_file(wth);
    idb_inf = wtap_file_get_idb_info(wth);
    nrb_hdrs = wtap_file_get_nrb_for_new_file(wth);

    /* Open outfile (same filetype/encap as input file) */
    if (strcmp(outfile, "-") == 0) {
      pdh = wtap_dump_open_stdout_ng(wtap_file_type_subtype(wth), wtap_file_encap(wth),
                                     65535, FALSE, shb_hdrs, idb_inf, nrb_hdrs, &err);
      outfile = "standard output";
    } else {
      pdh = wtap_dump_open_ng(outfile, wtap_file_type_subtype(wth), wtap_file_encap(wth),
                              65535, FALSE, shb_hdrs, idb_inf, nrb_hdrs, &err);
    }
    g_free(idb_inf);
    idb_inf = NULL;

    if (pdh == NULL) {
        fprintf(stderr, "reordercap: Failed to open output file: (%s) - error %s\n",
                outfile, wtap_strerror(err));
        wtap_block_array_free(shb_hdrs);
        wtap_block_array_free(nrb_hdrs);
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
            newFrameRecord->frame_time = phdr->ts;
        } else {
            nstime_set_unset(&newFrameRecord->frame_time);
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
      if (err_info != NULL) {
          fprintf(stderr, "(%s)\n", err_info);
          g_free(err_info);
      }
    }

    printf("%u frames, %u out of order\n", frames->len, wrong_order_count);

    /* Sort the frames */
    if (wrong_order_count > 0) {
        g_ptr_array_sort(frames, frames_compare);
    }

    /* Write out each sorted frame in turn */
    wtap_phdr_init(&dump_phdr);
    ws_buffer_init(&buf, 1500);
    for (i = 0; i < frames->len; i++) {
        FrameRecord_t *frame = (FrameRecord_t *)frames->pdata[i];

        /* Avoid writing if already sorted and configured to */
        if (write_output_regardless || (wrong_order_count > 0)) {
            frame_write(frame, wth, pdh, &dump_phdr, &buf, infile);
        }
        g_slice_free(FrameRecord_t, frame);
    }
    wtap_phdr_cleanup(&dump_phdr);
    ws_buffer_free(&buf);

    if (!write_output_regardless && (wrong_order_count == 0)) {
        printf("Not writing output file because input file is already in order!\n");
    }

    /* Free the whole array */
    g_ptr_array_free(frames, TRUE);

    /* Close outfile */
    if (!wtap_dump_close(pdh, &err)) {
        fprintf(stderr, "reordercap: Error closing %s: %s\n", outfile,
                wtap_strerror(err));
        wtap_block_array_free(shb_hdrs);
        wtap_block_array_free(nrb_hdrs);
        exit(1);
    }
    wtap_block_array_free(shb_hdrs);
    wtap_block_array_free(nrb_hdrs);

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
