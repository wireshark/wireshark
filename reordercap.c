/* Reorder the frames from an input dump file, and write to output dump file.
 * Martin Mathieson and Jakub Jawadzki
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <ui/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <cli_main.h>
#include <version_info.h>
#include <wiretap/wtap_opttypes.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>

#include "ui/failure_message.h"

#define INVALID_OPTION 1
#define OPEN_ERROR 2
#define OUTPUT_FILE_ERROR 1

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
            wtap_rec *rec, Buffer *buf, const char *infile,
            const char *outfile)
{
    int    err;
    gchar  *err_info;

    DEBUG_PRINT("\nDumping frame (offset=%" G_GINT64_MODIFIER "u)\n",
                frame->offset);


    /* Re-read the frame from the stored location */
    if (!wtap_seek_read(wth, frame->offset, rec, buf, &err, &err_info)) {
        if (err != 0) {
            /* Print a message noting that the read failed somewhere along the line. */
            fprintf(stderr,
                    "reordercap: An error occurred while re-reading \"%s\".\n",
                    infile);
            cfile_read_failure_message("reordercap", infile, err, err_info);
            exit(1);
        }
    }

    /* Copy, and set length and timestamp from item. */
    /* TODO: remove when wtap_seek_read() fills in rec,
       including time stamps, for all file types  */
    rec->ts = frame->frame_time;

    /* Dump frame to outfile */
    if (!wtap_dump(pdh, rec, ws_buffer_start_ptr(buf), &err, &err_info)) {
        cfile_write_failure_message("reordercap", infile, outfile, err,
                                    err_info, frame->num,
                                    wtap_file_type_subtype(wth));
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

/*
 * General errors and warnings are reported with an console message
 * in reordercap.
 */
static void
failure_warning_message(const char *msg_format, va_list ap)
{
    fprintf(stderr, "reordercap: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/********************************************************************/
/* Main function.                                                   */
/********************************************************************/
int
main(int argc, char *argv[])
{
    char *init_progfile_dir_error;
    wtap *wth = NULL;
    wtap_dumper *pdh = NULL;
    wtap_rec rec;
    Buffer buf;
    int err;
    gchar *err_info;
    gint64 data_offset;
    guint wrong_order_count = 0;
    gboolean write_output_regardless = TRUE;
    guint i;
    wtap_dump_params params;
    int                          ret = EXIT_SUCCESS;

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

    cmdarg_err_init(failure_warning_message, failure_message_cont);

    /* Initialize the version information. */
    ws_init_version_info("Reordercap (Wireshark)", NULL, NULL, NULL);

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    init_progfile_dir_error = init_progfile_dir(argv[0]);
    if (init_progfile_dir_error != NULL) {
        fprintf(stderr,
                "reordercap: Can't get pathname of directory containing the reordercap program: %s.\n",
                init_progfile_dir_error);
        g_free(init_progfile_dir_error);
    }

    init_report_message(failure_warning_message, failure_warning_message,
                        NULL, NULL, NULL);

    wtap_init(TRUE);

    /* Process the options first */
    while ((opt = getopt_long(argc, argv, "hnv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'n':
                write_output_regardless = FALSE;
                break;
            case 'h':
                show_help_header("Reorder timestamps of input file frames into output file.");
                print_usage(stdout);
                goto clean_exit;
            case 'v':
                show_version();
                goto clean_exit;
            case '?':
                print_usage(stderr);
                ret = INVALID_OPTION;
                goto clean_exit;
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
        ret = INVALID_OPTION;
        goto clean_exit;
    }

    /* Open infile */
    /* TODO: if reordercap is ever changed to give the user a choice of which
       open_routine reader to use, then the following needs to change. */
    wth = wtap_open_offline(infile, WTAP_TYPE_AUTO, &err, &err_info, TRUE);
    if (wth == NULL) {
        cfile_open_failure_message("reordercap", infile, err, err_info);
        ret = OPEN_ERROR;
        goto clean_exit;
    }
    DEBUG_PRINT("file_type_subtype is %d\n", wtap_file_type_subtype(wth));

    wtap_dump_params_init(&params, wth);

    /* Open outfile (same filetype/encap as input file) */
    if (strcmp(outfile, "-") == 0) {
      pdh = wtap_dump_open_stdout(wtap_file_type_subtype(wth), WTAP_UNCOMPRESSED, &params, &err);
    } else {
      pdh = wtap_dump_open(outfile, wtap_file_type_subtype(wth), WTAP_UNCOMPRESSED, &params, &err);
    }
    g_free(params.idb_inf);
    params.idb_inf = NULL;

    if (pdh == NULL) {
        cfile_dump_open_failure_message("reordercap", outfile, err,
                                        wtap_file_type_subtype(wth));
        wtap_dump_params_cleanup(&params);
        ret = OUTPUT_FILE_ERROR;
        goto clean_exit;
    }

    /* Allocate the array of frame pointers. */
    frames = g_ptr_array_new();

    /* Read each frame from infile */
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    while (wtap_read(wth, &rec, &buf, &err, &err_info, &data_offset)) {
        FrameRecord_t *newFrameRecord;

        newFrameRecord = g_slice_new(FrameRecord_t);
        newFrameRecord->num = frames->len + 1;
        newFrameRecord->offset = data_offset;
        if (rec.presence_flags & WTAP_HAS_TS) {
            newFrameRecord->frame_time = rec.ts;
        } else {
            nstime_set_unset(&newFrameRecord->frame_time);
        }

        if (prevFrame && frames_compare(&newFrameRecord, &prevFrame) < 0) {
           wrong_order_count++;
        }

        g_ptr_array_add(frames, newFrameRecord);
        prevFrame = newFrameRecord;
    }
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    if (err != 0) {
      /* Print a message noting that the read failed somewhere along the line. */
      cfile_read_failure_message("reordercap", infile, err, err_info);
    }

    printf("%u frames, %u out of order\n", frames->len, wrong_order_count);

    /* Sort the frames */
    if (wrong_order_count > 0) {
        g_ptr_array_sort(frames, frames_compare);
    }

    /* Write out each sorted frame in turn */
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    for (i = 0; i < frames->len; i++) {
        FrameRecord_t *frame = (FrameRecord_t *)frames->pdata[i];

        /* Avoid writing if already sorted and configured to */
        if (write_output_regardless || (wrong_order_count > 0)) {
            frame_write(frame, wth, pdh, &rec, &buf, infile, outfile);
        }
        g_slice_free(FrameRecord_t, frame);
    }
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    if (!write_output_regardless && (wrong_order_count == 0)) {
        printf("Not writing output file because input file is already in order.\n");
    }

    /* Free the whole array */
    g_ptr_array_free(frames, TRUE);

    /* Close outfile */
    if (!wtap_dump_close(pdh, &err)) {
        cfile_close_failure_message(outfile, err);
        wtap_dump_params_cleanup(&params);
        ret = OUTPUT_FILE_ERROR;
        goto clean_exit;
    }
    wtap_dump_params_cleanup(&params);

    /* Finally, close infile and release resources. */
    wtap_close(wth);

clean_exit:
    wtap_cleanup();
    free_progdirs();
    return ret;
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
