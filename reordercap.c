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
#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>

#include <ws_exit_codes.h>
#include <wsutil/ws_getopt.h>

#include <wiretap/wtap.h>

#include <wsutil/cmdarg_err.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <cli_main.h>
#include <wsutil/version_info.h>
#include <wiretap/wtap_opttypes.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif

#include <wsutil/report_message.h>
#include <wsutil/wslog.h>

#include "ui/failure_message.h"

/* Additional exit codes */
#define OUTPUT_FILE_ERROR 1

/* Show command-line usage */
static void
print_usage(FILE *output)
{
    fprintf(output, "\n");
    fprintf(output, "Usage: reordercap [options] <infile> <outfile>\n");
    fprintf(output, "\n");
    fprintf(output, "Options:\n");
    fprintf(output, "  -n                don't write to output file if the input file is ordered.\n");
    fprintf(output, "  -h, --help        display this help and exit.\n");
    fprintf(output, "  -v, --version     print version information and exit.\n");
}

/* Remember where this frame was in the file */
typedef struct FrameRecord_t {
    int64_t      offset;
    unsigned     num;

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
    char   *err_info;

    DEBUG_PRINT("\nDumping frame (offset=%" PRIu64 ")\n",
                frame->offset);


    /* Re-read the frame from the stored location */
    if (!wtap_seek_read(wth, frame->offset, rec, buf, &err, &err_info)) {
        if (err != 0) {
            /* Print a message noting that the read failed somewhere along the line. */
            fprintf(stderr,
                    "reordercap: An error occurred while re-reading \"%s\".\n",
                    infile);
            cfile_read_failure_message(infile, err, err_info);
            exit(1);
        }
    }

    /* Copy, and set length and timestamp from item. */
    /* TODO: remove when wtap_seek_read() fills in rec,
       including time stamps, for all file types  */
    rec->ts = frame->frame_time;

    /* Dump frame to outfile */
    if (!wtap_dump(pdh, rec, ws_buffer_start_ptr(buf), &err, &err_info)) {
        cfile_write_failure_message(infile, outfile, err, err_info, frame->num,
                                    wtap_file_type_subtype(wth));
        exit(1);
    }
    wtap_rec_reset(rec);
}

/* Comparing timestamps between 2 frames.
   negative if (t1 < t2)
   zero     if (t1 == t2)
   positive if (t1 > t2)
*/
static int
frames_compare(const void *a, const void *b)
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
reordercap_cmdarg_err(const char *msg_format, va_list ap)
{
    fprintf(stderr, "reordercap: ");
    vfprintf(stderr, msg_format, ap);
    fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
reordercap_cmdarg_err_cont(const char *msg_format, va_list ap)
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
    char *configuration_init_error;
    static const struct report_message_routines reordercap_message_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };
    wtap *wth = NULL;
    wtap_dumper *pdh = NULL;
    wtap_rec rec;
    Buffer buf;
    int err;
    char *err_info;
    int64_t data_offset;
    unsigned wrong_order_count = 0;
    bool write_output_regardless = true;
    unsigned i;
    wtap_dump_params params;
    int                          ret = EXIT_SUCCESS;

    GPtrArray *frames;
    FrameRecord_t *prevFrame = NULL;

    int opt;
    static const struct ws_option long_options[] = {
        {"help", ws_no_argument, NULL, 'h'},
        {"version", ws_no_argument, NULL, 'v'},
        {0, 0, 0, 0 }
    };
    int file_count;
    char *infile;
    const char *outfile;

    cmdarg_err_init(reordercap_cmdarg_err, reordercap_cmdarg_err_cont);

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("reordercap", vcmdarg_err);

    /* Early logging command-line initialization. */
    ws_log_parse_args(&argc, argv, vcmdarg_err, WS_EXIT_INVALID_OPTION);

    ws_noisy("Finished log init and parsing command line log arguments");

    /* Initialize the version information. */
    ws_init_version_info("Reordercap", NULL, NULL);

    /*
     * Get credential information for later use.
     */
    init_process_policies();

    /*
     * Attempt to get the pathname of the directory containing the
     * executable file.
     */
    configuration_init_error = configuration_init(argv[0], NULL);
    if (configuration_init_error != NULL) {
        fprintf(stderr,
                "reordercap: Can't get pathname of directory containing the reordercap program: %s.\n",
                configuration_init_error);
        g_free(configuration_init_error);
    }

    init_report_message("reordercap", &reordercap_message_routines);

    wtap_init(true);

    /* Process the options first */
    while ((opt = ws_getopt_long(argc, argv, "hnv", long_options, NULL)) != -1) {
        switch (opt) {
            case 'n':
                write_output_regardless = false;
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
                ret = WS_EXIT_INVALID_OPTION;
                goto clean_exit;
        }
    }

    /* Remaining args are file names */
    file_count = argc - ws_optind;
    if (file_count == 2) {
        infile  = argv[ws_optind];
        outfile = argv[ws_optind+1];
    }
    else {
        print_usage(stderr);
        ret = WS_EXIT_INVALID_OPTION;
        goto clean_exit;
    }

    /* Open infile */
    /* TODO: if reordercap is ever changed to give the user a choice of which
       open_routine reader to use, then the following needs to change. */
    wth = wtap_open_offline(infile, WTAP_TYPE_AUTO, &err, &err_info, true);
    if (wth == NULL) {
        cfile_open_failure_message(infile, err, err_info);
        ret = WS_EXIT_OPEN_ERROR;
        goto clean_exit;
    }
    DEBUG_PRINT("file_type_subtype is %d\n", wtap_file_type_subtype(wth));

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
        wtap_rec_reset(&rec);
    }
    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);
    if (err != 0) {
      /* Print a message noting that the read failed somewhere along the line. */
      cfile_read_failure_message(infile, err, err_info);
    }

    printf("%u frames, %u out of order\n", frames->len, wrong_order_count);

    wtap_dump_params_init(&params, wth);

    /* Sort the frames */
    /* XXX - Does this handle multiple SHBs correctly? */
    if (wrong_order_count > 0) {
        g_ptr_array_sort(frames, frames_compare);
    }


    /* Avoid writing if already sorted and configured to */
    if (write_output_regardless || (wrong_order_count > 0)) {
        /* Open outfile (same filetype/encap as input file) */
        if (strcmp(outfile, "-") == 0) {
          pdh = wtap_dump_open_stdout(wtap_file_type_subtype(wth),
                                      WTAP_UNCOMPRESSED, &params, &err, &err_info);
        } else {
          pdh = wtap_dump_open(outfile, wtap_file_type_subtype(wth),
                               WTAP_UNCOMPRESSED, &params, &err, &err_info);
        }
        g_free(params.idb_inf);
        params.idb_inf = NULL;

        if (pdh == NULL) {
            cfile_dump_open_failure_message(outfile, err, err_info,
                                            wtap_file_type_subtype(wth));
            wtap_dump_params_cleanup(&params);
            ret = OUTPUT_FILE_ERROR;
            goto clean_exit;
        }


        /* Write out each sorted frame in turn */
        wtap_rec_init(&rec);
        ws_buffer_init(&buf, 1514);
        for (i = 0; i < frames->len; i++) {
            FrameRecord_t *frame = (FrameRecord_t *)frames->pdata[i];

            frame_write(frame, wth, pdh, &rec, &buf, infile, outfile);

            g_slice_free(FrameRecord_t, frame);
        }

        wtap_rec_cleanup(&rec);
        ws_buffer_free(&buf);



        /* Close outfile */
        if (!wtap_dump_close(pdh, NULL, &err, &err_info)) {
            cfile_close_failure_message(outfile, err, err_info);
            wtap_dump_params_cleanup(&params);
            ret = OUTPUT_FILE_ERROR;
            goto clean_exit;
        }
    } else {
        printf("Not writing output file because input file is already in order.\n");

        /* Free frame memory */
        for (i = 0; i < frames->len; i++) {
            FrameRecord_t *frame = (FrameRecord_t *)frames->pdata[i];

            g_slice_free(FrameRecord_t, frame);
        }
    }


    /* Free the whole array */
    g_ptr_array_free(frames, TRUE);

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
