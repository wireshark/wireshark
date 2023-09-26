/* Read IPv4 and IPv6 addresses on stdin and print their MMDB entries on stdout.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program uses the MaxMind DB library (libmaxminddb) and MUST be
 * compatible with its license (Apache 2.0).
 *
 * SPDX-License-Identifier: MIT
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <maxminddb.h>

#define MAX_ADDR_LEN 46
#define MMDBR_STRINGIFY(x) MMDBR_STRINGIFY_S(x)
#define MMDBR_STRINGIFY_S(s) #s
#define OUT_BUF_SIZE 65536

// Uncomment to enable slow lookups. Only useful on Windows for now.
// #define MMDB_DEBUG_SLOW 1

#ifdef MMDB_DEBUG_SLOW
#ifdef _WIN32
#include <Windows.h>
#endif
#endif

static const char *co_iso_key[]     = {"country", "iso_code", NULL};
static const char *co_name_key[]    = {"country", "names", "en", NULL};
static const char *ci_name_key[]    = {"city", "names", "en", NULL};
static const char *asn_o_key[]      = {"autonomous_system_organization", NULL};
static const char *asn_key[]        = {"autonomous_system_number", NULL};
static const char *l_lat_key[]      = {"location", "latitude", NULL};
static const char *l_lon_key[]      = {"location", "longitude", NULL};
static const char *l_accuracy_key[] = {"location", "accuracy_radius", NULL};
static const char *empty_key[]      = {NULL};

static const char **lookup_keys[] = {
    co_iso_key,
    co_name_key,
    ci_name_key,
    asn_o_key,
    asn_key,
    l_lat_key,
    l_lon_key,
    l_accuracy_key,
    empty_key
};

static void exit_err(void) {
    fprintf(stderr, "Usage: mmdbresolve -f db_file [-f db_file ...]\n");
    exit(1);
}

int
main(int argc, char *argv[])
{
    char addr_str[MAX_ADDR_LEN+1];
    size_t mmdb_count = 0;
    MMDB_s *mmdbs = NULL, *new_mmdbs;
    int mmdb_err;

    char *out_buf = (char *) malloc(OUT_BUF_SIZE);
    if (out_buf == NULL) {
        fprintf(stdout, "ERROR: malloc failed\n");
        return 1;
    }
    setvbuf(stdout, out_buf, _IOFBF, OUT_BUF_SIZE);

    fprintf(stdout, "[init]\n");

    // If we need to handle anything beyond "-f" we'll probably want to
    // link with GLib and use GOption.
    int arg_idx = 0;
    while (arg_idx < argc - 1) {
        if (strcmp(argv[arg_idx], "-f") == 0) {
            arg_idx++;
            const char *db_arg = argv[arg_idx];
            MMDB_s try_mmdb;
            mmdb_err = MMDB_open(db_arg, 0, &try_mmdb);
            fprintf(stdout, "db.%zd.path: %s\n", mmdb_count, db_arg);
            fprintf(stdout, "db.%zd.status: ", mmdb_count);
            if (mmdb_err == MMDB_SUCCESS) {
                mmdb_count++;
                new_mmdbs = (MMDB_s *) realloc(mmdbs, mmdb_count * sizeof(MMDB_s));
                if (new_mmdbs == NULL) {
                    free(mmdbs);
                    fprintf(stdout, "ERROR out of memory\n");
                    return 1;
                }
                mmdbs = new_mmdbs;
                mmdbs[mmdb_count - 1] = try_mmdb;
                fprintf(stdout, "OK\n");
                fprintf(stdout, "db.%zd.type: %s\n", mmdb_count, mmdbs[mmdb_count - 1].metadata.database_type);
            } else {
                fprintf(stdout, "ERROR %s\n", MMDB_strerror(mmdb_err));
            }
        }
        arg_idx++;
    }

    fprintf(stdout, "mmdbresolve.status: %s\n", mmdb_count > 0 ? "true": "false");
    fprintf(stdout, "# End init\n");
    fflush(stdout);

    if (arg_idx != argc || mmdb_count < 1) {
        exit_err();
    }

    int in_items = 0;
    while (in_items != EOF) {
        int gai_err;

        in_items = fscanf(stdin, "%" MMDBR_STRINGIFY(MAX_ADDR_LEN) "s", addr_str);

        if (in_items < 1) {
            continue;
        }

        fprintf(stdout, "[%s]\n", addr_str);

#ifdef MMDB_DEBUG_SLOW
#ifdef _WIN32
        Sleep(1000);
#endif
#endif

        for (size_t mmdb_idx = 0; mmdb_idx < mmdb_count; mmdb_idx++) {
            fprintf(stdout, "# %s\n", mmdbs[mmdb_idx].metadata.database_type);
            MMDB_lookup_result_s result = MMDB_lookup_string(&mmdbs[mmdb_idx], addr_str, &gai_err, &mmdb_err);

            if (result.found_entry && gai_err == 0 && mmdb_err == MMDB_SUCCESS) {
                for (size_t key_idx = 0; lookup_keys[key_idx][0]; key_idx++) {
                    MMDB_entry_data_s entry_data;
                    int status = MMDB_aget_value(&result.entry, &entry_data, lookup_keys[key_idx]);
                    if (status == MMDB_SUCCESS && entry_data.has_data) {
                        char *sep = "";
                        for (int idx = 0; lookup_keys[key_idx][idx] != 0; idx++) {
                            fprintf(stdout, "%s%s", sep, lookup_keys[key_idx][idx]);
                            sep = ".";
                        }
                        switch (entry_data.type) {
                            case MMDB_DATA_TYPE_UTF8_STRING:
                            {
                                char len_fmt[12]; // : %.xxxxxs\n\0
                                snprintf(len_fmt, 11, ": %%.%us\n", entry_data.data_size);
                                fprintf(stdout, len_fmt, entry_data.utf8_string);
                            }
                            break;
                            case MMDB_DATA_TYPE_UINT16:
                                fprintf(stdout, ": %u\n", entry_data.uint16);
                                break;
                            case MMDB_DATA_TYPE_UINT32:
                                fprintf(stdout, ": %u\n", entry_data.uint32);
                                break;
                            case MMDB_DATA_TYPE_INT32:
                                fprintf(stdout, ": %d\n", entry_data.int32);
                                break;
                            case MMDB_DATA_TYPE_BOOLEAN:
                                fprintf(stdout, ": %s\n", entry_data.boolean ? "True" : "False");
                                break;
                            case MMDB_DATA_TYPE_DOUBLE:
                                fprintf(stdout, ": %f\n", entry_data.double_value);
                                break;
                            case MMDB_DATA_TYPE_FLOAT:
                                fprintf(stdout, ": %f\n", entry_data.float_value);
                                break;
                            default:
                                fprintf(stdout, ": UNKNOWN (%u)\n", entry_data.type);
                        }
                    }
                }
            } else {
                // dump error info.
            }
        }
        fprintf(stdout, "# End %s\n", addr_str);
        fflush(stdout);
    }

    free(mmdbs);

    return 0;
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
