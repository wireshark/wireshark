/* maxmind_db.c
 * GeoIP database support
 *
 * Copyright 2018, Gerald Combs <gerald@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>

#include <epan/maxmind_db.h>

static mmdb_lookup_t mmdb_not_found;

#ifdef HAVE_MAXMINDDB

#include <stdio.h>
#include <errno.h>

#include <epan/wmem_scopes.h>

#include <epan/addr_resolv.h>
#include <epan/uat.h>
#include <epan/prefs.h>

#include <wsutil/report_message.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/ws_pipe.h>
#include <wsutil/strtoi.h>
#include <wsutil/glib-compat.h>

// To do:
// - Add RBL lookups? Along with the "is this a spammer" information that most RBL databases
//   provide, you can also fetch AS information: https://www.team-cymru.com/IP-ASN-mapping.html
// - Switch to a different format? I was going to use g_key_file_* to parse
//   the mmdbresolve output, but it was easier to just parse it directly.

static GThread *write_mmdbr_stdin_thread;
static GAsyncQueue *mmdbr_request_q; // g_allocated char *
static char mmdbr_stop_sentinel[] = "\x04"; // ASCII EOT. Could be anything.

// The GLib documentation says that g_rw_lock_reader_lock can be called
// recursively:
//   https://developer-old.gnome.org/glib/stable/glib-Threads.html#g-rw-lock-reader-lock
// However, g_rw_lock_reader_lock calls AcquireSRWLockShared
//   https://gitlab.gnome.org/GNOME/glib/blob/master/glib/gthread-win32.c#L206
// and SRW locks "cannot be acquired recursively"
//   https://docs.microsoft.com/en-us/windows/desktop/Sync/slim-reader-writer--srw--locks
//   https://devblogs.microsoft.com/oldnewthing/?p=93416
static GRWLock mmdbr_pipe_mtx;

// Hashes of mmdb_lookup_t
typedef struct _mmdbr_response_t {
    gboolean is_ipv4;
    ws_in4_addr ipv4_addr;
    ws_in6_addr ipv6_addr;
    mmdb_lookup_t mmdb_val;
} mmdb_response_t;

static wmem_map_t *mmdb_ipv4_map;
static wmem_map_t *mmdb_ipv6_map;
static GAsyncQueue *mmdbr_response_q; // g_allocated mmdbr_response_t *
static GThread *read_mmdbr_stdout_thread;

// Interned strings
static wmem_map_t *mmdb_str_chunk;
static wmem_map_t *mmdb_ipv6_chunk;

/* Child mmdbresolve process */
static ws_pipe_t mmdbr_pipe; // Requires mutex

/* UAT definitions. Copied from oids.c */
typedef struct _maxmind_db_path_t {
    char* path;
} maxmind_db_path_t;

static maxmind_db_path_t *maxmind_db_paths;
static guint num_maxmind_db_paths;
static const maxmind_db_path_t maxmind_db_system_paths[] = {
#ifdef _WIN32
    // XXX Properly expand "%ProgramData%\GeoIP".
    { "C:\\ProgramData\\GeoIP" },
    { "C:\\GeoIP" },
#else
    { "/usr/share/GeoIP" },
    { "/var/lib/GeoIP" },
#endif
    { NULL }
};
static uat_t *maxmind_db_paths_uat;
UAT_DIRECTORYNAME_CB_DEF(maxmind_mod, path, maxmind_db_path_t)

static GPtrArray *mmdb_file_arr; // .mmdb files

static gboolean resolve_synchronously = FALSE;

#if 0
#define MMDB_DEBUG(...) { \
    char *MMDB_DEBUG_MSG = ws_strdup_printf(__VA_ARGS__); \
    ws_warning("mmdb: %s:%d %s", G_STRFUNC, __LINE__, MMDB_DEBUG_MSG); \
    g_free(MMDB_DEBUG_MSG); \
}
#else
#define MMDB_DEBUG(...)
#endif

static void mmdb_resolve_stop(void);

// Hopefully scanning a few lines asynchronously has less overhead than
// reading in a child thread.
#define RES_INVALID_LINE        "# Invalid"
#define RES_STATUS_ERROR        "mmdbresolve.status: false"
#define RES_COUNTRY_ISO_CODE    "country.iso_code"
#define RES_COUNTRY_NAMES_EN    "country.names.en"
#define RES_CITY_NAMES_EN       "city.names.en"
#define RES_ASN_ORG             "autonomous_system_organization"
#define RES_ASN_NUMBER          "autonomous_system_number"
#define RES_LOCATION_LATITUDE   "location.latitude"
#define RES_LOCATION_LONGITUDE  "location.longitude"
#define RES_LOCATION_ACCURACY   "location.accuracy_radius"
#define RES_END                 "# End "

// Interned strings and v6 addresses, similar to GLib's string chunks.
static const char *chunkify_string(char *key) {
    char *chunk_string = (char *) wmem_map_lookup(mmdb_str_chunk, key);

    if (!chunk_string) {
        chunk_string = wmem_strdup(wmem_epan_scope(), key);
        wmem_map_insert(mmdb_str_chunk, chunk_string, chunk_string);
    }

    return chunk_string;
}

static const void *chunkify_v6_addr(const ws_in6_addr *addr) {
    void *chunk_v6_bytes = (char *) wmem_map_lookup(mmdb_ipv6_chunk, addr->bytes);

    if (!chunk_v6_bytes) {
        chunk_v6_bytes = wmem_memdup(wmem_epan_scope(), addr->bytes, sizeof(ws_in6_addr));
        wmem_map_insert(mmdb_ipv6_chunk, chunk_v6_bytes, chunk_v6_bytes);
    }

    return chunk_v6_bytes;
}

static void init_lookup(mmdb_lookup_t *lookup) {
    mmdb_lookup_t empty_lookup = { FALSE, NULL, NULL, NULL, 0, NULL, DBL_MAX, DBL_MAX, 0 };
    *lookup = empty_lookup;
}

static gboolean mmdbr_pipe_valid(void) {
    g_rw_lock_reader_lock(&mmdbr_pipe_mtx);
    gboolean pipe_valid = ws_pipe_valid(&mmdbr_pipe);
    g_rw_lock_reader_unlock(&mmdbr_pipe_mtx);
    return pipe_valid;
}

// Writing to mmdbr_pipe.stdin_fd can block. Do so in a separate thread.
static gpointer
write_mmdbr_stdin_worker(gpointer data _U_) {
    GIOStatus status;
    GError *err = NULL;
    gsize bytes_written;
    MMDB_DEBUG("starting write worker");

    while (1) {
        // On some operating systems (most notably macOS), g_async_queue_timeout_pop
        // will return immediately if we've been built with an older version of GLib:
        //   https://bugzilla.gnome.org/show_bug.cgi?id=673607
        // Call g_async_queue_pop instead. When we need to stop processing,
        // mmdb_resolve_stop will close our pipe and then push an invalid address
        // (mmdbr_stop_sentinel) onto the queue.
        char *request = (char *) g_async_queue_pop(mmdbr_request_q);
        if (!request) {
            continue;
        }
        if (strcmp(request, mmdbr_stop_sentinel) == 0) {
            g_free(request);
            return NULL;
        }

        MMDB_DEBUG("write %s ql %d", request, g_async_queue_length(mmdbr_request_q));
        status = g_io_channel_write_chars(mmdbr_pipe.stdin_io, request, strlen(request), &bytes_written, &err);
        if (status != G_IO_STATUS_NORMAL) {
            MMDB_DEBUG("write error %s. exiting thread.", err->message);
            g_clear_error(&err);
            g_free(request);
            return NULL;
        }
        g_clear_error(&err);
        g_free(request);
    }
    return NULL;
}

#define MAX_MMDB_LINE_LEN 2001
static gpointer
read_mmdbr_stdout_worker(gpointer data _U_) {
    mmdb_response_t *response = g_new0(mmdb_response_t, 1);
    gchar *line_buf = g_new(gchar, MAX_MMDB_LINE_LEN);
    GString *country_iso = g_string_new("");
    GString *country = g_string_new("");
    GString *city = g_string_new("");
    GString *as_org = g_string_new("");
    char cur_addr[WS_INET6_ADDRSTRLEN] = { 0 };

    size_t bytes_in_buffer, search_offset;
    gboolean line_feed_found;

    MMDB_DEBUG("starting read worker");

    bytes_in_buffer = search_offset = 0;
    line_feed_found = FALSE;
    for (;;) {
        if (line_feed_found) {
            /* Line parsed, move all (if any) next line bytes to beginning */
            bytes_in_buffer -= (search_offset + 1);
            memmove(line_buf, &line_buf[search_offset + 1], bytes_in_buffer);
            search_offset = 0;
            line_feed_found = FALSE;
        }

        while (search_offset < bytes_in_buffer) {
            if (line_buf[search_offset] == '\n') {
                line_buf[search_offset] = 0; /* NULL-terminate the string */
                line_feed_found = TRUE;
                break;
            }
            search_offset++;
        }

        if (!line_feed_found) {
            int space_available = (int)(MAX_MMDB_LINE_LEN - bytes_in_buffer);
            if (space_available > 0) {
                gsize bytes_read;
                g_io_channel_read_chars(mmdbr_pipe.stdout_io, &line_buf[bytes_in_buffer],
                                        space_available, &bytes_read, NULL);
                if (bytes_read > 0) {
                    bytes_in_buffer += bytes_read;
                } else {
                    MMDB_DEBUG("no pipe data. exiting thread.");
                    break;
                }
            } else {
                MMDB_DEBUG("long line");
                bytes_in_buffer = g_strlcpy(line_buf, RES_INVALID_LINE, MAX_MMDB_LINE_LEN);
                search_offset = bytes_in_buffer;
            }
            continue;
        }

        char *line = g_strstrip(line_buf);
        size_t line_len = strlen(line);
        MMDB_DEBUG("read %zd bytes: %s", line_len, line);
        if (line_len < 1) continue;

        char *val_start = strchr(line, ':');
        if (val_start) {
            val_start = g_strstrip(val_start + 1);
        }

        if (line[0] == '[' && line_len > 2) {
            // [init] or resolved address in square brackets.
            line[line_len - 1] = '\0';
            (void) g_strlcpy(cur_addr, line + 1, WS_INET6_ADDRSTRLEN);
            if (ws_inet_pton4(cur_addr, &response->ipv4_addr)) {
                response->is_ipv4 = TRUE;
            } else if (ws_inet_pton6(cur_addr, &response->ipv6_addr)) {
                response->is_ipv4 = FALSE;
            } else if (strcmp(cur_addr, "init") != 0) {
                MMDB_DEBUG("Invalid address: %s", cur_addr);
                cur_addr[0] = '\0';
            }
            // Reset state.
            init_lookup(&response->mmdb_val);
            g_string_truncate(country_iso, 0);
            g_string_truncate(country, 0);
            g_string_truncate(city, 0);
            g_string_truncate(as_org, 0);
        } else if (strcmp(line, RES_STATUS_ERROR) == 0) {
            // Error during init.
            cur_addr[0] = '\0';
            init_lookup(&response->mmdb_val);
            break;
        } else if (val_start && g_str_has_prefix(line, RES_COUNTRY_ISO_CODE)) {
            response->mmdb_val.found = TRUE;
            g_string_assign(country_iso, val_start);
        } else if (val_start && g_str_has_prefix(line, RES_COUNTRY_NAMES_EN)) {
            response->mmdb_val.found = TRUE;
            g_string_assign(country, val_start);
        } else if (val_start && g_str_has_prefix(line, RES_CITY_NAMES_EN)) {
            response->mmdb_val.found = TRUE;
            g_string_assign(city, val_start);
        } else if (val_start && g_str_has_prefix(line, RES_ASN_ORG)) {
            response->mmdb_val.found = TRUE;
            g_string_assign(as_org, val_start);
        } else if (val_start && g_str_has_prefix(line, RES_ASN_NUMBER)) {
            if (ws_strtou32(val_start, NULL, &response->mmdb_val.as_number)) {
                response->mmdb_val.found = TRUE;
            } else {
                MMDB_DEBUG("Invalid ASN: %s", val_start);
            }
        } else if (val_start && g_str_has_prefix(line, RES_LOCATION_LATITUDE)) {
            response->mmdb_val.found = TRUE;
            response->mmdb_val.latitude = g_ascii_strtod(val_start, NULL);
        } else if (val_start && g_str_has_prefix(line, RES_LOCATION_LONGITUDE)) {
            response->mmdb_val.found = TRUE;
            response->mmdb_val.longitude = g_ascii_strtod(val_start, NULL);
        } else if (val_start && g_str_has_prefix(line, RES_LOCATION_ACCURACY)) {
            if (ws_strtou16(val_start, NULL, &response->mmdb_val.accuracy)) {
                response->mmdb_val.found = TRUE;
            } else {
                MMDB_DEBUG("Invalid accuracy radius: %s", val_start);
            }
        } else if (g_str_has_prefix(line, RES_END)) {
            if (response->mmdb_val.found && cur_addr[0]) {
                if (country_iso->len) {
                    response->mmdb_val.country_iso = g_strdup(country_iso->str);
                }
                if (country->len) {
                    response->mmdb_val.country = g_strdup(country->str);
                }
                if (city->len) {
                    response->mmdb_val.city = g_strdup(city->str);
                }
                if (as_org->len) {
                    response->mmdb_val.as_org = g_strdup(as_org->str);
                }
                MMDB_DEBUG("queued %p %s %s: city %s country %s", response, response->is_ipv4 ? "v4" : "v6", cur_addr, response->mmdb_val.city, response->mmdb_val.country);
                g_async_queue_push(mmdbr_response_q, response); // Will be freed by maxmind_db_lookup_process.
                response = g_new0(mmdb_response_t, 1);
            } else if (strcmp(cur_addr, "init") != 0) {
                if (resolve_synchronously) {
                    // Synchronous lookups expect a 1-in 1-out resolution.
                    MMDB_DEBUG("Pushing not-found result due to bad address");
                    g_async_queue_push(mmdbr_response_q, response); // Will be freed by maxmind_db_lookup_process.
                    response = g_new0(mmdb_response_t, 1);
                }
                else {
                    MMDB_DEBUG("Discarded previous values due to bad address");
                }
            }
            cur_addr[0] = '\0';
            init_lookup(&response->mmdb_val);
        }
    }

    g_string_free(country_iso, TRUE);
    g_string_free(country, TRUE);
    g_string_free(city, TRUE);
    g_string_free(as_org, TRUE);
    g_free(line_buf);
    g_free(response);
    return NULL;
}

/**
 * Stop our mmdbresolve process.
 * Main thread only.
 */
static void mmdb_resolve_stop(void) {
    char *request;
    mmdb_response_t *response;

    while (mmdbr_request_q && (request = (char *) g_async_queue_try_pop(mmdbr_request_q)) != NULL) {
        g_free(request);
    }

    if (!mmdbr_pipe_valid()) {
        MMDB_DEBUG("not cleaning up, invalid PID %d", mmdbr_pipe.pid);
        return;
    }

    g_rw_lock_writer_lock(&mmdbr_pipe_mtx);

    g_async_queue_push(mmdbr_request_q, g_strdup(mmdbr_stop_sentinel));

    g_rw_lock_writer_unlock(&mmdbr_pipe_mtx);

    // write_mmdbr_stdin_worker should exit
    g_thread_join(write_mmdbr_stdin_thread);
    write_mmdbr_stdin_thread = NULL;

    MMDB_DEBUG("closing stdin IO");
    g_io_channel_unref(mmdbr_pipe.stdin_io);

    MMDB_DEBUG("closing pid %d", mmdbr_pipe.pid);
    g_spawn_close_pid(mmdbr_pipe.pid);
    mmdbr_pipe.pid = WS_INVALID_PID;

    // child process notices broken stdin pipe and exits (breaks stdout pipe)
    // read_mmdbr_stdout_worker should exit

    g_thread_join(read_mmdbr_stdout_thread);
    read_mmdbr_stdout_thread = NULL;

    MMDB_DEBUG("closing stdout IO");
    g_io_channel_unref(mmdbr_pipe.stdout_io);

    while (mmdbr_response_q && (response = (mmdb_response_t *) g_async_queue_try_pop(mmdbr_response_q)) != NULL) {
        g_free((char *) response->mmdb_val.country_iso);
        g_free((char *) response->mmdb_val.country);
        g_free((char *) response->mmdb_val.city);
        g_free((char *) response->mmdb_val.as_org);
        g_free(response);
        MMDB_DEBUG("cleaned response %p", response);
    }
}

/**
 * Start an mmdbresolve process.
 */
static void mmdb_resolve_start(void) {
    if (!mmdbr_request_q) {
        mmdbr_request_q = g_async_queue_new();
    }

    if (!mmdbr_response_q) {
        mmdbr_response_q = g_async_queue_new();
    }

    if (!mmdb_ipv4_map) {
        mmdb_ipv4_map = wmem_map_new(wmem_epan_scope(), g_direct_hash, g_direct_equal);
    }

    if (!mmdb_ipv6_map) {
        mmdb_ipv6_map = wmem_map_new(wmem_epan_scope(), ipv6_oat_hash, ipv6_equal);
    }

    if (!mmdb_str_chunk) {
        mmdb_str_chunk = wmem_map_new(wmem_epan_scope(), wmem_str_hash, g_str_equal);
    }

    if (!mmdb_ipv6_chunk) {
        mmdb_ipv6_chunk = wmem_map_new(wmem_epan_scope(), ipv6_oat_hash, ipv6_equal);
    }

    if (!mmdb_file_arr) {
        MMDB_DEBUG("unexpected mmdb_file_arr == NULL");
        return;
    }

    mmdb_resolve_stop();

    if (mmdb_file_arr->len == 0) {
        MMDB_DEBUG("no GeoIP databases found");
        return;
    }

    GPtrArray *args = g_ptr_array_new();
    char *mmdbresolve = ws_strdup_printf("%s%c%s", get_progfile_dir(), G_DIR_SEPARATOR, "mmdbresolve");
    g_ptr_array_add(args, mmdbresolve);
    for (guint i = 0; i < mmdb_file_arr->len; i++) {
        g_ptr_array_add(args, g_strdup("-f"));
        g_ptr_array_add(args, g_strdup((const gchar *)g_ptr_array_index(mmdb_file_arr, i)));
    }
    g_ptr_array_add(args, NULL);

    ws_pipe_init(&mmdbr_pipe);
    GPid pipe_pid = ws_pipe_spawn_async(&mmdbr_pipe, args);
    MMDB_DEBUG("spawned %s pid %d", mmdbresolve, pipe_pid);

    for (guint i = 0; i < args->len; i++) {
        char *arg = (char *)g_ptr_array_index(args, i);
        MMDB_DEBUG("args: %s", arg);
        g_free(arg);
    }
    g_ptr_array_free(args, TRUE);

    if (pipe_pid == WS_INVALID_PID) {
        ws_pipe_init(&mmdbr_pipe);
        return;
    }
    g_io_channel_unref(mmdbr_pipe.stderr_io);

    write_mmdbr_stdin_thread = g_thread_new("write_mmdbr_stdin_worker", write_mmdbr_stdin_worker, NULL);
    read_mmdbr_stdout_thread = g_thread_new("read_mmdbr_stdout_worker", read_mmdbr_stdout_worker, NULL);
}

/**
 * Scan a directory for GeoIP databases and load them
 */
static void
maxmind_db_scan_dir(const char *dirname) {
    WS_DIR *dir;
    WS_DIRENT *file;

    if ((dir = ws_dir_open(dirname, 0, NULL)) != NULL) {
        while ((file = ws_dir_read_name(dir)) != NULL) {
            const char *name = ws_dir_get_name(file);
            if (g_str_has_suffix(file, ".mmdb")) {
                char *datname = ws_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", dirname, name);
                FILE *mmdb_f = ws_fopen(datname, "r");
                if (mmdb_f) {
                    g_ptr_array_add(mmdb_file_arr, datname);
                    fclose(mmdb_f);
                } else {
                    g_free(datname);
                }
            }
        }
        ws_dir_close (dir);
    }
}

/* UAT callbacks */
static void* maxmind_db_path_copy_cb(void* dest, const void* orig, size_t len _U_) {
    const maxmind_db_path_t *m = (const maxmind_db_path_t *)orig;
    maxmind_db_path_t *d = (maxmind_db_path_t *)dest;

    d->path = g_strdup(m->path);

    return d;
}

static void maxmind_db_path_free_cb(void* p) {
    maxmind_db_path_t *m = (maxmind_db_path_t *)p;
    g_free(m->path);
}

static void maxmind_db_cleanup(void) {
    guint i;

    mmdb_resolve_stop();

    /* If we have old data, clear out the whole thing
     * and start again. TODO: Just update the ones that
     * have changed for efficiency's sake. */
    if (mmdb_file_arr) {
        for (i = 0; i < mmdb_file_arr->len; i++) {
            g_free(g_ptr_array_index(mmdb_file_arr, i));
        }
        /* finally, free the array itself */
        g_ptr_array_free(mmdb_file_arr, TRUE);
        mmdb_file_arr = NULL;
    }
}

/* called every time the user presses "Apply" or "OK in the list of
 * GeoIP directories, and also once on startup */
static void maxmind_db_post_update_cb(void) {
    guint i;

    maxmind_db_cleanup();

    /* allocate the array */
    mmdb_file_arr = g_ptr_array_new();

    /* First try the system paths */
    for (i = 0; maxmind_db_system_paths[i].path != NULL; i++) {
        maxmind_db_scan_dir(maxmind_db_system_paths[i].path);
    }

    /* Walk all the directories */
    for (i = 0; i < num_maxmind_db_paths; i++) {
        if (maxmind_db_paths[i].path) {
            maxmind_db_scan_dir(maxmind_db_paths[i].path);
        }
    }

    mmdb_resolve_start();
}

/**
 * Initialize GeoIP lookups
 */
void
maxmind_db_pref_init(module_t *nameres)
{
    static uat_field_t maxmind_db_paths_fields[] = {
        UAT_FLD_DIRECTORYNAME(maxmind_mod, path, "MaxMind Database Directory", "The MaxMind database directory path"),
        UAT_END_FIELDS
    };

    maxmind_db_paths_uat = uat_new("MaxMind Database Paths",
            sizeof(maxmind_db_path_t),
            "maxmind_db_paths",
            FALSE, // Global, not per-profile
            (void**)&maxmind_db_paths,
            &num_maxmind_db_paths,
            UAT_AFFECTS_DISSECTION, // Affects IP4 and IPv6 packets.
            "ChMaxMindDbPaths",
            maxmind_db_path_copy_cb,
            NULL, // update_cb
            maxmind_db_path_free_cb,
            maxmind_db_post_update_cb,
            maxmind_db_cleanup,
            maxmind_db_paths_fields);

    prefs_register_uat_preference(nameres,
            "maxmind_db_paths",
            "MaxMind database directories",
            "Search paths for MaxMind address mapping databases."
            " Wireshark will look in each directory for files ending"
            " with \".mmdb\".",
            maxmind_db_paths_uat);
}

void maxmind_db_pref_cleanup(void)
{
    mmdb_resolve_stop();
}

static void maxmind_db_pop_response(mmdb_response_t *response)
{
    mmdb_lookup_t *mmdb_val = (mmdb_lookup_t *) wmem_memdup(wmem_epan_scope(), &response->mmdb_val, sizeof(mmdb_lookup_t));
    if (response->mmdb_val.country_iso) {
        char *country_iso = (char *) response->mmdb_val.country_iso;
        mmdb_val->country_iso = chunkify_string(country_iso);
        g_free(country_iso);
    }
    if (response->mmdb_val.country) {
        char *country = (char *) response->mmdb_val.country;
        mmdb_val->country = chunkify_string(country);
        g_free(country);
    }
    if (response->mmdb_val.city) {
        char *city = (char *) response->mmdb_val.city;
        mmdb_val->city = chunkify_string(city);
        g_free(city);
    }
    if (response->mmdb_val.as_org) {
        char *as_org = (char *) response->mmdb_val.as_org;
        mmdb_val->as_org = chunkify_string(as_org);
        g_free(as_org);
    }
    MMDB_DEBUG("popped response %s city %s country %s", response->is_ipv4 ? "v4" : "v6", mmdb_val->city, mmdb_val->country);

    if (response->is_ipv4) {
        wmem_map_insert(mmdb_ipv4_map, GUINT_TO_POINTER(response->ipv4_addr), mmdb_val);
    } else {
        wmem_map_insert(mmdb_ipv6_map, chunkify_v6_addr(&response->ipv6_addr), mmdb_val);
    }
    g_free(response);
}

static void maxmind_db_await_response(void)
{
    mmdb_response_t *response;

    if (mmdbr_response_q != NULL) {
        MMDB_DEBUG("entering blocking wait for response");
        response = (mmdb_response_t *) g_async_queue_pop(mmdbr_response_q);
        MMDB_DEBUG("exiting blocking wait for response");
        maxmind_db_pop_response(response);
    }
}

/**
 * Public API
 */

gboolean maxmind_db_lookup_process(void)
{
    gboolean new_entries = FALSE;
    mmdb_response_t *response;

    while (mmdbr_response_q && (response = (mmdb_response_t *) g_async_queue_try_pop(mmdbr_response_q)) != NULL) {
        new_entries = TRUE;
        maxmind_db_pop_response(response);
    }

    return new_entries;
}

const mmdb_lookup_t *
maxmind_db_lookup_ipv4(const ws_in4_addr *addr) {
    mmdb_lookup_t *result = (mmdb_lookup_t *) wmem_map_lookup(mmdb_ipv4_map, GUINT_TO_POINTER(*addr));

    if (!result) {
        result = &mmdb_not_found;
        wmem_map_insert(mmdb_ipv4_map, GUINT_TO_POINTER(*addr), result);

        if (mmdbr_pipe_valid()) {
            char addr_str[WS_INET_ADDRSTRLEN];
            ws_inet_ntop4(addr, addr_str, WS_INET_ADDRSTRLEN);
            MMDB_DEBUG("looking up %s", addr_str);
            g_async_queue_push(mmdbr_request_q, ws_strdup_printf("%s\n", addr_str));
            if (resolve_synchronously) {
                maxmind_db_await_response();
                result = (mmdb_lookup_t *) wmem_map_lookup(mmdb_ipv4_map, GUINT_TO_POINTER(*addr));
            }
        }
    }

    return result;
}

const mmdb_lookup_t *
maxmind_db_lookup_ipv6(const ws_in6_addr *addr) {
    mmdb_lookup_t * result = (mmdb_lookup_t *) wmem_map_lookup(mmdb_ipv6_map, addr->bytes);

    if (!result) {
        result = &mmdb_not_found;
        wmem_map_insert(mmdb_ipv6_map, chunkify_v6_addr(addr), result);

        if (mmdbr_pipe_valid()) {
            char addr_str[WS_INET6_ADDRSTRLEN];
            ws_inet_ntop6(addr, addr_str, WS_INET6_ADDRSTRLEN);
            MMDB_DEBUG("looking up %s", addr_str);
            g_async_queue_push(mmdbr_request_q, ws_strdup_printf("%s\n", addr_str));
            if (resolve_synchronously) {
                maxmind_db_await_response();
                result = (mmdb_lookup_t *) wmem_map_lookup(mmdb_ipv6_map, addr->bytes);
            }
        }
    }

    return result;
}

gchar *
maxmind_db_get_paths(void) {
    GString* path_str = NULL;
    guint i;

    path_str = g_string_new("");

    for (i = 0; maxmind_db_system_paths[i].path != NULL; i++) {
        g_string_append_printf(path_str,
                "%s" G_SEARCHPATH_SEPARATOR_S, maxmind_db_system_paths[i].path);
    }

    for (i = 0; i < num_maxmind_db_paths; i++) {
        if (maxmind_db_paths[i].path) {
            g_string_append_printf(path_str,
                    "%s" G_SEARCHPATH_SEPARATOR_S, maxmind_db_paths[i].path);
        }
    }

    g_string_truncate(path_str, path_str->len-1);

    return g_string_free(path_str, FALSE);
}

void
maxmind_db_set_synchrony(gboolean synchronous) {
    resolve_synchronously = synchronous;
}

#else // HAVE_MAXMINDDB

void
maxmind_db_pref_init(module_t *nameres _U_) {}

void
maxmind_db_pref_cleanup(void) {}


gboolean
maxmind_db_lookup_process(void)
{
    return FALSE;
}

const mmdb_lookup_t *
maxmind_db_lookup_ipv4(const ws_in4_addr *addr _U_) {
    return &mmdb_not_found;
}

const mmdb_lookup_t *
maxmind_db_lookup_ipv6(const ws_in6_addr *addr _U_) {
    return &mmdb_not_found;
}

gchar *
maxmind_db_get_paths(void) {
    return g_strdup("");
}

void
maxmind_db_set_synchrony(gboolean synchronous _U_) {
    /* Nothing to set. */
}

#endif // HAVE_MAXMINDDB


/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
