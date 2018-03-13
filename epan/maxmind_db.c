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

#include <epan/wmem/wmem.h>

#include <epan/addr_resolv.h>
#include <epan/uat.h>
#include <epan/prefs.h>

#include <wsutil/report_message.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/ws_pipe.h>
#include <wsutil/strtoi.h>

// To do:
// - If we can't reliably do non-blocking reads, move process_mmdbr_stdout to a worker thread.
// - Add RBL lookups? Along with the "is this a spammer" information that most RBL databases
//   provide, you can also fetch AS information: http://www.team-cymru.org/IP-ASN-mapping.html
// - Switch to a different format? I was going to use g_key_file_* to parse
//   the mmdbresolve output, but it was easier to just parse it directly.

// Hashes of mmdb_lookup_t
static wmem_map_t *mmdb_ipv4_map;
static wmem_map_t *mmdb_ipv6_map;

// Interned strings
static wmem_map_t *mmdb_str_chunk;
static wmem_map_t *mmdb_ipv6_chunk;

/* Child mmdbresolve process */
static char cur_addr[WS_INET6_ADDRSTRLEN];
static mmdb_lookup_t cur_lookup;
static ws_pipe_t mmdbr_pipe;
static FILE *mmdbr_stdout;

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

#if 0
#define MMDB_DEBUG(...) { \
    char *MMDB_DEBUG_MSG = g_strdup_printf(__VA_ARGS__); \
    g_warning("mmdb: %s:%d %s", G_STRFUNC, __LINE__, MMDB_DEBUG_MSG); \
    g_free(MMDB_DEBUG_MSG); \
}
#else
#define MMDB_DEBUG(...)
#endif

static void mmdb_resolve_stop(void);

// Hopefully scanning a few lines asynchronously has less overhead than
// reading in a child thread.
#define RES_STATUS_ERROR        "mmdbresolve.status: false"
#define RES_COUNTRY_ISO_CODE    "country.iso_code"
#define RES_COUNTRY_NAMES_EN    "country.names.en"
#define RES_CITY_NAMES_EN       "city.names.en"
#define RES_ASN_ORG             "autonomous_system_organization"
#define RES_ASN_NUMBER          "autonomous_system_number"
#define RES_LOCATION_LATITUDE   "location.latitude"
#define RES_LOCATION_LONGITUDE  "location.longitude"
#define RES_END                 "# End "

// Interned strings and v6 addresses, similar to GLib's string chunks.
static const char *chunkify_string(char *key) {
    key = g_strstrip(key);
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
    mmdb_lookup_t empty_lookup = { FALSE, NULL, NULL, NULL, 0, NULL, DBL_MAX, DBL_MAX };
    *lookup = empty_lookup;
}

static gboolean
process_mmdbr_stdout(void) {

    int read_buf_size = 2048;
    char *read_buf = (char *) g_malloc(read_buf_size);
    gboolean new_entries = FALSE;

    MMDB_DEBUG("start %d", ws_pipe_data_available(mmdbr_pipe.stdout_fd));

    while (ws_pipe_data_available(mmdbr_pipe.stdout_fd)) {
        read_buf[0] = '\0';
        char *line = fgets(read_buf, read_buf_size, mmdbr_stdout);
        if (!line || ferror(mmdbr_stdout)) {
            MMDB_DEBUG("read error %s", g_strerror(errno));
            mmdb_resolve_stop();
            break;
        }

        line = g_strstrip(line);
        size_t line_len = strlen(line);
        MMDB_DEBUG("read %zd bytes, feof %d: %s", line_len, feof(mmdbr_stdout), line);
        if (line_len < 1) continue;

        char *val_start = strchr(line, ':');
        if (val_start) val_start++;

        if (line[0] == '[' && line_len > 2) {
            // [init] or resolved address in square brackets.
            line[line_len - 1] = '\0';
            g_strlcpy(cur_addr, line + 1, WS_INET6_ADDRSTRLEN);
            init_lookup(&cur_lookup);
        } else if (strcmp(line, RES_STATUS_ERROR) == 0) {
            // Error during init.
            cur_addr[0] = '\0';
            init_lookup(&cur_lookup);
            mmdb_resolve_stop();
        } else if (val_start && g_str_has_prefix(line, RES_COUNTRY_ISO_CODE)) {
            cur_lookup.found = TRUE;
            cur_lookup.country_iso = chunkify_string(val_start);
        } else if (val_start && g_str_has_prefix(line, RES_COUNTRY_NAMES_EN)) {
            cur_lookup.found = TRUE;
            cur_lookup.country = chunkify_string(val_start);
        } else if (val_start && g_str_has_prefix(line, RES_CITY_NAMES_EN)) {
            cur_lookup.found = TRUE;
            cur_lookup.city = chunkify_string(val_start);
        } else if (val_start && g_str_has_prefix(line, RES_ASN_ORG)) {
            cur_lookup.found = TRUE;
            cur_lookup.as_org = chunkify_string(val_start);
        } else if (val_start && g_str_has_prefix(line, RES_ASN_NUMBER)) {
            if (ws_strtou32(val_start, NULL, &cur_lookup.as_number)) {
                cur_lookup.found = TRUE;
            } else {
                MMDB_DEBUG("Invalid as number: %s", val_start);
            }
        } else if (val_start && g_str_has_prefix(line, RES_LOCATION_LATITUDE)) {
            cur_lookup.found = TRUE;
            cur_lookup.latitude = g_ascii_strtod(val_start, NULL);
        } else if (val_start && g_str_has_prefix(line, RES_LOCATION_LONGITUDE)) {
            cur_lookup.found = TRUE;
            cur_lookup.longitude = g_ascii_strtod(val_start, NULL);
        } else if (g_str_has_prefix(line, RES_END)) {
            if (cur_lookup.found) {
                mmdb_lookup_t *mmdb_val = (mmdb_lookup_t *) wmem_memdup(wmem_epan_scope(), &cur_lookup, sizeof(cur_lookup));
                if (strstr(cur_addr, ".")) {
                    MMDB_DEBUG("inserting v4 %p %s: city %s country %s", (void *) mmdb_val, cur_addr, mmdb_val->city, mmdb_val->country);
                    guint32 addr;
                    ws_inet_pton4(cur_addr, &addr);
                    wmem_map_insert(mmdb_ipv4_map, GUINT_TO_POINTER(addr), mmdb_val);
                    new_entries = TRUE;
                } else if (strstr(cur_addr, ":")) {
                    MMDB_DEBUG("inserting v6 %p %s: city %s country %s", (void *) mmdb_val, cur_addr, mmdb_val->city, mmdb_val->country);
                    ws_in6_addr addr;
                    ws_inet_pton6(cur_addr, &addr);
                    wmem_map_insert(mmdb_ipv6_map, chunkify_v6_addr(&addr), mmdb_val);
                    new_entries = TRUE;
                }
            }
            cur_addr[0] = '\0';
            init_lookup(&cur_lookup);
        }
    }

    g_free(read_buf);
    return new_entries;
}

/**
 * Stop our mmdbresolve process.
 */
static void mmdb_resolve_stop(void) {
    if (!ws_pipe_valid(&mmdbr_pipe)) {
        MMDB_DEBUG("not cleaning up, invalid PID %d", mmdbr_pipe.pid);
        return;
    }

    ws_close(mmdbr_pipe.stdin_fd);
    fclose(mmdbr_stdout);
    MMDB_DEBUG("closing pid %d", mmdbr_pipe.pid);
    g_spawn_close_pid(mmdbr_pipe.pid);
    mmdbr_pipe.pid = WS_INVALID_PID;
    mmdbr_stdout = NULL;
}

/**
 * Start an mmdbresolve process.
 */
static void mmdb_resolve_start(void) {
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
    char *mmdbresolve = g_strdup_printf("%s%c%s", get_progfile_dir(), G_DIR_SEPARATOR, "mmdbresolve");
    g_ptr_array_add(args, mmdbresolve);
    for (guint i = 0; i < mmdb_file_arr->len; i++) {
        g_ptr_array_add(args, g_strdup("-f"));
        g_ptr_array_add(args, g_strdup((const gchar *)g_ptr_array_index(mmdb_file_arr, i)));
    }
    g_ptr_array_add(args, NULL);

    ws_pipe_init(&mmdbr_pipe);
    mmdbr_stdout = NULL;
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

    // XXX Should we set O_NONBLOCK similar to dumpcap?
    mmdbr_stdout = ws_fdopen(mmdbr_pipe.stdout_fd, "r");
    setvbuf(mmdbr_stdout, NULL, _IONBF, 0);

    // [init]
    process_mmdbr_stdout();
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
                char *datname = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", dirname, name);
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

/**
 * Public API
 */

gboolean maxmind_db_lookup_process(void)
{
    if (!ws_pipe_valid(&mmdbr_pipe)) return FALSE;

    return process_mmdbr_stdout();
}

const mmdb_lookup_t *
maxmind_db_lookup_ipv4(guint32 addr) {
    mmdb_lookup_t *result = (mmdb_lookup_t *) wmem_map_lookup(mmdb_ipv4_map, GUINT_TO_POINTER(addr));

    // XXX Should we call maxmind_db_lookup_process first?
    if (!result) {
        if (ws_pipe_valid(&mmdbr_pipe)) {
            char addr_str[WS_INET_ADDRSTRLEN + 1];
            ws_inet_ntop4(&addr, addr_str, WS_INET_ADDRSTRLEN);
            MMDB_DEBUG("looking up %s", addr_str);
            g_strlcat(addr_str, "\n", (gsize) sizeof(addr_str));
            ssize_t write_status = ws_write(mmdbr_pipe.stdin_fd, addr_str, (unsigned int)strlen(addr_str));
            if (write_status < 0) {
                MMDB_DEBUG("write error %s", g_strerror(errno));
                mmdb_resolve_stop();
            }
        }

        result = &mmdb_not_found;
        wmem_map_insert(mmdb_ipv4_map, GUINT_TO_POINTER(addr), result);
    }

    return result;
}

const mmdb_lookup_t *
maxmind_db_lookup_ipv6(const ws_in6_addr *addr) {
    mmdb_lookup_t * result = (mmdb_lookup_t *) wmem_map_lookup(mmdb_ipv6_map, addr->bytes);

    // XXX Should we call maxmind_db_lookup_process first?
    if (!result) {
        if (ws_pipe_valid(&mmdbr_pipe)) {
            char addr_str[WS_INET6_ADDRSTRLEN + 1];
            ws_inet_ntop6(addr, addr_str, WS_INET6_ADDRSTRLEN);
            MMDB_DEBUG("looking up %s", addr_str);
            g_strlcat(addr_str, "\n", (gsize) sizeof(addr_str));
            ssize_t write_status = ws_write(mmdbr_pipe.stdin_fd, addr_str, (unsigned int)strlen(addr_str));
            if (write_status < 0) {
                MMDB_DEBUG("write error %s", g_strerror(errno));
                mmdb_resolve_stop();
            }
        }

        result = &mmdb_not_found;
        wmem_map_insert(mmdb_ipv6_map, chunkify_v6_addr(addr), result);
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
maxmind_db_lookup_ipv4(guint32 addr _U_) {
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
