/* process_lookup-linux.c
 * Look up the processes that have a network socket open: Linux, through /proc
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#define WS_LOG_DOMAIN LOG_DOMAIN_WSUTIL

#include "process_lookup_int.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

/*
 * The sockets come from /proc/net/{tcp,tcp6,udp,udp6}, which list every
 * socket in the network namespace with its owner's UID and its inode, and
 * the processes that have each open from the socket inodes in
 * /proc/<pid>/fd, which can be read for the caller's own processes and,
 * with CAP_SYS_PTRACE or as root, for everybody's. Sockets nobody has open
 * any more, such as TIME_WAIT ones, have inode 0 and are skipped.
 */

#define NS_PER_S 1000000000ULL

typedef struct {
    GHashTable *inode_to_pids;  /* uint64_t * -> GArray of the uint32_t pids that have the socket open */
    uint64_t    boot_time_s;    /* seconds since the Epoch */
    long        clk_tck;
} linux_state_t;

static void
pid_array_free(void *p)
{
    g_array_free((GArray *)p, TRUE);
}

static uint64_t
read_boot_time(void)
{
    char *contents = NULL;
    const char *line;
    uint64_t btime = 0;

    if (!g_file_get_contents("/proc/stat", &contents, NULL, NULL))
        return 0;
    line = strstr(contents, "btime ");
    if (line != NULL && (line == contents || line[-1] == '\n'))
        btime = g_ascii_strtoull(line + 6, NULL, 10);
    g_free(contents);
    return btime;
}

static void *
linux_open(char **err_msg)
{
    linux_state_t *state;

    if (access("/proc/net/tcp", R_OK) != 0) {
        *err_msg = ws_strdup_printf("Cannot read /proc/net/tcp: %s", g_strerror(errno));
        return NULL;
    }
    state = g_new0(linux_state_t, 1);
    state->inode_to_pids = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, pid_array_free);
    state->boot_time_s = read_boot_time();
    state->clk_tck = sysconf(_SC_CLK_TCK);
    if (state->clk_tck <= 0)
        state->clk_tck = 100;
    return state;
}

static void
linux_close(void *p)
{
    linux_state_t *state = (linux_state_t *)p;

    g_hash_table_destroy(state->inode_to_pids);
    g_free(state);
}

/* Read /proc/<pid>/<file> into a g_malloc()ed buffer; NULL if it can't be read. */
static char *
read_proc_file(uint32_t pid, const char *file, size_t *len)
{
    char path[64];
    char *contents = NULL;
    gsize contents_len = 0;

    snprintf(path, sizeof path, "/proc/%u/%s", pid, file);
    if (!g_file_get_contents(path, &contents, &contents_len, NULL))
        return NULL;
    if (len != NULL)
        *len = contents_len;
    return contents;
}

/* The parent and the start time, in clock ticks since boot, from the contents of /proc/<pid>/stat. */
static bool
parse_proc_stat(const char *stat, unsigned *ppid, uint64_t *start_ticks)
{
    const char *rparen = strrchr(stat, ')');  /* the name is in parentheses and may contain anything */

    return rparen != NULL &&
           sscanf(rparen + 1,
                  " %*c %u %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s %" SCNu64,
                  ppid, start_ticks) == 2;
}

/* Map every socket inode we are allowed to see to the processes that have it open. */
static void
scan_socket_fds(linux_state_t *state)
{
    DIR *proc;
    struct dirent *de;

    g_hash_table_remove_all(state->inode_to_pids);
    proc = opendir("/proc");
    if (proc == NULL)
        return;
    while ((de = readdir(proc)) != NULL) {
        char fd_dir[64];
        DIR *fds;
        struct dirent *fe;
        uint32_t pid;

        if (!g_ascii_isdigit(de->d_name[0]))
            continue;
        pid = (uint32_t)strtoul(de->d_name, NULL, 10);
        /* The names are numbers; the precisions keep the compiler from worrying about their length. */
        snprintf(fd_dir, sizeof fd_dir, "/proc/%.20s/fd", de->d_name);
        fds = opendir(fd_dir);
        if (fds == NULL)
            continue;  /* another user's process */
        while ((fe = readdir(fds)) != NULL) {
            char link_path[128], target[64];
            ssize_t len;
            unsigned long inode;

            if (!g_ascii_isdigit(fe->d_name[0]))
                continue;
            snprintf(link_path, sizeof link_path, "%s/%.20s", fd_dir, fe->d_name);
            len = readlink(link_path, target, sizeof target - 1);
            if (len <= 0)
                continue;
            target[len] = '\0';
            if (sscanf(target, "socket:[%lu]", &inode) == 1) {
                uint64_t inode_key = inode;
                GArray *pids = (GArray *)g_hash_table_lookup(state->inode_to_pids, &inode_key);

                if (pids == NULL) {
                    pids = g_array_new(FALSE, FALSE, sizeof(uint32_t));
                    g_hash_table_insert(state->inode_to_pids,
                                        g_memdup2(&inode_key, sizeof inode_key), pids);
                }
                /* A process may have it open through several descriptors; they come in a row. */
                if (pids->len == 0 || g_array_index(pids, uint32_t, pids->len - 1) != pid)
                    g_array_append_val(pids, pid);
            }
        }
        closedir(fds);
    }
    closedir(proc);
}

/*
 * Parse an address as /proc/net prints it: the 32-bit words of the address
 * as stored in memory, each printed as a hexadecimal number in host byte
 * order. Returns the IP version, or 0 if it is not an address.
 */
static uint8_t
parse_proc_addr(const char *hex, uint8_t *addr)
{
    size_t len = strlen(hex);

    if (len != 8 && len != 32)
        return 0;
    for (size_t i = 0; i < len / 8; i++) {
        char word[9];
        uint32_t w;

        memcpy(word, hex + i * 8, 8);
        word[8] = '\0';
        w = (uint32_t)strtoul(word, NULL, 16);
        memcpy(addr + i * 4, &w, sizeof w);
    }
    return (len == 8) ? 4 : 6;
}

static bool
read_socket_table(linux_state_t *state, const char *path, uint8_t protocol,
                  ws_process_lookup_add_socket_func add, void *ctx, char **err_msg)
{
    char *contents = NULL;
    GError *error = NULL;
    char **lines;

    if (!g_file_get_contents(path, &contents, NULL, &error)) {
        *err_msg = ws_strdup_printf("Cannot read %s: %s", path, error->message);
        g_error_free(error);
        return false;
    }
    lines = g_strsplit(contents, "\n", -1);
    g_free(contents);
    for (char **line = lines + 1; *line != NULL; line++) {  /* skip the header */
        char local_hex[33], remote_hex[33];
        unsigned local_port, remote_port, st, uid;
        unsigned long inode;
        uint64_t inode_key;
        uint8_t local_addr[16], remote_addr[16], ip_version;
        ws_process_lookup_socket_key_t key;
        const GArray *pids;

        if (sscanf(*line,
                   "%*d: %32[0-9A-Fa-f]:%4x %32[0-9A-Fa-f]:%4x %2x "
                   "%*[0-9A-Fa-f]:%*[0-9A-Fa-f] %*[0-9A-Fa-f]:%*[0-9A-Fa-f] %*[0-9A-Fa-f] %u %*u %lu",
                   local_hex, &local_port, remote_hex, &remote_port, &st, &uid, &inode) != 7)
            continue;
        if (inode == 0)
            continue;  /* nobody has it open (any more) */
        inode_key = inode;
        pids = (const GArray *)g_hash_table_lookup(state->inode_to_pids, &inode_key);
        if (pids == NULL)
            continue;  /* not our process, and we may not look */
        ip_version = parse_proc_addr(local_hex, local_addr);
        if (ip_version == 0 || parse_proc_addr(remote_hex, remote_addr) != ip_version)
            continue;
        ws_process_lookup_key_init(&key, protocol, ip_version,
                                   local_addr, (uint16_t)local_port,
                                   remote_addr, (uint16_t)remote_port);
        for (unsigned i = 0; i < pids->len; i++)
            add(ctx, &key, g_array_index(pids, uint32_t, i));
    }
    g_strfreev(lines);
    return true;
}

static bool
linux_refresh(void *p, ws_process_lookup_add_socket_func add, void *ctx, char **err_msg)
{
    linux_state_t *state = (linux_state_t *)p;
    static const struct {
        const char *path;
        uint8_t     protocol;
        bool        required;
    } tables[] = {
        { "/proc/net/tcp",  WS_PROCESS_LOOKUP_TCP, true },
        { "/proc/net/udp",  WS_PROCESS_LOOKUP_UDP, true },
        { "/proc/net/tcp6", WS_PROCESS_LOOKUP_TCP, false },  /* absent without IPv6 */
        { "/proc/net/udp6", WS_PROCESS_LOOKUP_UDP, false },
    };

    scan_socket_fds(state);
    for (size_t i = 0; i < G_N_ELEMENTS(tables); i++) {
        if (!tables[i].required && access(tables[i].path, R_OK) != 0)
            continue;
        if (!read_socket_table(state, tables[i].path, tables[i].protocol, add, ctx, err_msg))
            return false;
    }
    return true;
}

static bool
linux_describe(void *p, uint32_t pid, ws_process_info_t *info)
{
    linux_state_t *state = (linux_state_t *)p;
    char *stat, *comm, *status;
    unsigned ppid;
    uint64_t start_ticks;
    char path[64];
    size_t len;

    /* The process exists if it has a stat file: its parent and start time. */
    stat = read_proc_file(pid, "stat", NULL);
    if (stat == NULL)
        return false;
    if (parse_proc_stat(stat, &ppid, &start_ticks)) {
        info->has_ppid = true;
        info->ppid = ppid;
        if (state->boot_time_s != 0) {
            info->start_time_ns = state->boot_time_s * NS_PER_S +
                                  (start_ticks * NS_PER_S) / (uint64_t)state->clk_tck;
        }
    }
    g_free(stat);

    comm = read_proc_file(pid, "comm", NULL);
    if (comm != NULL) {
        g_strchomp(comm);
        if (comm[0] != '\0')
            info->name = comm;
        else
            g_free(comm);
    }

    snprintf(path, sizeof path, "/proc/%u/exe", pid);
    info->path = g_file_read_link(path, NULL);  /* NULL for another user's process, or a kernel thread */
    if (info->path != NULL && g_str_has_suffix(info->path, " (deleted)"))
        info->path[strlen(info->path) - strlen(" (deleted)")] = '\0';

    info->cmdline = (uint8_t *)read_proc_file(pid, "cmdline", &len);
    if (info->cmdline != NULL) {
        while (len > 0 && info->cmdline[len - 1] == '\0')
            len--;  /* the arguments are NUL-terminated; the last one need not be */
        if (len == 0) {
            g_free(info->cmdline);  /* a kernel thread */
            info->cmdline = NULL;
        }
        info->cmdline_len = len;
    }

    status = read_proc_file(pid, "status", NULL);
    if (status != NULL) {
        const char *uid_line = strstr(status, "\nUid:");
        unsigned uid;

        if (uid_line != NULL && sscanf(uid_line + 5, " %u", &uid) == 1) {
            struct passwd pwd, *result = NULL;
            char buf[4096];

            info->has_uid = true;
            info->uid = uid;
            if (getpwuid_r(uid, &pwd, buf, sizeof buf, &result) == 0 && result != NULL)
                info->user = g_strdup(pwd.pw_name);
        }
        g_free(status);
    }
    return true;
}

const ws_process_lookup_backend_t ws_process_lookup_backend = {
    true,
    linux_open,
    linux_close,
    linux_refresh,
    linux_describe,
};

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
