/* process_lookup-macos.c
 * Look up the processes that have a network socket open: macOS, through libproc
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <pwd.h>
#include <libproc.h>
#include <sys/types.h>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <netinet/in.h>

/*
 * There is no table of all the sockets with their processes that can be
 * read through a public interface: the structures of the
 * net.inet.{tcp,udp}.pcblist_n sysctls, which netstat reads, are private.
 * So, as lsof does, list the file descriptors of each process with
 * proc_pidinfo() and ask what socket is behind each one with
 * proc_pidfdinfo(). That can be done for the caller's own processes and, as
 * root, for everybody's.
 *
 * What a process is, other than its command line, can be found out for
 * every process.
 */

#define NS_PER_S  1000000000ULL
#define NS_PER_US 1000ULL

/* Room for what appears between asking for a size and asking for the data. */
#define EXTRA_PIDS 64
#define EXTRA_FDS  32

typedef struct {
    pid_t              *pids;       /* buffers that are reused from one refresh to the next */
    size_t              max_pids;
    struct proc_fdinfo *fds;
    size_t              max_fds;
} macos_state_t;

static void *
macos_create(char **err_msg)
{
    if (proc_listallpids(NULL, 0) <= 0) {
        *err_msg = ws_strdup_printf("Cannot list the processes: %s", g_strerror(errno));
        return NULL;
    }
    return g_new0(macos_state_t, 1);
}

static void
macos_destroy(void *p)
{
    macos_state_t *state = (macos_state_t *)p;

    g_free(state->pids);
    g_free(state->fds);
    g_free(state);
}

/* Report the socket behind a file descriptor, if it is a TCP or UDP one. */
static void
add_socket_fd(pid_t pid, int32_t fd, ws_process_lookup_add_socket_func add, void *ctx)
{
    struct socket_fdinfo so;
    const struct in_sockinfo *in;
    ws_process_lookup_socket_key_t key;
    const uint8_t *local_addr, *remote_addr;
    uint8_t protocol, ip_version;

    if (proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, &so, sizeof so) != (int)sizeof so)
        return;  /* closed meanwhile */
    if (so.psi.soi_family != AF_INET && so.psi.soi_family != AF_INET6)
        return;
    switch (so.psi.soi_kind) {
    case SOCKINFO_TCP:
        protocol = WS_PROCESS_LOOKUP_TCP;
        in = &so.psi.soi_proto.pri_tcp.tcpsi_ini;
        break;
    case SOCKINFO_IN:
        if (so.psi.soi_protocol != IPPROTO_UDP)
            return;  /* a raw socket, for instance */
        protocol = WS_PROCESS_LOOKUP_UDP;
        in = &so.psi.soi_proto.pri_in;
        break;
    default:
        return;
    }
    if (in->insi_lport == 0)
        return;  /* not bound, so no packet is its */

    /*
     * The kernel fills in the IPv6 form of the addresses if the socket does
     * IPv6, which includes an IPv6 socket that accepts IPv4 as well while it
     * is bound to no address, and the IPv4 form otherwise, which includes
     * an IPv6 socket that is bound or connected to an IPv4-mapped address.
     */
    if (in->insi_vflag & INI_IPV6) {
        ip_version = 6;
        local_addr = in->insi_laddr.ina_6.s6_addr;
        remote_addr = in->insi_faddr.ina_6.s6_addr;
    } else if (in->insi_vflag & INI_IPV4) {
        ip_version = 4;
        local_addr = (const uint8_t *)&in->insi_laddr.ina_46.i46a_addr4;
        remote_addr = (const uint8_t *)&in->insi_faddr.ina_46.i46a_addr4;
    } else {
        return;
    }

    /* The ports are in network byte order, in an int. */
    ws_process_lookup_key_init(&key, protocol, ip_version,
                               local_addr, g_ntohs((uint16_t)in->insi_lport),
                               remote_addr, g_ntohs((uint16_t)in->insi_fport));
    add(ctx, &key, (uint32_t)pid);
}

static bool
macos_refresh(void *p, ws_process_lookup_add_socket_func add, void *ctx, char **err_msg)
{
    macos_state_t *state = (macos_state_t *)p;
    int num_pids;

    num_pids = proc_listallpids(NULL, 0);
    if (num_pids > 0) {
        if ((size_t)num_pids + EXTRA_PIDS > state->max_pids) {
            state->max_pids = (size_t)num_pids + EXTRA_PIDS;
            state->pids = g_renew(pid_t, state->pids, state->max_pids);
        }
        num_pids = proc_listallpids(state->pids, (int)(state->max_pids * sizeof(pid_t)));
    }
    if (num_pids <= 0) {
        *err_msg = ws_strdup_printf("Cannot list the processes: %s", g_strerror(errno));
        return false;
    }

    for (int i = 0; i < num_pids; i++) {
        pid_t pid = state->pids[i];
        int size;
        size_t num_fds;

        if (pid <= 0)
            continue;  /* the kernel */
        size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
        if (size <= 0)
            continue;  /* somebody else's process, or it has exited */
        num_fds = (size_t)size / sizeof(struct proc_fdinfo) + EXTRA_FDS;
        if (num_fds > state->max_fds) {
            state->max_fds = num_fds;
            state->fds = g_renew(struct proc_fdinfo, state->fds, state->max_fds);
        }
        size = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, state->fds,
                            (int)(state->max_fds * sizeof(struct proc_fdinfo)));
        if (size <= 0)
            continue;
        num_fds = (size_t)size / sizeof(struct proc_fdinfo);
        for (size_t j = 0; j < num_fds; j++) {
            if (state->fds[j].proc_fdtype == PROX_FDTYPE_SOCKET)
                add_socket_fd(pid, state->fds[j].proc_fd, add, ctx);
        }
    }
    return true;
}

/*
 * The command line, from the KERN_PROCARGS2 sysctl: the number of arguments,
 * the path of the executable, NULs up to the next word, the arguments, each
 * of them NUL-terminated, and then the environment, which is none of our
 * business. It is only available for the caller's own processes, or to root.
 */
static void
get_cmdline(uint32_t pid, ws_process_info_t *info)
{
    int mib[3] = { CTL_KERN, KERN_PROCARGS2, (int)pid };
    size_t size = 0;
    char *buf, *p, *end, *args;
    int argc;

    if (sysctl(mib, 3, NULL, &size, NULL, 0) != 0 || size <= sizeof argc)
        return;
    buf = (char *)g_malloc(size);
    if (sysctl(mib, 3, buf, &size, NULL, 0) != 0 || size <= sizeof argc) {
        g_free(buf);
        return;
    }
    memcpy(&argc, buf, sizeof argc);
    end = buf + size;

    p = buf + sizeof argc;
    while (p < end && *p != '\0')
        p++;  /* the path of the executable */
    while (p < end && *p == '\0')
        p++;  /* the padding */
    args = p;
    for (int i = 0; i < argc && p < end; i++) {
        while (p < end && *p != '\0')
            p++;
        if (i + 1 < argc && p < end)
            p++;  /* the NUL between two arguments; there is none after the last */
    }
    if (p > args) {
        info->cmdline_len = (size_t)(p - args);
        info->cmdline = (uint8_t *)g_memdup2(args, info->cmdline_len);
    }
    g_free(buf);
}

static bool
macos_describe(void *p _U_, uint32_t pid, ws_process_detail_t detail, ws_process_info_t *info)
{
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, (int)pid };
    struct kinfo_proc kp;
    size_t size = sizeof kp;
    char name[2 * MAXCOMLEN + 1];
    char path[PROC_PIDPATHINFO_MAXSIZE];
    struct passwd pwd, *result = NULL;
    char pwd_buf[4096];

    /* This works for every process; nothing is returned if there is no such process. */
    if (pid > INT_MAX || sysctl(mib, 4, &kp, &size, NULL, 0) != 0 || size < sizeof kp)
        return false;

    info->start_time_ns = (uint64_t)kp.kp_proc.p_starttime.tv_sec * NS_PER_S +
                          (uint64_t)kp.kp_proc.p_starttime.tv_usec * NS_PER_US;

    /* p_comm holds MAXCOMLEN characters of the name; proc_name() gives twice as many, if it may. */
    if (proc_name((int)pid, name, sizeof name) > 0 && name[0] != '\0')
        info->name = g_strdup(name);
    else if (kp.kp_proc.p_comm[0] != '\0')
        info->name = g_strndup(kp.kp_proc.p_comm, sizeof kp.kp_proc.p_comm);
    if (detail != WS_PROCESS_DETAIL_FULL)
        return true;  /* the rest is not wanted, so it is not read */

    info->has_ppid = true;
    info->ppid = (uint32_t)kp.kp_eproc.e_ppid;

    if (proc_pidpath((int)pid, path, sizeof path) > 0 && path[0] != '\0')
        info->path = g_strdup(path);

    get_cmdline(pid, info);

    info->has_uid = true;
    info->uid = (uint32_t)kp.kp_eproc.e_pcred.p_ruid;
    if (getpwuid_r((uid_t)info->uid, &pwd, pwd_buf, sizeof pwd_buf, &result) == 0 && result != NULL)
        info->user = g_strdup(pwd.pw_name);
    return true;
}

const ws_process_lookup_backend_t ws_process_lookup_backend = {
    true,
    macos_create,
    macos_destroy,
    macos_refresh,
    macos_describe,
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
