/* process_lookup-win32.c
 * Look up the process that owns a network socket: Windows, through the
 * IP Helper API, which reports one process per socket
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

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <shellapi.h>
#include <sddl.h>

#include <string.h>

#include <wsutil/nstime.h>

/*
 * The sockets come from GetExtendedTcpTable() and GetExtendedUdpTable(),
 * which list every socket on the system with its owning process, the one
 * that bound it (a socket inherited by or duplicated into another process
 * is still attributed to that one), and need no privilege. Several sockets
 * on the same endpoint, with SO_REUSEADDR, are listed each with their own
 * process. What can be found out about a process depends on the
 * caller's access to it: the name and parent of every process come from a
 * Toolhelp snapshot, the path, start time and user from a limited-query
 * handle, and the command line from reading the process's memory, which
 * usually works for the caller's own processes only. Sockets that no
 * process owns any more, such as TIME_WAIT ones, have process ID 0 and
 * are skipped.
 */

typedef struct {
    uint32_t ppid;
    char    *name;
} toolhelp_entry_t;

typedef NTSTATUS (NTAPI *NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct {
    GHashTable *processes;  /* pid -> toolhelp_entry_t *, from the last refresh */
    NtQueryInformationProcess_t query_process;
} win32_state_t;

static void
toolhelp_entry_free(void *p)
{
    toolhelp_entry_t *entry = (toolhelp_entry_t *)p;

    g_free(entry->name);
    g_free(entry);
}

static void *
win32_open(char **err_msg _U_)
{
    win32_state_t *state = g_new0(win32_state_t, 1);
    HMODULE ntdll;

    state->processes = g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                             NULL, toolhelp_entry_free);
    /* Not a documented import; look it up, and do without if it's not there. */
    ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll != NULL) {
        state->query_process = (NtQueryInformationProcess_t)(void (*)(void))
            GetProcAddress(ntdll, "NtQueryInformationProcess");
    }
    return state;
}

static void
win32_close(void *p)
{
    win32_state_t *state = (win32_state_t *)p;

    g_hash_table_destroy(state->processes);
    g_free(state);
}

/* The name and parent of every process, in one go. */
static void
load_toolhelp_snapshot(win32_state_t *state)
{
    HANDLE snapshot;
    PROCESSENTRY32W pe;

    g_hash_table_remove_all(state->processes);
    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;
    pe.dwSize = sizeof pe;
    if (Process32FirstW(snapshot, &pe)) {
        do {
            toolhelp_entry_t *entry = g_new0(toolhelp_entry_t, 1);

            entry->ppid = pe.th32ParentProcessID;
            entry->name = g_utf16_to_utf8(pe.szExeFile, -1, NULL, NULL, NULL);
            g_hash_table_insert(state->processes, GUINT_TO_POINTER(pe.th32ProcessID), entry);
        } while (Process32NextW(snapshot, &pe));
    }
    CloseHandle(snapshot);
}

typedef DWORD (*fetch_table_func)(void *table, DWORD *size);

static DWORD
fetch_tcp4(void *table, DWORD *size)
{
    return GetExtendedTcpTable(table, size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
}

static DWORD
fetch_tcp6(void *table, DWORD *size)
{
    return GetExtendedTcpTable(table, size, FALSE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
}

static DWORD
fetch_udp4(void *table, DWORD *size)
{
    return GetExtendedUdpTable(table, size, FALSE, AF_INET, UDP_TABLE_OWNER_PID, 0);
}

static DWORD
fetch_udp6(void *table, DWORD *size)
{
    return GetExtendedUdpTable(table, size, FALSE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
}

/* Fetch a table into a g_malloc()ed buffer, growing it as the table grows. */
static void *
fetch_table(fetch_table_func fetch, const char *what, char **err_msg)
{
    void *table = NULL;
    DWORD size = 0;

    for (int attempt = 0; attempt < 5; attempt++) {
        DWORD ret = fetch(table, &size);

        if (ret == NO_ERROR && table != NULL)
            return table;
        if (ret != ERROR_INSUFFICIENT_BUFFER && !(ret == NO_ERROR && table == NULL)) {
            g_free(table);
            *err_msg = ws_strdup_printf("Cannot get the %s table: error %lu", what, (unsigned long)ret);
            return NULL;
        }
        g_free(table);
        table = g_malloc(size);
    }
    g_free(table);
    *err_msg = ws_strdup_printf("Cannot get the %s table: it keeps growing", what);
    return NULL;
}

/* The port fields hold the port in network byte order in their low 16 bits. */
static uint16_t
table_port(DWORD port)
{
    return GUINT16_FROM_BE((uint16_t)port);
}

static bool
win32_refresh(void *p, ws_process_lookup_add_socket_func add, void *ctx, char **err_msg)
{
    win32_state_t *state = (win32_state_t *)p;
    ws_process_lookup_socket_key_t key;
    MIB_TCPTABLE_OWNER_PID *tcp4;
    MIB_TCP6TABLE_OWNER_PID *tcp6;
    MIB_UDPTABLE_OWNER_PID *udp4;
    MIB_UDP6TABLE_OWNER_PID *udp6;

    load_toolhelp_snapshot(state);

    tcp4 = (MIB_TCPTABLE_OWNER_PID *)fetch_table(fetch_tcp4, "IPv4 TCP", err_msg);
    if (tcp4 == NULL)
        return false;
    for (DWORD i = 0; i < tcp4->dwNumEntries; i++) {
        const MIB_TCPROW_OWNER_PID *row = &tcp4->table[i];

        if (row->dwOwningPid == 0)
            continue;
        ws_process_lookup_key_init(&key, WS_PROCESS_LOOKUP_TCP, 4,
                                   (const uint8_t *)&row->dwLocalAddr, table_port(row->dwLocalPort),
                                   (const uint8_t *)&row->dwRemoteAddr, table_port(row->dwRemotePort));
        add(ctx, &key, row->dwOwningPid);
    }
    g_free(tcp4);

    tcp6 = (MIB_TCP6TABLE_OWNER_PID *)fetch_table(fetch_tcp6, "IPv6 TCP", err_msg);
    if (tcp6 == NULL)
        return false;
    for (DWORD i = 0; i < tcp6->dwNumEntries; i++) {
        const MIB_TCP6ROW_OWNER_PID *row = &tcp6->table[i];

        if (row->dwOwningPid == 0)
            continue;
        ws_process_lookup_key_init(&key, WS_PROCESS_LOOKUP_TCP, 6,
                                   row->ucLocalAddr, table_port(row->dwLocalPort),
                                   row->ucRemoteAddr, table_port(row->dwRemotePort));
        add(ctx, &key, row->dwOwningPid);
    }
    g_free(tcp6);

    udp4 = (MIB_UDPTABLE_OWNER_PID *)fetch_table(fetch_udp4, "IPv4 UDP", err_msg);
    if (udp4 == NULL)
        return false;
    for (DWORD i = 0; i < udp4->dwNumEntries; i++) {
        const MIB_UDPROW_OWNER_PID *row = &udp4->table[i];

        if (row->dwOwningPid == 0)
            continue;
        ws_process_lookup_key_init(&key, WS_PROCESS_LOOKUP_UDP, 4,
                                   (const uint8_t *)&row->dwLocalAddr, table_port(row->dwLocalPort),
                                   NULL, 0);
        add(ctx, &key, row->dwOwningPid);
    }
    g_free(udp4);

    udp6 = (MIB_UDP6TABLE_OWNER_PID *)fetch_table(fetch_udp6, "IPv6 UDP", err_msg);
    if (udp6 == NULL)
        return false;
    for (DWORD i = 0; i < udp6->dwNumEntries; i++) {
        const MIB_UDP6ROW_OWNER_PID *row = &udp6->table[i];

        if (row->dwOwningPid == 0)
            continue;
        ws_process_lookup_key_init(&key, WS_PROCESS_LOOKUP_UDP, 6,
                                   row->ucLocalAddr, table_port(row->dwLocalPort),
                                   NULL, 0);
        add(ctx, &key, row->dwOwningPid);
    }
    g_free(udp6);
    return true;
}

/* "DOMAIN\user" of the account the process runs as, or its SID if that can't be looked up. */
static char *
process_user(HANDLE process)
{
    HANDLE token;
    DWORD len = 0;
    TOKEN_USER *token_user;
    char *user = NULL;

    if (!OpenProcessToken(process, TOKEN_QUERY, &token))
        return NULL;
    GetTokenInformation(token, TokenUser, NULL, 0, &len);
    if (len == 0) {
        CloseHandle(token);
        return NULL;
    }
    token_user = (TOKEN_USER *)g_malloc(len);
    if (GetTokenInformation(token, TokenUser, token_user, len, &len)) {
        wchar_t name[256], domain[256];
        DWORD name_len = G_N_ELEMENTS(name), domain_len = G_N_ELEMENTS(domain);
        SID_NAME_USE use;
        LPWSTR sid_str;

        if (LookupAccountSidW(NULL, token_user->User.Sid, name, &name_len, domain, &domain_len, &use)) {
            char *name8 = g_utf16_to_utf8(name, -1, NULL, NULL, NULL);
            char *domain8 = g_utf16_to_utf8(domain, -1, NULL, NULL, NULL);

            if (name8 != NULL) {
                user = (domain8 != NULL && domain8[0] != '\0') ?
                    ws_strdup_printf("%s\\%s", domain8, name8) : g_strdup(name8);
            }
            g_free(name8);
            g_free(domain8);
        } else if (ConvertSidToStringSidW(token_user->User.Sid, &sid_str)) {
            user = g_utf16_to_utf8(sid_str, -1, NULL, NULL, NULL);
            LocalFree(sid_str);
        }
    }
    g_free(token_user);
    CloseHandle(token);
    return user;
}

/* The command line, read from the process's memory and split into arguments. */
static void
process_cmdline(win32_state_t *state, HANDLE process, ws_process_info_t *info)
{
    PROCESS_BASIC_INFORMATION pbi;
    PEB peb;
    RTL_USER_PROCESS_PARAMETERS params;
    SIZE_T got;
    size_t chars;
    wchar_t *cmdline;
    int argc;
    LPWSTR *argv;
    GByteArray *out;

    if (state->query_process == NULL)
        return;
    if (state->query_process(process, ProcessBasicInformation, &pbi, sizeof pbi, NULL) != 0 ||
        pbi.PebBaseAddress == NULL)
        return;
    if (!ReadProcessMemory(process, pbi.PebBaseAddress, &peb, sizeof peb, &got) || got != sizeof peb)
        return;
    if (peb.ProcessParameters == NULL ||
        !ReadProcessMemory(process, peb.ProcessParameters, &params, sizeof params, &got) ||
        got != sizeof params)
        return;
    if (params.CommandLine.Buffer == NULL || params.CommandLine.Length == 0)
        return;
    chars = params.CommandLine.Length / sizeof(wchar_t);
    cmdline = g_new0(wchar_t, chars + 1);
    if (!ReadProcessMemory(process, params.CommandLine.Buffer, cmdline,
                           params.CommandLine.Length, &got) ||
        got != params.CommandLine.Length) {
        g_free(cmdline);
        return;
    }
    argv = CommandLineToArgvW(cmdline, &argc);
    g_free(cmdline);
    if (argv == NULL)
        return;
    out = g_byte_array_new();
    for (int i = 0; i < argc; i++) {
        char *arg = g_utf16_to_utf8(argv[i], -1, NULL, NULL, NULL);

        if (arg == NULL)
            continue;
        if (out->len > 0)
            g_byte_array_append(out, (const uint8_t *)"", 1);
        g_byte_array_append(out, (const uint8_t *)arg, (unsigned)strlen(arg));
        g_free(arg);
    }
    LocalFree(argv);
    if (out->len == 0) {
        g_byte_array_free(out, TRUE);
        return;
    }
    info->cmdline_len = out->len;
    info->cmdline = g_byte_array_free(out, FALSE);
}

static bool
win32_describe(void *p, uint32_t pid, ws_process_detail_t detail, ws_process_info_t *info)
{
    win32_state_t *state = (win32_state_t *)p;
    bool full = (detail == WS_PROCESS_DETAIL_FULL);
    const toolhelp_entry_t *entry;
    HANDLE process = NULL;
    bool can_read_memory = false;
    FILETIME creation, exit, kernel, user;

    entry = (const toolhelp_entry_t *)g_hash_table_lookup(state->processes, GUINT_TO_POINTER(pid));
    if (entry != NULL) {
        info->name = g_strdup(entry->name);
        if (full) {
            info->has_ppid = true;
            info->ppid = entry->ppid;
        }
    }

    /* Its memory is only read for the command line. */
    if (full) {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        can_read_memory = (process != NULL);
    }
    if (process == NULL)
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) {
        /* Not ours to look at, or gone; the snapshot may still have known it. */
        return entry != NULL;
    }

    /* The path, which is also where the name comes from if the snapshot did not have it. */
    if (full || info->name == NULL) {
        DWORD path_len = 32768;
        wchar_t *path = g_new(wchar_t, path_len);

        if (QueryFullProcessImageNameW(process, 0, path, &path_len)) {
            char *path_utf8 = g_utf16_to_utf8(path, path_len, NULL, NULL, NULL);

            if (info->name == NULL && path_utf8 != NULL)
                info->name = g_path_get_basename(path_utf8);
            if (full)
                info->path = path_utf8;
            else
                g_free(path_utf8);
        }
        g_free(path);
    }

    if (GetProcessTimes(process, &creation, &exit, &kernel, &user)) {
        uint64_t filetime = ((uint64_t)creation.dwHighDateTime << 32) | creation.dwLowDateTime;
        nstime_t start;

        if (filetime_to_nstime(&start, filetime))
            info->start_time_ns = (uint64_t)start.secs * 1000000000ULL + (uint64_t)start.nsecs;
    }

    if (full) {
        info->user = process_user(process);
        if (can_read_memory)
            process_cmdline(state, process, info);
    }

    CloseHandle(process);
    return true;
}

const ws_process_lookup_backend_t ws_process_lookup_backend = {
    true,
    win32_open,
    win32_close,
    win32_refresh,
    win32_describe,
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
