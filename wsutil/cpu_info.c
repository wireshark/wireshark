/* cpu_info.c
 * Routines to report CPU information
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>
#include <glib.h>

#include <wsutil/ws_cpuid.h>
#include <wsutil/cpu_info.h>
#include <wsutil/file_util.h>

#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__) || defined(__APPLE__)
  #define HAVE_SYSCTL
#elif defined(sun) || defined(__sun)
  #define HAVE_SYSINFO
#endif

#if defined(_WIN32)
  #include <windows.h>
#elif defined(HAVE_SYSCTL)
  #include <sys/types.h>
  #include <sys/sysctl.h>
#elif defined(HAVE_SYSINFO)
  #include <sys/systeminfo.h>
#endif

/*
 * Functions used for the GTree we use to keep a list of *unique*
 * model strings.
 */
static gint
compare_model_names(gconstpointer a, gconstpointer b, gpointer user_data _U_)
{
    return strcmp((const char *)a, (const char *)b);
}

struct string_info {
    GString *str;
    const char *sep;
};

static gboolean
add_model_name_to_string(gpointer key, gpointer value _U_,
                         gpointer data)
{
    struct string_info *info = (struct string_info *)data;

    /* Separate this from the previous entry, if necessary. */
    if (info->sep != NULL)
        g_string_append(info->str, info->sep);

    /* Now add the model name. */
    g_string_append(info->str, (char *)key);

    /*
     * There will *definitely* need to be a separator for any subsequent
     * model string.
     */
    info->sep = ", ";

    /* Keep going. */
    return FALSE;
}

/*
 * Get the CPU info, and append it to the GString
 *
 * On at least some OSes, there's a call that will return this information
 * for all CPU types for which the OS determines that information, not just
 * x86 processors with CPUID and the brand string.  On those OSes, we use
 * that.
 *
 * On other OSes, we use ws_cpuid(), which will fail unconditionally on
 * non-x86 CPUs.
 */
void
get_cpu_info(GString *str)
{
    GTree *model_names = g_tree_new_full(compare_model_names, NULL, g_free, NULL);

#if defined(__linux__)
    /*
     * We scan /proc/cpuinfo looking for lines that begins with
     * "model name\t: ", and extract what comes after that prefix.
     *
     * /proc/cpuinfo can report information about multiple "CPU"s.
     * A "CPU" appears to be a CPU core, so this treats a multi-core
     * chip as multiple CPUs (which is arguably should), but doesn't
     * appear to treat a multi-threaded core as multiple CPUs.
     *
     * So we accumulate a table of *multiple* CPU strings, saving
     * one copy of each unique string, and glue them together at
     * the end.  We use a GTree for this.
     *
     * We test for Linux first, so that, even if you're on a Linux
     * that supports sysctl(), we don't use it, we scan /proc/cpuinfo,
     * as that's the right way to do this.
     */
    FILE *proc_cpuinfo;

    proc_cpuinfo = ws_fopen("/proc/cpuinfo", "r");
    if (proc_cpuinfo == NULL) {
        /* Just give up. */
        g_tree_destroy(model_names);
        return;
    }

    char *line = NULL;
    size_t linecap = 0;
    static const char prefix[] = "model name\t: ";
    #define PREFIX_STRLEN (sizeof prefix - 1)
    ssize_t linelen;

    /*
     * Read lines from /proc/cpuinfo; stop when we either hit an EOF
     * or get an error.
     */
    for (;;) {
        linelen = getline(&line, &linecap, proc_cpuinfo);
        if (linelen == -1) {
           /* EOF or error; just stop. */
           break;
        }
        /* Remove trailing newline. */
        if (linelen != 0)
            line[linelen - 1] = '\0';
        if (strncmp(line, prefix, PREFIX_STRLEN) == 0) {
            /* OK, we have a model name. */
            char *model_name;

            /* Get everything after the prefix. */
            model_name = g_strdup(line + PREFIX_STRLEN);

            /*
             * Add an entry to the tree with the model name as key and
             * a null value.  There will only be one such entry in the
             * tree; if there's already such an entry, it will be left
             * alone, and model_name will be freed, otherwise a new
             * node will be created using model_name as the key.
             *
             * Thus, we don't free model_name; either it will be freed
             * for us, or it will be used in the tree and freed when we
             * free the tree.
             */
            g_tree_insert(model_names, model_name, NULL);
        }
    }

    fclose(proc_cpuinfo);
#define xx_free free  /* hack so checkAPIs doesn't complain */
    xx_free(line);    /* yes, free(), as getline() mallocates it */
#elif defined(_WIN32)
    /*
     * They're in the Registry.  (Isn't everything?)
     */
    HKEY processors_key;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor",
                      0, KEY_READ, &processors_key) != ERROR_SUCCESS) {
        /* Just give up. */
        g_tree_destroy(model_names);
        return;
    }

    /*
     * The processors appear under that key.  Enumerate all the keys
     * under it.
     */
    DWORD num_subkeys;
    DWORD max_subkey_len;
    wchar_t *subkey_buf;

    /*
     * How many subkeys are there, and what's the biggest subkey size?
     *
     * I assume that when the documentation says that some number is
     * in units of "Unicode characters" they mean "units of elements
     * of UTF-16 characters", i.e. "units of 2-octet items".
     */
    if (RegQueryInfoKeyW(processors_key, NULL, NULL, NULL, &num_subkeys,
                         &max_subkey_len, NULL, NULL, NULL, NULL, NULL,
                         NULL) != ERROR_SUCCESS) {
        /* Just give up. */
        g_tree_destroy(model_names);
        return;
    }

    /*
     * max_subkey_len does not count the trailing '\0'.  Add it.
     */
    max_subkey_len++;

    /*
     * Allocate a buffer for the subkey.
     */
    subkey_buf = (wchar_t *)g_malloc(max_subkey_len * sizeof (wchar_t));
    if (subkey_buf == NULL) {
        /* Just give up. */
        g_tree_destroy(model_names);
        return;
    }

    for (DWORD processor_index = 0; processor_index < num_subkeys;
         processor_index++) {
        /*
         * The documentation says that this is "in characters"; I'm
         * assuming, for now, that they mean "Unicode characters",
         * meaning "2-octet items".
         */
        DWORD subkey_bufsize = max_subkey_len;
        if (RegEnumKeyExW(processors_key, processor_index, subkey_buf,
                          &subkey_bufsize, NULL, NULL, NULL,
                          NULL) != ERROR_SUCCESS) {
            /* Just exit the loop. */
            break;
        }

        /*
         * Get the length of processor name string for this processor.
         *
         * That's the "ProcessorNameString" value for the subkey of
         * processors_key with the name in subkey_buf.
         *
         * It's a string, so only allow REG_SZ values.
         */
        DWORD model_name_bufsize;

        model_name_bufsize = 0;
        if (RegGetValueW(processors_key, subkey_buf, L"ProcessorNameString",
                         RRF_RT_REG_SZ, NULL, NULL,
                         &model_name_bufsize) != ERROR_SUCCESS) {
            /* Just exit the loop. */
            break;
        }

        /*
         * Allocate a buffer for the string, as UTF-16.
         * The retrieved length includes the terminating '\0'.
         */
        wchar_t *model_name_wchar = g_malloc(model_name_bufsize);
        if (RegGetValueW(processors_key, subkey_buf, L"ProcessorNameString",
                         RRF_RT_REG_SZ, NULL, model_name_wchar,
                         &model_name_bufsize) != ERROR_SUCCESS) {
            /* Just exit the loop. */
            g_free(model_name_wchar);
            break;
        }

        /* Convert it to UTF-8. */
        char *model_name = g_utf16_to_utf8(model_name_wchar, -1, NULL, NULL, NULL);
        g_free(model_name_wchar);

        /*
         * Add an entry to the tree with the model name as key and
         * a null value.  There will only be one such entry in the
         * tree; if there's already such an entry, it will be left
         * alone, and model_name will be freed, otherwise a new
         * node will be created using model_name as the key.
         *
         * Thus, we don't free model_name; either it will be freed
         * for us, or it will be used in the tree and freed when we
         * free the tree.
         */
        g_tree_insert(model_names, model_name, NULL);
    }

    g_free(subkey_buf);

    /*
     * Close the registry key.
     */
    RegCloseKey(processors_key);
#elif defined(HAVE_SYSCTL)
    /*
     * Fetch the string using the appropriate sysctl.
     */
    size_t model_name_len;
    char *model_name;
  #if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    /*
     * Thanks, OpenBSD guys, for not having APIs to map MIB names to
     * MIB values!  Just consruct the MIB entry directly.
     *
     * We also do that for FreeBSD and DragonFly BSD, because we can.
     *
     * FreeBSD appears to support this for x86, PowerPC/Power ISA, and
     * Arm.  OpenBSD appears to support this for a number of
     * architectures.  DragonFly BSD appears to support it only for
     * x86, but I think they only run on x86-64 now, and may never
     * have run on anything non-x86.
     */
    int mib[2] = { CTL_HW, HW_MODEL };
    size_t miblen = 2;
  #else
    /* These require a lookup, as they don't have #defines. */
    #if defined(__APPLE__) /* Darwin */
        /*
         * The code seems to support this on both x86 and ARM.
         */
        #define BRAND_STRING_SYSCTL "machdep.cpu.brand_string"
        #define MIB_DEPTH 3
    #elif defined(__NetBSD__)
        /*
         * XXX - the "highly portable Unix-like Open Source operating
         * system" that "is available for a wide range of platforms"
         * doesn't seem to support this except on x86, and doesn't
         * seem to support any other MIB for, for example, ARM64.
         *
         * Maybe someday, so use it anyway.
         */
        #define BRAND_STRING_SYSCTL "machdep.cpu_brand"
        #define MIB_DEPTH 2
    #endif
    int mib[MIB_DEPTH];
    size_t miblen = MIB_DEPTH;

    /* Look up the sysctl name and get the MIB. */
    if (sysctlnametomib(BRAND_STRING_SYSCTL, mib, &miblen) == -1) {
        /*
         * Either there's no such string or something else went wrong.
         * Just give up.
         */
        g_tree_destroy(model_names);
        return;
    }
  #endif
    if (sysctl(mib, (u_int)miblen, NULL, &model_name_len, NULL, 0) == -1) {
        /*
         * Either there's no such string or something else went wrong.
         * Just give up.
         */
        g_tree_destroy(model_names);
        return;
    }
    model_name = g_malloc(model_name_len);
    if (sysctl(mib, (u_int)miblen, model_name, &model_name_len, NULL, 0) == -1) {
        /*
         * Either there's no such string or something else went wrong.
         * Just give up.
         */
        g_free(model_name);
        g_tree_destroy(model_names);
        return;
    }
    g_tree_insert(model_names, model_name, NULL);
#elif defined(HAVE_SYSINFO) && defined(SI_CPUBRAND)
    /*
     * Solaris.  Use sysinfo() with SI_CPUBRAND; the documentation
     * indicates that it works on SPARC as well as x86.
     *
     * Unfortunately, SI_CPUBRAND seems to be a recent addition, so
     * older versions of Solaris - dating back to some versions of
     * 11.3 - don't have it.
     */
    int model_name_len;
    char *model_name;

    /* How big is the model name? */
    model_name_len = sysinfo(SI_CPUBRAND, NULL, 0);
    if (model_name_len == -1) {
        g_tree_destroy(model_names);
        return;
    }
    model_name = g_malloc(model_name_len);
    if (sysinfo(SI_CPUBRAND, model_name, model_name_len) == -1) {
        g_tree_destroy(model_names);
        return;
    }
    g_tree_insert(model_names, model_name, NULL);
#else
    /*
     * OS for which we don't support the "get the CPU type" call; we
     * use ws_cpuid(), which uses CPUID on x86 and doesn't get any
     * information for other instruction sets.
     */
    guint32 CPUInfo[4];
    char CPUBrandString[0x40];
    unsigned nExIds;

    /*
     * Calling ws_cpuid with 0x80000000 as the selector argument, i.e.
     * executing a cpuid instruction with EAX equal to 0x80000000 and
     * ECX equal to 0, gets the number of valid extended IDs.
     */
    if (!ws_cpuid(CPUInfo, 0x80000000)) {
        g_tree_destroy(model_names);
        return;
    }

    nExIds = CPUInfo[0];

    if (nExIds<0x80000005) {
        g_tree_destroy(model_names);
        return;
    }

    memset(CPUBrandString, 0, sizeof(CPUBrandString));

    /* Interpret CPU brand string */
    ws_cpuid(CPUInfo, 0x80000002);
    memcpy(CPUBrandString, CPUInfo, sizeof(CPUInfo));
    ws_cpuid(CPUInfo, 0x80000003);
    memcpy(CPUBrandString + 16, CPUInfo, sizeof(CPUInfo));
    ws_cpuid(CPUInfo, 0x80000004);
    memcpy(CPUBrandString + 32, CPUInfo, sizeof(CPUInfo));

    model_name = g_strdup(g_strstrip(CPUBrandString));
    g_tree_insert(model_names, model_name, NULL);
#endif

    gint num_model_names = g_tree_nnodes(model_names);

    if (num_model_names > 0) {
        /*
         * We have at least one model name, so add the name(s) to
         * the string.
         *
         * If the string is not empty, separate the name(s) from
         * what precedes it.
         */
        if (str->len > 0)
            g_string_append(str, ", with ");

        if (num_model_names > 1) {
            /*
             * There's more than one, so put the list inside curly
             * brackets.
             */
            g_string_append(str, "{ ");
        }

        /* Iterate over the tree, adding model names to the string. */
        struct string_info info;
        info.str = str;
        info.sep = NULL;
        g_tree_foreach(model_names, add_model_name_to_string, &info);

        if (num_model_names > 1) {
            /*
             * There's more than one, so put the list inside curly
             * brackets.
             */
            g_string_append(str, " }");
        }
    }

    /* We're done; get rid of the tree. */
    g_tree_destroy(model_names);

    /*
     * We do this on all OSes and instruction sets, so that we don't
     * have to figure out how to dredge the "do we have SSE 4.2?"
     * information from whatever source provides it in the OS on
     * x86 processors.  We already have ws_cpuid_sse42() (which we
     * use to determine whether to use SSE 4.2 code to scan buffers
     * for strings), so use that; it always returns "false" on non-x86
     * processors.
     *
     * If you have multiple CPUs, some of which support it and some
     * of which don't, I'm not sure we can guarantee that buffer
     * scanning will work if, for example, the scanning code gets
     * preempted while running on an SSE-4.2-capable CPU  and, when
     * it gets rescheduled, gets rescheduled on a non-SSE-4.2-capable
     * CPU and tries to continue the SSE 4.2-based scan.  So we don't
     * worry about that case; constructing a CPU string is the *least*
     * of our worries in that case.
     */
    if (ws_cpuid_sse42())
        g_string_append(str, " (with SSE4.2)");
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
