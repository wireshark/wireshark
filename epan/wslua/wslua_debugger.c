/* wslua_debugger.c
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "init_wslua.h"
#include "wslua.h"
#include "wslua_debugger.h"
#include <glib.h>
#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/report_message.h>
#include <wsutil/ws_assert.h>

typedef enum
{
    WSLUA_STEP_KIND_NONE = 0,
    WSLUA_STEP_KIND_IN,   /**< Next line hook anywhere (step into calls) */
    WSLUA_STEP_KIND_OVER, /**< Next line at same or outer stack depth */
    WSLUA_STEP_KIND_OUT   /**< Pause when returning to an outer frame */
} wslua_step_kind_t;

/*
 * One captured (name, value_ref) pair for a single local or upvalue of an
 * activation that was alive at the moment the runtime error fired.
 *
 * @c value_ref is a strong @c luaL_ref into the captured @c lua_State's
 * registry; it keeps the original Lua value reachable across the
 * @c lua_pcall unwind that destroys the activation. Pushing it back with
 * @c lua_rawgeti yields the same value the live frame held, so the
 * normal Watch / Variables machinery (path walker, child enumerator,
 * value formatter) can run unchanged against either a live pause or a
 * post-unwind error pause.
 *
 * Nothing else is cached here: type, value preview, full value, and
 * @c can_expand are recomputed on demand from the pushed value, exactly
 * the way the live pause path computes them. That guarantees the user
 * sees the same string for the same value in both modes and avoids
 * paying for a deep pre-capture at error time.
 */
typedef struct
{
    char *name;
    int   value_ref;
} wslua_runtime_error_binding_t;

typedef struct
{
    wslua_runtime_error_binding_t *locals;
    int32_t locals_count;
    wslua_runtime_error_binding_t *upvalues;
    int32_t upvalues_count;
} wslua_runtime_error_frame_snapshot_t;

/* debugger context */
typedef struct
{
    wslua_debugger_state_t state;
    bool enabled;
    wslua_debugger_ui_update_cb_t ui_update_callback;
    lua_State *L;
    lua_State *paused_L;
    GMutex mutex;
    bool mutex_initialized;
    wslua_breakpoint_t temporary_breakpoint;
    wslua_step_kind_t step_kind;
    int step_stack_depth; /**< Frame count captured when OVER/OUT begins */
    int32_t variable_stack_level; /**< lua_getstack index for Locals/Upvalues */
    /*
     * Set only in wslua_debugger_notify_reload() to copy debugger.enabled
     * before the reload path forces enabled false and clears L. Used by
     * wslua_debugger_restore_after_reload() to turn the debugger back on after
     * cf_reload / redissect (not by wslua_debugger_init, which is suppressed
     * while this sequence runs). Cleared on consume, on renounce, or when the
     * user sets user_explicitly_disabled (uncheck) so a pending restore does
     * not fight that intent.
     */
    bool was_enabled_before_reload;
    /*
     * True between wslua_debugger_notify_reload() and
     * wslua_debugger_notify_post_reload(). While set, wslua_debugger_init()
     * returns without auto-enabling for active breakpoints, so the line hook
     * does not run inside the reload / re-dissection stack and re-enter the
     * event loop.
     */
    bool reload_in_progress;
    /*
     * Set from the UI main enable checkbox via
     * wslua_debugger_set_user_explicitly_disabled(). When true, the user has
     * left the core debugger "off" on purpose. Gates wslua_debugger_init
     * breakpoint auto-enable, wslua_debugger_may_auto_enable_for_breakpoints,
     * wslua_debugger_run_to_line, and a secondary check in
     * wslua_debugger_restore_after_reload. Not equivalent to !enabled — the
     * core can be off for other reasons (e.g. live capture) without this bit
     * being set, and it persists across operations that do not touch
     * was_enabled_before_reload.
     */
    bool user_explicitly_disabled;
    /*
     * Set only in wslua_debugger_notify_reload() to copy
     * debugger.error_break_enabled before the reload path forces it false.
     * Used by wslua_debugger_restore_after_reload() to turn break-on-error
     * back on after cf_reload / redissect, mirroring the
     * was_enabled_before_reload snapshot for the main enabled flag. Cleared
     * on consume, on renounce, when the user sets user_explicitly_disabled,
     * or when the user manually toggles break-on-error during the reload window so a
     * pending restore does not fight that intent.
     */
    bool error_break_was_enabled_before_reload;

    /* Break-on-error fields */
    bool error_break_enabled;        /**< User toggle for break-on-error */
    char *last_error_text;           /**< Error message from last caught error */
    int64_t last_error_line;         /**< Line number where error occurred */
    char *last_error_file;           /**< File path where error occurred */
    bool error_break_occurred;       /**< Flag set when an error break fired (any error type) */
    bool explicit_error_break_recent;/**< One-shot marker set by error()/assert() wrapper pauses */
    wslua_stack_frame_t *runtime_error_stack; /**< Captured pre-unwind stack */
    int32_t runtime_error_stack_count; /**< Number of captured stack frames */
    wslua_runtime_error_frame_snapshot_t *runtime_error_frame_snapshots; /**< Captured pre-unwind Locals/Upvalues per frame */
    lua_State *runtime_error_stack_L; /**< Lua state used when snapshot was taken */
    bool runtime_error_pause_active; /**< True while a deferred runtime-error pause is active */
    int original_error_ref;          /**< LUA_REGISTRYINDEX ref to original error() function */
    int original_assert_ref;         /**< LUA_REGISTRYINDEX ref to original assert() function */
} wslua_debugger_t;

static wslua_debugger_t debugger = {
    WSLUA_DEBUGGER_OFF,
    false,
    NULL,
    NULL,
    NULL,
    {0}, /* mutex */
    false,
    {NULL, 0, false, NULL, 0, 0, WSLUA_HIT_COUNT_MODE_FROM, false, NULL, NULL, false, 0}, /* temporary_breakpoint */
    WSLUA_STEP_KIND_NONE, /* step_kind */
    0,                    /* step_stack_depth */
    0,                    /* variable_stack_level */
    false,                /* was_enabled_before_reload */
    false,                /* reload_in_progress */
    false,                /* user_explicitly_disabled */
    false,                /* error_break_was_enabled_before_reload */
    false,                /* error_break_enabled */
    NULL,                 /* last_error_text */
    0,                    /* last_error_line */
    NULL,                 /* last_error_file */
    false,                /* error_break_occurred */
    false,                /* explicit_error_break_recent */
    NULL,                 /* runtime_error_stack */
    0,                    /* runtime_error_stack_count */
    NULL,                 /* runtime_error_frame_snapshots */
    NULL,                 /* runtime_error_stack_L */
    false,                /* runtime_error_pause_active */
    LUA_NOREF,            /* original_error_ref */
    LUA_NOREF,            /* original_assert_ref */
};

/* Breakpoints (in-memory, persisted by Qt side) */
static GArray *breakpoints_array = NULL;

/*
 * Monotonic timestamp (microseconds) captured the last time the debugger
 * transitioned from disabled to enabled. Reset to 0 on disable. Used to
 * compute the {elapsed} logpoint tag; 0 means the debugger has not been
 * enabled in this process yet (or is currently disabled), in which case
 * {elapsed} reports 0ms.
 */
static int64_t debugger_start_us = 0;

static GHashTable *canonical_path_cache = NULL;
static GRWLock canonical_path_cache_lock;

/* Caller must hold debugger.mutex. */
static bool debugger_has_auto_break_triggers_locked(void)
{
    if (debugger.error_break_enabled)
    {
        return true;
    }
    if (!breakpoints_array)
    {
        return false;
    }
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (bp->active)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Ensure the canonical path cache is initialized exactly once.
 */
static void ensure_canonical_path_cache_initialized(void)
{
    static size_t canonical_cache_once = 0;
    if (g_once_init_enter(&canonical_cache_once))
    {
        g_rw_lock_init(&canonical_path_cache_lock);
        canonical_path_cache =
            g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
        g_once_init_leave(&canonical_cache_once, 1);
    }
}

/**
 * @brief Set of @c (canonical_path, line) pairs that currently host an
 *        active regular breakpoint.
 *
 * Used by @ref wslua_debug_hook to early-out on lines that aren't
 * breakpoint sites without locking @ref debugger.mutex or walking
 * @ref breakpoints_array.
 *
 * Rebuild rule: a mutator must call @ref rebuild_bp_site_set_locked
 * iff it changes whether an active breakpoint exists at a given
 * @c (canonical_path, line) pair. In practice this is:
 *  - @c wslua_debugger_set_breakpoint (adds a row, always active),
 *  - @c wslua_debugger_remove_breakpoint,
 *  - @c wslua_debugger_set_breakpoint_active (flips @c bp->active),
 *  - @c wslua_debugger_clear_breakpoints,
 *  - and the @c WSLUA_HIT_COUNT_MODE_ONCE auto-disable inside the line hook.
 *
 * The condition / hit-count target / hit-count mode / log-message /
 * log-also-pause / hit-count-reset setters intentionally do NOT
 * rebuild — they don't move sites in or out of the set, so the
 * slow path still finds the row by @c (canonical_path, line) once
 * the membership test admits the line.
 *
 * The rebuild runs under @c debugger.mutex, so the new set
 * snapshot is consistent with the array changes the slow path
 * will see on the next hook fire for the affected line.
 *
 * The temporary breakpoint (Run-To-Line) is intentionally NOT in
 * this set — it's checked separately at the bottom of the hook.
 */
typedef struct
{
    char   *path; /**< Canonical file path, owned by this entry. */
    int64_t line; /**< 1-based line number. */
} bp_site_key_t;

static GHashTable *bp_site_set = NULL;
static GRWLock bp_site_set_lock;

static guint
bp_site_key_hash(gconstpointer key)
{
    const bp_site_key_t *k = key;
    /* Mix g_str_hash of the path with the line number using the
     * boost-style combiner; keeps duplicate paths on different lines
     * well-separated in the table. */
    guint h = g_str_hash(k->path);
    h ^= (guint)k->line + 0x9e3779b9U + (h << 6) + (h >> 2);
    return h;
}

static gboolean
bp_site_key_equal(gconstpointer a, gconstpointer b)
{
    const bp_site_key_t *ka = a;
    const bp_site_key_t *kb = b;
    return ka->line == kb->line && g_str_equal(ka->path, kb->path);
}

static void
bp_site_key_free(gpointer key)
{
    bp_site_key_t *k = key;
    g_free(k->path);
    g_free(k);
}

static void
ensure_bp_site_set_initialized(void)
{
    static size_t bp_site_set_once = 0;
    if (g_once_init_enter(&bp_site_set_once))
    {
        g_rw_lock_init(&bp_site_set_lock);
        bp_site_set = g_hash_table_new_full(bp_site_key_hash,
                                             bp_site_key_equal,
                                             bp_site_key_free, NULL);
        g_once_init_leave(&bp_site_set_once, 1);
    }
}

/**
 * @brief Rebuild the breakpoint-site set from @ref breakpoints_array.
 *
 * Caller must hold @ref debugger.mutex so the array snapshot is
 * stable. This function takes @ref bp_site_set_lock as writer; the
 * hook never holds the mutex and the writer lock simultaneously, so
 * there is no lock-order inversion.
 */
static void
rebuild_bp_site_set_locked(void)
{
    ensure_bp_site_set_initialized();
    g_rw_lock_writer_lock(&bp_site_set_lock);
    g_hash_table_remove_all(bp_site_set);
    if (breakpoints_array)
    {
        for (unsigned i = 0; i < breakpoints_array->len; i++)
        {
            wslua_breakpoint_t *bp =
                &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
            if (!bp->active || !bp->file_path)
                continue;
            bp_site_key_t *k = g_new(bp_site_key_t, 1);
            k->path = g_strdup(bp->file_path);
            k->line = bp->line;
            g_hash_table_insert(bp_site_set, k, NULL);
        }
    }
    g_rw_lock_writer_unlock(&bp_site_set_lock);
}

/**
 * @brief Test whether @c (canonical_path, line) hosts an active
 *        regular breakpoint, without taking @ref debugger.mutex.
 *
 * Designed for the line-hook fast path. @a canonical_path is borrowed
 * (no copy) into a stack-allocated probe key; the equality function
 * compares by string content so the probe key's address is fine.
 */
static bool
bp_site_set_contains(const char *canonical_path, int64_t line)
{
    if (!canonical_path)
        return false;
    ensure_bp_site_set_initialized();
    bp_site_key_t probe;
    probe.path = (char *)canonical_path;
    probe.line = line;
    g_rw_lock_reader_lock(&bp_site_set_lock);
    const bool present =
        bp_site_set ? g_hash_table_contains(bp_site_set, &probe) : false;
    g_rw_lock_reader_unlock(&bp_site_set_lock);
    return present;
}

/**
 * @brief Canonicalize a file path while caching results for reuse.
 * @param file_path Path in any user-provided form.
 * @return Pointer to cached canonical path; ownership stays with the cache.
 */
static const char *
wslua_debugger_get_cached_canonical_path(const char *file_path)
{
    if (!file_path || !*file_path)
    {
        return NULL;
    }

    ensure_canonical_path_cache_initialized();

    g_rw_lock_reader_lock(&canonical_path_cache_lock);
    const char *cached_path =
        canonical_path_cache
            ? (const char *)g_hash_table_lookup(canonical_path_cache, file_path)
            : NULL;
    if (cached_path)
    {
        g_rw_lock_reader_unlock(&canonical_path_cache_lock);
        return cached_path;
    }
    g_rw_lock_reader_unlock(&canonical_path_cache_lock);

    char *canonicalized_path = g_canonicalize_filename(file_path, NULL);
    if (!canonicalized_path)
    {
        return NULL;
    }

    g_rw_lock_writer_lock(&canonical_path_cache_lock);
    const char *existing_path =
        canonical_path_cache
            ? (const char *)g_hash_table_lookup(canonical_path_cache, file_path)
            : NULL;
    if (existing_path)
    {
        g_rw_lock_writer_unlock(&canonical_path_cache_lock);
        g_free(canonicalized_path);
        return existing_path;
    }

    char *key_copy = g_strdup(file_path);
    g_hash_table_insert(canonical_path_cache, key_copy, canonicalized_path);
    g_rw_lock_writer_unlock(&canonical_path_cache_lock);
    return canonicalized_path;
}

/**
 * @brief Return a newly allocated canonical path copy for caller ownership.
 */
static char *wslua_debugger_dup_canonical_path(const char *file_path)
{
    const char *cached_path =
        wslua_debugger_get_cached_canonical_path(file_path);
    return cached_path ? g_strdup(cached_path) : NULL;
}

/**
 * @brief Determine if a breakpoint matches a canonical path + line pair.
 */
static bool
wslua_debugger_breakpoint_matches(const wslua_breakpoint_t *breakpoint,
                                  const char *canonical_path, int64_t line)
{
    if (!breakpoint || !canonical_path)
    {
        return false;
    }
    if (breakpoint->line != line)
    {
        return false;
    }

    return g_strcmp0(breakpoint->file_path, canonical_path) == 0;
}

/* Forward declarations */
static void wslua_debug_hook(lua_State *L, lua_Debug *debug_info);
static void wslua_debugger_update_hook(void);
static int wslua_debugger_count_stack_frames(lua_State *L);
static void remove_breakpoint_at(unsigned idx);
static bool wslua_debugger_entry_is_hidden(lua_State *L);
static int64_t wslua_debugger_count_visible_table_entries(lua_State *L, int idx);
static char *wslua_debugger_describe_value(lua_State *L, int idx);
static bool wslua_debugger_push_getters(lua_State *L, int idx);
static int64_t wslua_debugger_count_userdata_getters(lua_State *L, int idx);
static bool wslua_debugger_push_pairs_iterator(lua_State *L, int idx);
static bool wslua_debugger_pairs_next(lua_State *L);
static bool wslua_debugger_userdata_has_visible_pairs(lua_State *L, int idx);
static bool wslua_debugger_eval_bool_at_level0(lua_State *L,
                                                const char *expr,
                                                bool *out_truthy,
                                                char **error_msg);
static bool wslua_debugger_first_lua_location(lua_State *L,
                                              int32_t start_level,
                                              const char **out_file_src,
                                              int64_t *out_line);
static void wslua_debugger_free_stack_frames(wslua_stack_frame_t *stack,
                                             int32_t frame_count);
static wslua_stack_frame_t *
wslua_debugger_dup_stack_frames(const wslua_stack_frame_t *stack,
                                int32_t frame_count);
static bool wslua_debugger_push_function_for_ar(lua_State *L, lua_Debug *ar);
static char *wslua_debugger_format_value_type(lua_State *L, int idx);
static void wslua_debugger_clear_runtime_error_snapshot_locked(void);
static char *wslua_debugger_describe_value_ex(lua_State *L, int idx,
                                              bool truncate);
static bool wslua_debugger_value_can_expand(lua_State *L, int idx);
static int wslua_debugger_abs_index(lua_State *L, int idx);
static void wslua_debugger_basic_table_counts(lua_State *L, int idx,
                                              int64_t *total,
                                              int64_t *visible);
static bool wslua_debugger_basic_entry_is_hidden(lua_State *L);
static inline void notify_breakpoint_state_dirty(void);

/**
 * @brief Per-fire context handed to the logpoint formatter.
 *
 * All fields are snapshots captured at the moment the logpoint fires;
 * the formatter never reads any live debugger state, so the line hook
 * can pre-compute under the mutex and pass the values through.
 *
 * Fields that aren't applicable on a given fire degrade gracefully:
 *   - @c fn_name may be NULL (rendered as the empty string).
 *   - @c fn_what may be NULL (rendered as the empty string).
 *   - @c delta_ms / @c elapsed_ms are 0 when no reference timestamp is
 *     available yet (first fire / debugger start).
 *   - @c is_main_thread true means @c thread_ptr is unused.
 */
typedef struct {
    const char *file_path;     /**< {filename} / source of {basename} */
    int64_t     line;          /**< {line} */
    int64_t     hit_count;     /**< {hits} */
    int64_t     delta_ms;      /**< {delta}: ms since this bp last fired */
    int64_t     elapsed_ms;    /**< {elapsed}: ms since debugger attached */
    const char *fn_name;       /**< {function}: may be NULL */
    const char *fn_what;       /**< {what}: "Lua"/"C"/"main"/"tail"/NULL */
    int         depth;         /**< {depth}: Lua frame count */
    bool        is_main_thread; /**< {thread}: true => "main" */
    const void *thread_ptr;    /**< {thread}: coroutine id when not main */
} wslua_logpoint_context_t;

static char *wslua_debugger_format_log_message(
    lua_State *L, const char *fmt, const wslua_logpoint_context_t *ctx);
static void wslua_debugger_emit_log_message(const char *file_path,
                                             int64_t line,
                                             const char *message);

/**
 * @brief Set of expensive logpoint tags actually referenced by a
 *        template, derived from a single pass over the format string.
 *
 * Used by @ref wslua_debug_hook to skip the per-fire computation of
 * tags the user has not asked for. The scanner walks the template
 * once and sets exactly these flags; everything else (cheap source /
 * line / counter values) is populated unconditionally because it has
 * already been gathered as part of the line-hook's normal work.
 */
typedef struct {
    bool needs_depth;  /**< @c {depth} appears at least once. */
    bool needs_thread; /**< @c {thread} appears at least once. */
} wslua_logpoint_tags_t;

static void wslua_debugger_scan_log_tags(const char *fmt,
                                          wslua_logpoint_tags_t *out);
static wslua_breakpoint_t *find_breakpoint_locked(const char *canonical_path,
                                                   int64_t line);

/**
 * @brief Ensure breakpoints array is initialized.
 */
static void ensure_breakpoints_initialized(void)
{
    if (!breakpoints_array)
    {
        breakpoints_array =
            g_array_new(FALSE, TRUE, sizeof(wslua_breakpoint_t));
    }
}

/**
 * @brief Free a breakpoint's allocated memory.
 */
static void free_breakpoint(wslua_breakpoint_t *bp)
{
    if (bp)
    {
        g_free(bp->file_path);
        bp->file_path = NULL;
        g_free(bp->condition);
        bp->condition = NULL;
        g_free(bp->condition_error_msg);
        bp->condition_error_msg = NULL;
        g_free(bp->log_message);
        bp->log_message = NULL;
    }
}

/**
 * @brief Remove a breakpoint at the specified index.
 */
static void remove_breakpoint_at(unsigned idx)
{
    ensure_breakpoints_initialized();

    if (idx >= breakpoints_array->len)
        return;

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    free_breakpoint(bp);
    g_array_remove_index(breakpoints_array, idx);
}

/**
 * @brief Initialize the debugger subsystem.
 * @param L The Lua state.
 */
void wslua_debugger_init(lua_State *L)
{
    debugger.L = L;
    static bool initialized = false;

    if (!debugger.mutex_initialized)
    {
        g_mutex_init(&debugger.mutex);
        debugger.mutex_initialized = true;
    }

    if (!initialized)
    {
        /* Initialize breakpoints array */
        ensure_breakpoints_initialized();

        /* Note: JSON settings are loaded by the Qt UI (lua_debugger_dialog.cpp)
         * when the dialog is first opened. The C side only maintains in-memory
         * state. */

        initialized = true;
    }

    /*
     * During a reload, do NOT auto-enable the debugger here.
     * The hook would fire inside cf_reload → cf_read → dissectIdle,
     * potentially entering a nested event loop while deep in the
     * reload call stack.  The callers will call
     * wslua_debugger_notify_post_reload() after cf_reload completes.
     */
    g_mutex_lock(&debugger.mutex);
    const bool reload_in_progress = debugger.reload_in_progress;
    g_mutex_unlock(&debugger.mutex);
    if (reload_in_progress)
    {
        /* Don't auto-enable: the hook would fire during
         * cf_reload / redissect and re-enter the event loop.
         * wslua_debugger_restore_after_reload() handles this. */
        return;
    }

    /* Check if we should auto-enable based on active breakpoints or break-on-error. */
    bool has_auto_triggers = false;
    ensure_breakpoints_initialized();
    g_mutex_lock(&debugger.mutex);
    has_auto_triggers = debugger_has_auto_break_triggers_locked();
    g_mutex_unlock(&debugger.mutex);

    bool user_wants_debugger_off = false;
    g_mutex_lock(&debugger.mutex);
    user_wants_debugger_off = debugger.user_explicitly_disabled;
    g_mutex_unlock(&debugger.mutex);

    if (has_auto_triggers && !user_wants_debugger_off)
    {
        wslua_debugger_set_enabled(true);
    }
    else
    {
        /* Ensure hook is updated for new L */
        wslua_debugger_update_hook();
    }
}

/**
 * @brief Check if debugger is enabled.
 * @return true if enabled, false otherwise.
 */
bool wslua_debugger_is_enabled(void)
{
    g_mutex_lock(&debugger.mutex);
    bool enabled = debugger.enabled;
    g_mutex_unlock(&debugger.mutex);
    return enabled;
}

static void wslua_debugger_free_stack_frames(wslua_stack_frame_t *stack,
                                             int32_t frame_count)
{
    if (!stack || frame_count <= 0)
    {
        g_free(stack);
        return;
    }
    for (int32_t i = 0; i < frame_count; i++)
    {
        g_free(stack[i].source);
        g_free(stack[i].name);
    }
    g_free(stack);
}

static wslua_stack_frame_t *
wslua_debugger_dup_stack_frames(const wslua_stack_frame_t *stack,
                                int32_t frame_count)
{
    if (!stack || frame_count <= 0)
    {
        return NULL;
    }

    wslua_stack_frame_t *copy = g_new0(wslua_stack_frame_t, frame_count);
    for (int32_t i = 0; i < frame_count; i++)
    {
        copy[i].source = g_strdup(stack[i].source ? stack[i].source : "?");
        copy[i].line = stack[i].line;
        copy[i].linedefined = stack[i].linedefined;
        copy[i].name = g_strdup(stack[i].name ? stack[i].name : "?");
    }
    return copy;
}

static void wslua_debugger_free_variable_records(wslua_variable_t *variables,
                                                 int32_t variable_count)
{
    if (!variables)
    {
        return;
    }

    for (int32_t variable_index = 0; variable_index < variable_count;
         variable_index++)
    {
        g_free(variables[variable_index].name);
        g_free(variables[variable_index].value);
        g_free(variables[variable_index].type);
    }
    g_free(variables);
}

/*
 * The break-on-error snapshot keeps just (name, value_ref) pairs per
 * frame. Children, type strings, value previews, and the @c can_expand
 * bit are computed on demand from the pushed Lua value via the live
 * Watch helpers (@ref wslua_debugger_describe_value,
 * @ref wslua_debugger_format_value_type,
 * @ref wslua_debugger_value_can_expand,
 * @ref wslua_debugger_append_children_of_value), so the visible result
 * is byte-identical to a regular pause on the same value.
 */

/*
 * Snapshot bindings own a @c LUA_REGISTRYINDEX ref. We deliberately
 * anchor every ref on the persistent main state @c debugger.L instead
 * of the activation's @c lua_State. The capture path runs on a
 * dissector coroutine (@c L1 = @c lua_newthread() from
 * @ref dissect_lua); that coroutine is closed and garbage-collected as
 * soon as the dissector returns, but the snapshot must outlive the
 * pause loop and remain inspectable until the user disables the
 * debugger or a fresh error fires. Calling @c luaL_unref on a freed
 * coroutine pointer is use-after-free (lua_rawgeti dereferences @c L
 * to push to its stack), which manifests as an ASAN deadly-signal
 * crash inside @c clear_runtime_error_snapshot_locked. The Lua
 * registry table itself lives in the shared @c global_State, so a ref
 * created on any thread of that family can be safely released through
 * @c debugger.L — which is durable from @ref wslua_debugger_init until
 * a reload (and during a reload the snapshot has already been cleared
 * before @c debugger.L is nulled).
 */

/* Caller must hold debugger.mutex. */
static void
wslua_debugger_free_runtime_error_bindings(
    wslua_runtime_error_binding_t *bindings, int32_t binding_count)
{
    if (!bindings)
    {
        return;
    }
    lua_State *anchor_L = debugger.L;
    for (int32_t i = 0; i < binding_count; i++)
    {
        g_free(bindings[i].name);
        if (anchor_L && bindings[i].value_ref != LUA_NOREF)
        {
            luaL_unref(anchor_L, LUA_REGISTRYINDEX, bindings[i].value_ref);
        }
    }
    g_free(bindings);
}

/* Caller must hold debugger.mutex. */
static void wslua_debugger_free_runtime_error_frame_snapshots(
    wslua_runtime_error_frame_snapshot_t *frames, int32_t frame_count)
{
    if (!frames || frame_count <= 0)
    {
        g_free(frames);
        return;
    }

    for (int32_t frame_index = 0; frame_index < frame_count; frame_index++)
    {
        wslua_debugger_free_runtime_error_bindings(
            frames[frame_index].locals, frames[frame_index].locals_count);
        wslua_debugger_free_runtime_error_bindings(
            frames[frame_index].upvalues, frames[frame_index].upvalues_count);
    }
    g_free(frames);
}

/*
 * Capture a single (name, registry-ref) pair for the value at the top of
 * @a L. Pops the value. Lives on its own so the locals/upvalues capture
 * loops below stay readable. The value is moved to @c debugger.L's stack
 * via @c lua_xmove before being ref'd so the resulting ref is owned by
 * the persistent main state and survives @a L's eventual GC; see the
 * comment block above @ref wslua_debugger_free_runtime_error_bindings.
 */
static void
wslua_debugger_capture_runtime_error_binding(
    lua_State *L, const char *name, GArray *bindings_array)
{
    wslua_runtime_error_binding_t binding;
    binding.name = g_strdup(name ? name : "");
    lua_State *anchor_L = debugger.L;
    if (anchor_L && anchor_L != L)
    {
        /* Move from the (possibly transient) coroutine stack onto the
         * durable main state, then ref there. Both states share a
         * single global_State so the registry table is the same. */
        lua_xmove(L, anchor_L, 1);
        binding.value_ref = luaL_ref(anchor_L, LUA_REGISTRYINDEX);
    }
    else if (anchor_L)
    {
        binding.value_ref = luaL_ref(anchor_L, LUA_REGISTRYINDEX);
    }
    else
    {
        /* No anchor available (debugger torn down mid-capture); drop
         * the value to keep the stack balanced and skip the ref. */
        lua_pop(L, 1);
        binding.value_ref = LUA_NOREF;
    }
    g_array_append_val(bindings_array, binding);
}

static wslua_runtime_error_binding_t *
wslua_debugger_capture_locals_for_activation(lua_State *L, lua_Debug *ar,
                                             int32_t *count_out)
{
    GArray *bindings_array =
        g_array_new(false, false, sizeof(wslua_runtime_error_binding_t));

    int32_t local_index = 1;
    const char *name;
    while ((name = lua_getlocal(L, ar, local_index++)))
    {
        /* Skip Lua's internal slots ("(temporary)", "(for index)", …)
         * the same way the live Locals enumerator does in
         * wslua_debugger_get_variables(). */
        if (g_str_has_prefix(name, "("))
        {
            lua_pop(L, 1);
            continue;
        }
        wslua_debugger_capture_runtime_error_binding(L, name, bindings_array);
    }

    *count_out = (int32_t)bindings_array->len;
    return (wslua_runtime_error_binding_t *)
        g_array_free(bindings_array, false);
}

static wslua_runtime_error_binding_t *
wslua_debugger_capture_upvalues_for_activation(lua_State *L, lua_Debug *ar,
                                               int32_t *count_out)
{
    GArray *bindings_array =
        g_array_new(false, false, sizeof(wslua_runtime_error_binding_t));

    if (wslua_debugger_push_function_for_ar(L, ar))
    {
        int32_t upvalue_index = 1;
        const char *name;
        while ((name = lua_getupvalue(L, -1, upvalue_index)))
        {
            /* C closures use "" as the upvalue name; mirror the live
             * Upvalues enumerator's "(closure #N)" label so the path
             * "Upvalues.(closure #N)" round-trips identically in both
             * pause modes. */
            char *display_name = NULL;
            if (name[0] == '\0')
            {
                display_name =
                    g_strdup_printf("(closure #%d)", upvalue_index);
            }
            else
            {
                display_name = g_strdup(name);
            }
            wslua_debugger_capture_runtime_error_binding(L, display_name,
                                                         bindings_array);
            g_free(display_name);
            upvalue_index++;
        }
        lua_pop(L, 1); /* function */
    }

    *count_out = (int32_t)bindings_array->len;
    return (wslua_runtime_error_binding_t *)
        g_array_free(bindings_array, false);
}

/* Find a binding by name. Caller must hold debugger.mutex. */
static const wslua_runtime_error_binding_t *
wslua_debugger_find_runtime_error_binding(
    const wslua_runtime_error_binding_t *bindings, int32_t binding_count,
    const char *name)
{
    if (!bindings || binding_count <= 0 || !name || !*name)
    {
        return NULL;
    }
    for (int32_t i = 0; i < binding_count; i++)
    {
        if (g_strcmp0(bindings[i].name, name) == 0)
        {
            return &bindings[i];
        }
    }
    return NULL;
}

/* Push a captured binding's value onto @a target_L on hit; leave the
 * stack unchanged on miss. @a lookup_mode is 1 for Locals-only, 2 for
 * Upvalues-only, 0 for "Locals first then Upvalues" (matches the
 * WSLUA_LOOKUP_FIRST_AUTO ordering used by the live walker). When
 * @a search_all_frames is true the helper sweeps every captured frame
 * starting at @a stack_level; this is what the env_index / section_index
 * proxies use so a bare identifier in an expression watch resolves the
 * same way it would on a regular pause. Caller must hold debugger.mutex.
 */
static bool
wslua_debugger_push_runtime_error_snapshot_binding_locked(
    lua_State *target_L, int32_t stack_level, const char *name,
    int lookup_mode, bool search_all_frames)
{
    if (!debugger.runtime_error_frame_snapshots ||
        stack_level < 0 || stack_level >= debugger.runtime_error_stack_count ||
        !name || !*name)
    {
        return false;
    }

    int32_t level_start = stack_level;
    int32_t level_end   = stack_level + 1;
    if (search_all_frames)
    {
        level_start = 0;
        level_end   = debugger.runtime_error_stack_count;
    }

    const wslua_runtime_error_binding_t *binding = NULL;
    for (int32_t level = level_start; level < level_end && !binding; level++)
    {
        const wslua_runtime_error_frame_snapshot_t *frame =
            &debugger.runtime_error_frame_snapshots[level];

        if (lookup_mode == 1)
        {
            binding = wslua_debugger_find_runtime_error_binding(
                frame->locals, frame->locals_count, name);
        }
        else if (lookup_mode == 2)
        {
            binding = wslua_debugger_find_runtime_error_binding(
                frame->upvalues, frame->upvalues_count, name);
        }
        else
        {
            binding = wslua_debugger_find_runtime_error_binding(
                frame->locals, frame->locals_count, name);
            if (!binding)
            {
                binding = wslua_debugger_find_runtime_error_binding(
                    frame->upvalues, frame->upvalues_count, name);
            }
        }
    }

    if (!binding || binding->value_ref == LUA_NOREF)
    {
        return false;
    }

    lua_rawgeti(target_L, LUA_REGISTRYINDEX, binding->value_ref);
    return true;
}

/*
 * Push the captured chunk @c _ENV (Wireshark's per-script sandbox table)
 * for frame @a stack_level onto @a target_L, so a Globals.foo lookup at a
 * break-on-error pause sees the same script-defined globals that
 * @ref wslua_debugger_get_global_or_env_field would surface at a regular
 * breakpoint via @c lua_getupvalue(_, "_ENV"). Returns false (stack
 * unchanged) when no _ENV upvalue was captured for that frame (e.g. Lua
 * 5.1, or a frame with no Lua function).
 *
 * Caller must hold debugger.mutex.
 */
static bool
wslua_debugger_push_runtime_error_env_locked(lua_State *target_L,
                                             int32_t stack_level)
{
    if (!debugger.runtime_error_frame_snapshots ||
        stack_level < 0 || stack_level >= debugger.runtime_error_stack_count)
    {
        return false;
    }

    const wslua_runtime_error_frame_snapshot_t *frame =
        &debugger.runtime_error_frame_snapshots[stack_level];
    const wslua_runtime_error_binding_t *binding =
        wslua_debugger_find_runtime_error_binding(frame->upvalues,
                                                  frame->upvalues_count,
                                                  "_ENV");
    if (!binding || binding->value_ref == LUA_NOREF)
    {
        return false;
    }
    lua_rawgeti(target_L, LUA_REGISTRYINDEX, binding->value_ref);
    return true;
}

/*
 * Append rows for every (name, value_ref) pair in @a bindings to
 * @a variables_array, formatted exactly the way the live Locals /
 * Upvalues enumerator would format them. The pushed value is consumed
 * for each row, so the caller's stack is balanced on exit.
 *
 * Caller must hold debugger.mutex.
 */
static void
wslua_debugger_append_runtime_error_bindings_locked(
    lua_State *target_L,
    const wslua_runtime_error_binding_t *bindings, int32_t binding_count,
    GArray *variables_array)
{
    if (!bindings || binding_count <= 0 || !variables_array)
    {
        return;
    }
    for (int32_t i = 0; i < binding_count; i++)
    {
        if (bindings[i].value_ref == LUA_NOREF)
        {
            continue;
        }
        lua_rawgeti(target_L, LUA_REGISTRYINDEX, bindings[i].value_ref);

        wslua_variable_t variable;
        variable.name = g_strdup(bindings[i].name ? bindings[i].name : "");
        variable.type = wslua_debugger_format_value_type(target_L, -1);
        variable.value = wslua_debugger_describe_value(target_L, -1);
        variable.can_expand = wslua_debugger_value_can_expand(target_L, -1);

        g_array_append_val(variables_array, variable);
        lua_pop(target_L, 1);
    }
}

static void wslua_debugger_clear_runtime_error_snapshot_locked(void)
{
    wslua_debugger_free_stack_frames(debugger.runtime_error_stack,
                                     debugger.runtime_error_stack_count);
    wslua_debugger_free_runtime_error_frame_snapshots(
        debugger.runtime_error_frame_snapshots,
        debugger.runtime_error_stack_count);
    debugger.runtime_error_stack = NULL;
    debugger.runtime_error_stack_count = 0;
    debugger.runtime_error_frame_snapshots = NULL;
    debugger.runtime_error_stack_L = NULL;
}

static void wslua_debugger_clear_temporary_breakpoint_locked(void)
{
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
        debugger.temporary_breakpoint.file_path = NULL;
    }
    debugger.temporary_breakpoint.active = false;
}

static void wslua_debugger_clear_transient_state_locked(
    bool clear_runtime_error_snapshot)
{
    debugger.paused_L = NULL;
    debugger.runtime_error_pause_active = false;
    debugger.step_kind = WSLUA_STEP_KIND_NONE;
    debugger.step_stack_depth = 0;
    wslua_debugger_clear_temporary_breakpoint_locked();

    if (clear_runtime_error_snapshot)
    {
        wslua_debugger_clear_runtime_error_snapshot_locked();
    }
}

static bool wslua_debugger_should_install_hook_locked(void)
{
    if (!debugger.enabled)
    {
        return false;
    }

    if (breakpoints_array)
    {
        for (unsigned i = 0; i < breakpoints_array->len; i++)
        {
            wslua_breakpoint_t *bp =
                &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
            if (bp->active)
            {
                return true;
            }
        }
    }

    return debugger.temporary_breakpoint.active ||
           debugger.step_kind != WSLUA_STEP_KIND_NONE;
}

static bool wslua_debugger_first_lua_location(lua_State *L,
                                              int32_t start_level,
                                              const char **out_file_src,
                                              int64_t *out_line)
{
    if (!out_file_src || !out_line)
    {
        return false;
    }

    *out_file_src = "?";
    *out_line = -1;

    lua_Debug ar;
    memset(&ar, 0, sizeof(ar));
    for (int32_t level = start_level; lua_getstack(L, level, &ar); level++)
    {
        if (lua_getinfo(L, "Sln", &ar) == 0)
        {
            continue;
        }

        const bool is_c_frame = ar.what && strcmp(ar.what, "C") == 0;
        const bool is_c_source = ar.source && strcmp(ar.source, "=[C]") == 0;
        if (is_c_frame || is_c_source || !ar.source)
        {
            continue;
        }

        if (ar.currentline <= 0)
        {
            continue;
        }

        *out_file_src = (ar.source[0] == '@') ? ar.source + 1 : ar.source;
        *out_line = (int64_t)ar.currentline;
        return true;
    }

    return false;
}

/**
 * @brief Snapshot the "break-on-error pause is active" predicate under the lock.
 *
 * Returns true iff break-on-error is enabled and the debugger itself
 * is enabled (the AND is what every break-on-error entry point cares about).
 * Centralises the policy so future tweaks live in one place.
 *
 * Caller must not hold @c debugger.mutex.
 */
static bool wslua_debugger_should_break_on_error(void)
{
    g_mutex_lock(&debugger.mutex);
    const bool should_break = debugger.error_break_enabled && debugger.enabled;
    g_mutex_unlock(&debugger.mutex);
    return should_break;
}

/**
 * @brief Walk @a L starting at level 0 and append one
 *        @ref wslua_stack_frame_t per Lua activation to @a out.
 *
 * Each frame's @c source / @c line / @c linedefined / @c name strings
 * are heap-allocated copies; ownership transfers to the caller (use
 * @ref wslua_debugger_free_stack_frames or @c g_array_free to release).
 * Shared by the live @ref wslua_debugger_get_stack and the break-on-error
 * @ref wslua_debugger_capture_runtime_error snapshot paths so the two
 * stay structurally identical.
 */
static void wslua_debugger_collect_stack_frames(lua_State *L, GArray *out)
{
    lua_Debug debug_info;
    int32_t level = 0;
    while (lua_getstack(L, level, &debug_info))
    {
        lua_getinfo(L, "nSl", &debug_info);
        wslua_stack_frame_t frame;
        frame.source = g_strdup(debug_info.source ? debug_info.source : "?");
        frame.line = (int64_t)debug_info.currentline;
        frame.linedefined = (int64_t)debug_info.linedefined;
        frame.name = g_strdup(debug_info.name ? debug_info.name : "?");
        g_array_append_val(out, frame);
        level++;
    }
}

bool wslua_debugger_capture_runtime_error(lua_State *L, const char *msg)
{
    if (!wslua_debugger_should_break_on_error())
    {
        return false;
    }

    const char *file_src = "?";
    int64_t current_line = -1;
    (void)wslua_debugger_first_lua_location(L, 1, &file_src, &current_line);

    GArray *stack_array =
        g_array_new(false, false, sizeof(wslua_stack_frame_t));
    wslua_debugger_collect_stack_frames(L, stack_array);
    const int32_t captured_count = (int32_t)stack_array->len;

    /* Walk the captured frame list a second time to fetch a fresh
     * lua_Debug per level (lua_getlocal / lua_getupvalue need an
     * activation record, which isn't safe to retain across the first
     * loop) and snapshot per-frame locals + upvalues. */
    GArray *frame_snapshot_array =
        g_array_new(false, false,
                    sizeof(wslua_runtime_error_frame_snapshot_t));
    for (int32_t level = 0; level < captured_count; level++)
    {
        lua_Debug debug_info;
        if (!lua_getstack(L, level, &debug_info))
        {
            break;
        }
        lua_getinfo(L, "nSl", &debug_info);

        wslua_runtime_error_frame_snapshot_t frame_snapshot = {0};
        frame_snapshot.locals =
            wslua_debugger_capture_locals_for_activation(
                L, &debug_info, &frame_snapshot.locals_count);
        frame_snapshot.upvalues =
            wslua_debugger_capture_upvalues_for_activation(
                L, &debug_info, &frame_snapshot.upvalues_count);
        g_array_append_val(frame_snapshot_array, frame_snapshot);
    }

    wslua_stack_frame_t *captured_stack =
        (wslua_stack_frame_t *)g_array_free(stack_array, false);
    wslua_runtime_error_frame_snapshot_t *captured_frame_snapshots =
        (wslua_runtime_error_frame_snapshot_t *)g_array_free(
            frame_snapshot_array, false);

    g_mutex_lock(&debugger.mutex);
    g_free(debugger.last_error_text);
    debugger.last_error_text = g_strdup(msg ? msg : "(runtime error)");
    g_free(debugger.last_error_file);
    debugger.last_error_file = g_strdup(file_src);
    debugger.last_error_line = current_line;
    wslua_debugger_clear_runtime_error_snapshot_locked();
    debugger.runtime_error_stack = captured_stack;
    debugger.runtime_error_stack_count = captured_count;
    debugger.runtime_error_frame_snapshots = captured_frame_snapshots;
    debugger.runtime_error_stack_L = L;
    g_mutex_unlock(&debugger.mutex);

    return true;
}

/**
 * @brief Common pause-entry tail used by every direct caller of the UI
 *        pause callback.
 *
 * Disables the line hook on @a pause_L (so the nested Qt event loop
 * the UI callback enters does not re-fire the line hook), invokes
 * @c debugger.ui_update_callback if installed, then re-arms the main
 * debugger hook via @ref wslua_debugger_update_hook unless a reload is
 * in progress (in which case the deferred reload routine restores it).
 *
 * @a file_src must remain valid for the duration of this call; the
 * helper does not copy it. Caller must not hold @c debugger.mutex.
 *
 * @ref wslua_debug_hook intentionally stays inline because it may run
 * on a coroutine thread and re-installs its line hook thread-locally,
 * a path the main-state @c wslua_debugger_update_hook does not cover.
 */
static void wslua_debugger_enter_pause_event_loop(lua_State *pause_L,
                                                  const char *file_src,
                                                  int64_t line)
{
    lua_sethook(pause_L, NULL, 0, 0);

    if (debugger.ui_update_callback)
    {
        debugger.ui_update_callback(file_src, line);
    }

    g_mutex_lock(&debugger.mutex);
    const bool restore_hook = !debugger.reload_in_progress;
    g_mutex_unlock(&debugger.mutex);
    if (restore_hook)
    {
        wslua_debugger_update_hook();
    }
}

/**
 * @brief Pause handling for runtime errors.
 *
 * Uses a pre-unwind snapshot captured by
 * wslua_debugger_capture_runtime_error() when available. Internal: callers
 * outside this translation unit should use
 * @ref wslua_debugger_after_pcall_failure instead.
 */
static void wslua_debugger_on_runtime_error(lua_State *L, const char *msg)
{
    if (!wslua_debugger_should_break_on_error())
    {
        return;
    }

    g_mutex_lock(&debugger.mutex);
    const bool has_snapshot = debugger.runtime_error_stack_count > 0;
    g_mutex_unlock(&debugger.mutex);
    if (!has_snapshot)
    {
        wslua_debugger_capture_runtime_error(L, msg);
    }

    g_mutex_lock(&debugger.mutex);
    /* Copy file_src out from under the mutex: another thread could
     * replace debugger.last_error_file once we release. */
    char *file_src_copy = g_strdup(
        (debugger.last_error_file && debugger.last_error_file[0])
            ? debugger.last_error_file
            : "?");
    const int64_t current_line = debugger.last_error_line;
    lua_State *pause_L = debugger.runtime_error_stack_L ? debugger.runtime_error_stack_L : L;
    debugger.error_break_occurred = true;
    debugger.runtime_error_pause_active = true;
    debugger.state = WSLUA_DEBUGGER_PAUSED;
    debugger.paused_L = pause_L;
    g_mutex_unlock(&debugger.mutex);

    wslua_debugger_enter_pause_event_loop(pause_L, file_src_copy,
                                          current_line);
    g_free(file_src_copy);
}

/**
 * @brief Record the explicit error() / assert() break state under the lock.
 *
 * Stores the message, file, and line for the upcoming pause; marks the
 * pause as explicit (so the deferred pcall-failure path knows the
 * debugger is already handling this error); and transitions the
 * debugger to PAUSED with @a L as the paused state. Caller must not
 * hold @c debugger.mutex.
 */
static void wslua_debugger_record_explicit_error_break_locked(
    lua_State *L,
    const char *msg,
    const char *file_src,
    int64_t line)
{
    g_mutex_lock(&debugger.mutex);
    g_free(debugger.last_error_text);
    debugger.last_error_text = g_strdup(msg ? msg : "(error)");
    g_free(debugger.last_error_file);
    debugger.last_error_file = g_strdup(file_src);
    debugger.last_error_line = line;
    debugger.error_break_occurred = true;
    debugger.explicit_error_break_recent = true;
    debugger.state = WSLUA_DEBUGGER_PAUSED;
    debugger.paused_L = L;
    g_mutex_unlock(&debugger.mutex);
}

/**
 * @brief Re-invoke a saved original global function via its registry ref.
 *
 * Pushes the function stored at @a registry_ref, moves it underneath
 * the current arguments on the stack, and calls it with @a nresults
 * results.  Used by the @c error() and @c assert() wrappers to delegate
 * to the original Lua functions after the pause loop returns.  Returns
 * the number of results left on the stack (caller should @c return this
 * value from its @c lua_CFunction).
 */
static int wslua_debugger_call_original_global_via_ref(lua_State *L,
                                                       int registry_ref,
                                                       int nresults)
{
    lua_rawgeti(L, LUA_REGISTRYINDEX, registry_ref);
    lua_insert(L, 1);
    lua_call(L, lua_gettop(L) - 1, nresults);
    return (nresults == LUA_MULTRET) ? lua_gettop(L) : nresults;
}

/**
 * @brief Replacement for Lua's global error() when break-on-error is active.
 *
 * Installed over the global @c error function while the debugger is enabled.
 * When invoked and @c error_break_enabled is set, the wrapper captures the
 * call-site location, records the error message, triggers a debugger pause,
 * and then re-invokes the original @c error() so the error propagates
 * normally after the user clicks Continue.
 */
static int wslua_error_break_wrapper(lua_State *L)
{
    if (wslua_debugger_should_break_on_error())
    {
        const char *file_src = "?";
        int64_t current_line = -1;
        (void)wslua_debugger_first_lua_location(L, 1, &file_src, &current_line);

        const char *raw_msg = lua_tostring(L, 1);
        wslua_debugger_record_explicit_error_break_locked(
            L, raw_msg ? raw_msg : "(error)", file_src, current_line);

        wslua_debugger_enter_pause_event_loop(L, file_src, current_line);
    }

    /* Re-raise via the saved original error() to preserve level/message
     * semantics.  error() never returns — it longjmps past lua_call back to
     * the nearest lua_pcall. */
    return wslua_debugger_call_original_global_via_ref(
        L, debugger.original_error_ref, 0);
}

/**
 * @brief Replacement for Lua's global assert() when break-on-error is active.
 *
 * Mirrors the error() wrapper behavior: if break-on-error is enabled and the
 * assert condition is false/nil, pause at the caller frame before delegating to
 * the original assert() so Lua error semantics are preserved.
 */
static int wslua_assert_break_wrapper(lua_State *L)
{
    if (wslua_debugger_should_break_on_error() && !lua_toboolean(L, 1))
    {
        const char *file_src = "?";
        int64_t current_line = -1;
        (void)wslua_debugger_first_lua_location(L, 1, &file_src, &current_line);

        const char *raw_msg = lua_tostring(L, 2);
        wslua_debugger_record_explicit_error_break_locked(
            L, raw_msg ? raw_msg : "assertion failed!", file_src, current_line);

        wslua_debugger_enter_pause_event_loop(L, file_src, current_line);
    }

    return wslua_debugger_call_original_global_via_ref(
        L, debugger.original_assert_ref, LUA_MULTRET);
}

/**
 * @brief Swap a global Lua function for our @a wrapper, idempotently.
 *
 * If <tt>*ref_inout == LUA_NOREF</tt>, saves the current value of
 * @a global_name into the registry (storing the registry key in
 * @c *ref_inout) and replaces the global with @a wrapper. If the slot
 * is already swapped, this is a no-op so repeated update_hook() calls
 * stay safe.
 *
 * The caller is responsible for serialising swap/restore against the
 * Lua state; the @c _locked suffix matches the convention used for
 * other state-mutating helpers in this file even though no mutex is
 * acquired here (the refs are touched only from @ref
 * wslua_debugger_update_hook on the main state's thread).
 */
static void wslua_debugger_swap_global_with_wrapper_locked(
    lua_State *L,
    const char *global_name,
    lua_CFunction wrapper,
    int *ref_inout)
{
    if (*ref_inout != LUA_NOREF)
    {
        return;
    }
    lua_getglobal(L, global_name);
    *ref_inout = luaL_ref(L, LUA_REGISTRYINDEX);
    lua_pushcfunction(L, wrapper);
    lua_setglobal(L, global_name);
}

/**
 * @brief Restore the original global from the registry, idempotently.
 *
 * If <tt>*ref_inout != LUA_NOREF</tt>, replaces @a global_name with the
 * function stored at that registry slot, releases the slot, and resets
 * the ref to @c LUA_NOREF. If the slot is already restored this is a
 * no-op. Pairs with @ref wslua_debugger_swap_global_with_wrapper_locked.
 */
static void wslua_debugger_restore_global_from_wrapper_locked(
    lua_State *L,
    const char *global_name,
    int *ref_inout)
{
    if (*ref_inout == LUA_NOREF)
    {
        return;
    }
    lua_rawgeti(L, LUA_REGISTRYINDEX, *ref_inout);
    lua_setglobal(L, global_name);
    luaL_unref(L, LUA_REGISTRYINDEX, *ref_inout);
    *ref_inout = LUA_NOREF;
}

/**
 * @brief Update the Lua debug hook based on state.
 */
static void wslua_debugger_update_hook(void)
{
    if (!debugger.L)
        return;

    bool should_hook = false;
    g_mutex_lock(&debugger.mutex);
    should_hook = wslua_debugger_should_install_hook_locked();
    g_mutex_unlock(&debugger.mutex);

    if (should_hook)
    {
        lua_sethook(debugger.L, wslua_debug_hook, LUA_MASKLINE, 0);
    }
    else
    {
        lua_sethook(debugger.L, NULL, 0, 0);
    }

    /* Install or uninstall wrappers for global error()/assert(). */
    g_mutex_lock(&debugger.mutex);
    const bool enabled_now = debugger.enabled;
    g_mutex_unlock(&debugger.mutex);

    if (enabled_now)
    {
        wslua_debugger_swap_global_with_wrapper_locked(
            debugger.L, "error", wslua_error_break_wrapper,
            &debugger.original_error_ref);
        wslua_debugger_swap_global_with_wrapper_locked(
            debugger.L, "assert", wslua_assert_break_wrapper,
            &debugger.original_assert_ref);
    }
    else
    {
        wslua_debugger_restore_global_from_wrapper_locked(
            debugger.L, "error", &debugger.original_error_ref);
        wslua_debugger_restore_global_from_wrapper_locked(
            debugger.L, "assert", &debugger.original_assert_ref);
    }
}

/**
 * @brief Set the enabled state of the debugger.
 * @param enabled true to enable, false to disable.
 */
void wslua_debugger_set_enabled(bool enabled)
{
    g_mutex_lock(&debugger.mutex);
    if (!enabled && debugger.state == WSLUA_DEBUGGER_PAUSED)
    {
        g_mutex_unlock(&debugger.mutex);
        wslua_debugger_continue();
        g_mutex_lock(&debugger.mutex);
    }
    const bool was_enabled = debugger.enabled;
    debugger.enabled = enabled;
    if (enabled)
    {
        debugger.state = WSLUA_DEBUGGER_RUNNING;
        if (!was_enabled)
        {
            /* Seed the {elapsed} reference clock on each fresh attach. */
            debugger_start_us = g_get_monotonic_time();
        }
    }
    else if (was_enabled)
    {
        wslua_debugger_clear_transient_state_locked(true);
        /* On detach, drop the reference so a re-attach reseeds. */
        debugger_start_us = 0;
    }
    else if (!enabled)
    {
        wslua_debugger_clear_transient_state_locked(true);
    }
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

void wslua_debugger_set_user_explicitly_disabled(
    bool user_wants_debugger_stay_off)
{
    g_mutex_lock(&debugger.mutex);
    debugger.user_explicitly_disabled = user_wants_debugger_stay_off;
    if (user_wants_debugger_stay_off)
    {
        debugger.was_enabled_before_reload = false;
        debugger.error_break_was_enabled_before_reload = false;
    }
    g_mutex_unlock(&debugger.mutex);
}

bool wslua_debugger_may_auto_enable_for_breakpoints(void)
{
    ensure_breakpoints_initialized();
    g_mutex_lock(&debugger.mutex);
    const bool may = !debugger.user_explicitly_disabled &&
                     debugger_has_auto_break_triggers_locked();
    g_mutex_unlock(&debugger.mutex);
    return may;
}

bool wslua_debugger_get_user_explicitly_disabled(void)
{
    g_mutex_lock(&debugger.mutex);
    const bool disabled = debugger.user_explicitly_disabled;
    g_mutex_unlock(&debugger.mutex);
    return disabled;
}

void wslua_debugger_renounce_restore_after_reload(void)
{
    g_mutex_lock(&debugger.mutex);
    debugger.was_enabled_before_reload = false;
    debugger.error_break_was_enabled_before_reload = false;
    g_mutex_unlock(&debugger.mutex);
}

/**
 * @brief Register the UI callback.
 * @param cb The callback function.
 */
void wslua_debugger_register_ui_callback(wslua_debugger_ui_update_cb_t cb)
{
    debugger.ui_update_callback = cb;
}

/**
 * @brief Continue execution.
 */
void wslua_debugger_continue(void)
{
    g_mutex_lock(&debugger.mutex);
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    wslua_debugger_clear_transient_state_locked(false);
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Run to a specific line.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_run_to_line(const char *file_path, int64_t line)
{
    char *canonical_copy = wslua_debugger_dup_canonical_path(file_path);
    if (!canonical_copy)
    {
        return;
    }
    g_mutex_lock(&debugger.mutex);
    if (debugger.user_explicitly_disabled)
    {
        g_mutex_unlock(&debugger.mutex);
        g_free(canonical_copy);
        return;
    }
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
    }
    debugger.temporary_breakpoint.file_path = canonical_copy;
    debugger.temporary_breakpoint.line = line;
    debugger.temporary_breakpoint.active = true;

    debugger.step_kind = WSLUA_STEP_KIND_NONE;
    debugger.paused_L = NULL;
    debugger.enabled = true;
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Count Lua stack frames (0 = innermost).
 */
static int
wslua_debugger_count_stack_frames(lua_State *L)
{
    lua_Debug ar;
    int level = 0;

    while (lua_getstack(L, level, &ar))
    {
        level++;
    }
    return level;
}

/**
 * @brief Shared setup when resuming from a paused state into a step mode.
 */
static void
wslua_debugger_begin_step(wslua_step_kind_t kind, int stack_depth_for_over_out)
{
    g_mutex_lock(&debugger.mutex);
    /* Clear temp breakpoint since we're stepping */
    if (debugger.temporary_breakpoint.file_path)
    {
        g_free(debugger.temporary_breakpoint.file_path);
        debugger.temporary_breakpoint.file_path = NULL;
    }
    debugger.temporary_breakpoint.active = false;
    debugger.paused_L = NULL;

    debugger.step_kind = kind;
    if (kind == WSLUA_STEP_KIND_OVER || kind == WSLUA_STEP_KIND_OUT)
    {
        debugger.step_stack_depth = stack_depth_for_over_out;
    }
    debugger.state = WSLUA_DEBUGGER_RUNNING;
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

void wslua_debugger_step_in(void)
{
    wslua_debugger_begin_step(WSLUA_STEP_KIND_IN, 0);
}

void wslua_debugger_step_over(void)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        return;
    }
    const int depth = wslua_debugger_count_stack_frames(target_L);
    wslua_debugger_begin_step(WSLUA_STEP_KIND_OVER, depth);
}

void wslua_debugger_step_out(void)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        return;
    }
    const int depth = wslua_debugger_count_stack_frames(target_L);
    /*
     * Only one Lua frame: "step out" of the chunk is ordinary continuation —
     * there will be no further line hooks in this activation.
     */
    if (depth <= 1)
    {
        wslua_debugger_continue();
        return;
    }
    wslua_debugger_begin_step(WSLUA_STEP_KIND_OUT, depth);
}

void wslua_debugger_set_variable_stack_level(int32_t level)
{
    g_mutex_lock(&debugger.mutex);
    debugger.variable_stack_level = level < 0 ? 0 : level;
    g_mutex_unlock(&debugger.mutex);
}

/**
 * @brief Add a breakpoint.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_add_breakpoint(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    /* Check if exists */
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            return; /* Already exists */
        }
    }

    wslua_breakpoint_t breakpoint;
    breakpoint.file_path = g_strdup(norm_file_path);
    breakpoint.line = line;
    breakpoint.active = true;
    breakpoint.condition = NULL;
    breakpoint.hit_count_target = 0;
    breakpoint.hit_count = 0;
    breakpoint.hit_count_mode = WSLUA_HIT_COUNT_MODE_FROM;
    breakpoint.condition_error = false;
    breakpoint.condition_error_msg = NULL;
    breakpoint.log_message = NULL;
    breakpoint.log_also_pause = false;
    breakpoint.last_fired_us = 0;

    g_array_append_val(breakpoints_array, breakpoint);
    rebuild_bp_site_set_locked();
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
    wslua_debugger_update_hook();
}

/**
 * @brief Remove a breakpoint.
 * @param file_path The file path.
 * @param line The line number.
 */
void wslua_debugger_remove_breakpoint(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    bool removed = false;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            remove_breakpoint_at(i);
            removed = true;
            rebuild_bp_site_set_locked();
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            if (removed)
            {
                wslua_debugger_update_hook();
            }
            return;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * @brief Set breakpoint active state.
 * @param file_path The file path.
 * @param line The line number.
 * @param active The new state.
 */
void wslua_debugger_set_breakpoint_active(const char *file_path, int64_t line,
                                          bool active)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return;
    }

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, norm_file_path, line))
        {
            if (bp->active == active)
            {
                g_mutex_unlock(&debugger.mutex);
                g_free(norm_file_path);
                return;
            }
            bp->active = active;
            rebuild_bp_site_set_locked();
            g_mutex_unlock(&debugger.mutex);
            g_free(norm_file_path);
            /* Toggling a breakpoint's active state must never change the
             * debugger's enabled flag (especially during a live capture,
             * where debugging is suppressed entirely). Just re-arm the
             * Lua line hook so the change takes effect on the next tick. */
            wslua_debugger_update_hook();
            return;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * @brief Clear all breakpoints.
 */
void wslua_debugger_clear_breakpoints(void)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    /* Free all breakpoint data */
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        free_breakpoint(bp);
    }
    g_array_set_size(breakpoints_array, 0);
    rebuild_bp_site_set_locked();
    g_mutex_unlock(&debugger.mutex);
    wslua_debugger_update_hook();
}

/**
 * @brief Internal: locate a breakpoint by canonical path + line.
 *
 * Caller must hold @c debugger.mutex. Returns the in-array pointer or NULL.
 */
static wslua_breakpoint_t *
find_breakpoint_locked(const char *canonical_path, int64_t line)
{
    if (!breakpoints_array)
        return NULL;
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, canonical_path, line))
        {
            return bp;
        }
    }
    return NULL;
}

void wslua_debugger_set_breakpoint_condition(const char *file_path,
                                             int64_t line,
                                             const char *condition)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        g_free(bp->condition);
        bp->condition = (condition && condition[0])
                            ? g_strdup(condition)
                            : NULL;
        bp->condition_error = false;
        g_free(bp->condition_error_msg);
        bp->condition_error_msg = NULL;
        /* Preserve hit_count and last_fired_us across condition edits.
         * Earlier behavior reset both whenever the user touched the
         * condition, which silently threw away the counter the user
         * was watching as soon as they tweaked the expression. The
         * dedicated Reset Hit Count / Reset All Hit Counts menu items
         * are the only paths that should clear the counter. */
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

void wslua_debugger_set_breakpoint_hit_count_target(const char *file_path,
                                                    int64_t line,
                                                    int64_t target)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        const int64_t new_target = (target > 0) ? target : 0;
        const int64_t old_target = bp->hit_count_target;
        bp->hit_count_target = new_target;
        /* Preserve hit_count when the new target is still ahead of (or
         * equal to) the running counter — the existing count is still
         * meaningful as "how far we are toward the new threshold". Only
         * roll back when the user lowered the bar so far that the
         * counter is already past it (otherwise the breakpoint would
         * pause every hit forever instead of waiting for "the next N
         * hits"). Clearing the target entirely (target == 0) leaves the
         * counter alone too, matching VS Code / JetBrains. */
        if (new_target > 0 && bp->hit_count > new_target)
        {
            bp->hit_count = 0;
            bp->last_fired_us = 0;
        }
        (void)old_target;
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

void wslua_debugger_set_breakpoint_hit_count_mode(const char *file_path,
                                                   int64_t line,
                                                   wslua_hit_count_mode_t mode)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        /* Clamp unknown enum values to the safe default so a JSON file
         * carrying an unrecognised mode string (mapped to a sentinel by
         * the reader) does not silently break the gate. */
        switch (mode)
        {
        case WSLUA_HIT_COUNT_MODE_FROM:
        case WSLUA_HIT_COUNT_MODE_EVERY:
        case WSLUA_HIT_COUNT_MODE_ONCE:
            bp->hit_count_mode = mode;
            break;
        default:
            bp->hit_count_mode = WSLUA_HIT_COUNT_MODE_FROM;
            break;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

void wslua_debugger_set_breakpoint_log_also_pause(const char *file_path,
                                                   int64_t line,
                                                   bool also_pause)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        bp->log_also_pause = also_pause;
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

void wslua_debugger_set_breakpoint_log_message(const char *file_path,
                                               int64_t line,
                                               const char *message)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        g_free(bp->log_message);
        bp->log_message = (message && message[0])
                              ? g_strdup(message)
                              : NULL;
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

void wslua_debugger_reset_breakpoint_hit_count(const char *file_path,
                                               int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        bp->hit_count = 0;
        bp->condition_error = false;
        g_free(bp->condition_error_msg);
        bp->condition_error_msg = NULL;
        bp->last_fired_us = 0;
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

void wslua_debugger_reset_all_breakpoint_hit_counts(void)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        bp->hit_count = 0;
        bp->condition_error = false;
        g_free(bp->condition_error_msg);
        bp->condition_error_msg = NULL;
        bp->last_fired_us = 0;
    }
    g_mutex_unlock(&debugger.mutex);
}

/**
 * @brief Internal: check breakpoint state using an already-canonical path.
 */
static int32_t
get_breakpoint_state_for_canonical(const char *canonical_path, int64_t line)
{
    if (!canonical_path)
    {
        return -1;
    }

    ensure_breakpoints_initialized();

    int32_t result = -1;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, canonical_path, line))
        {
            result = bp->active ? 1 : 0;
            break;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    return result;
}

int32_t wslua_debugger_get_breakpoint_state(const char *file_path, int64_t line)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
    {
        return -1;
    }
    const int32_t result =
        get_breakpoint_state_for_canonical(norm_file_path, line);
    g_free(norm_file_path);
    return result;
}

int32_t wslua_debugger_get_breakpoint_state_canonical(
    const char *canonical_path, int64_t line, bool *has_extras)
{
    if (has_extras)
    {
        *has_extras = false;
    }
    if (!canonical_path)
    {
        return -1;
    }

    ensure_breakpoints_initialized();

    int32_t result = -1;
    g_mutex_lock(&debugger.mutex);
    for (unsigned i = 0; i < breakpoints_array->len; i++)
    {
        wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
        if (wslua_debugger_breakpoint_matches(bp, canonical_path, line))
        {
            result = bp->active ? 1 : 0;
            if (has_extras)
            {
                const bool has_cond = bp->condition && bp->condition[0];
                const bool has_target = bp->hit_count_target > 0;
                const bool has_log = bp->log_message && bp->log_message[0];
                *has_extras = has_cond || has_target || has_log;
            }
            break;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    return result;
}

char *wslua_debugger_canonical_path(const char *file_path)
{
    return wslua_debugger_dup_canonical_path(file_path);
}

/**
 * @brief The Lua debug hook.
 * @param L The Lua state.
 * @param debug_info The debug info.
 */
static void wslua_debug_hook(lua_State *L, lua_Debug *debug_info)
{
    g_mutex_lock(&debugger.mutex);
    bool hook_active = debugger.enabled;
    g_mutex_unlock(&debugger.mutex);
    if (!hook_active)
        return;

    /* Ask for `n`/`S`/`l` so debug_info populates name/what (used by the
     * {function} / {what} logpoint tags) in addition to source and
     * currentline. The marginal cost on the line-hook hot path is
     * negligible compared to the surrounding mutex / breakpoint scan. */
    if (lua_getinfo(L, "nSl", debug_info) == 0)
        return;

    /* Check if we are in a C function */
    if (debug_info->currentline < 0)
        return;

    const char *source = debug_info->source;
    if (source && source[0] == '@')
    {
        source++; /* Skip '@' */
    }
    else
    {
        /* Not a file */
        return;
    }

    const char *norm_source = wslua_debugger_get_cached_canonical_path(source);
    if (!norm_source)
    {
        return;
    }

    bool pause_for_step = false;

    /* Single-step modes (step in / over / out) */
    wslua_step_kind_t step_kind;
    int step_stack_depth_snapshot;
    g_mutex_lock(&debugger.mutex);
    step_kind = debugger.step_kind;
    step_stack_depth_snapshot = debugger.step_stack_depth;
    g_mutex_unlock(&debugger.mutex);

    if (step_kind != WSLUA_STEP_KIND_NONE)
    {
        bool step_done = false;
        switch (step_kind)
        {
        case WSLUA_STEP_KIND_IN:
            step_done = true;
            break;
        case WSLUA_STEP_KIND_OVER: {
            const int d = wslua_debugger_count_stack_frames(L);
            if (d <= step_stack_depth_snapshot)
            {
                step_done = true;
            }
            break;
        }
        case WSLUA_STEP_KIND_OUT: {
            const int d = wslua_debugger_count_stack_frames(L);
            if (d < step_stack_depth_snapshot)
            {
                step_done = true;
            }
            break;
        }
        default:
            break;
        }
        if (step_done)
        {
            pause_for_step = true;
            g_mutex_lock(&debugger.mutex);
            debugger.step_kind = WSLUA_STEP_KIND_NONE;
            g_mutex_unlock(&debugger.mutex);
        }
    }

    bool pause_for_bp = false;

    /* Check regular breakpoints (with hit-count gate, condition, and
     * logpoint handling). */
    if (bp_site_set_contains(norm_source,
                             (int64_t)debug_info->currentline))
    {
        /* Fast-path filter: most lines aren't breakpoint sites. The
         * @ref bp_site_set lookup above runs under a read-rwlock and
         * a single hash probe; only when it confirms the line hosts
         * an active regular breakpoint do we take @ref debugger.mutex
         * and walk @ref breakpoints_array. The temporary breakpoint
         * (Run-To-Line) is checked further down regardless of this
         * gate, because it's not represented in the site set. */

        /* Snapshot under mutex: find the first matching active BP,
         * advance its hit counter, and copy out the condition /
         * log_message strings so we can evaluate them without holding
         * the mutex. The eval helper runs user Lua code via lua_pcall
         * and installs its own count/call hooks; doing that under the
         * debugger mutex would risk deadlocks. */
        char *condition_snapshot = NULL;
        char *log_message_snapshot = NULL;
        bool log_also_pause_snapshot = false;
        int64_t hit_target = 0;
        int64_t new_hit_count = 0;
        /*
         * last_fired_snapshot_us is the breakpoint's previous fire
         * timestamp captured before we overwrite it with `now_us`.
         * Used to compute the {delta} logpoint tag. 0 means this is
         * the first fire (or the counter was just reset), in which
         * case {delta} reports 0ms.
         */
        int64_t last_fired_snapshot_us = 0;
        const int64_t now_us = g_get_monotonic_time();
        bool matched_active_bp = false;

        g_mutex_lock(&debugger.mutex);
        if (breakpoints_array)
        {
            for (unsigned i = 0; i < breakpoints_array->len; i++)
            {
                wslua_breakpoint_t *bp =
                    &g_array_index(breakpoints_array, wslua_breakpoint_t, i);
                if (!bp->active)
                    continue;
                if (!wslua_debugger_breakpoint_matches(
                        bp, norm_source, (int64_t)debug_info->currentline))
                    continue;

                bp->hit_count++;
                /* Wake the UI on every silent bump so the
                 * Breakpoints @em Hits column ticks live even when
                 * the row stays below threshold (no pause, no
                 * logpoint emit). The notification is a single
                 * atomic CAS in steady state — see
                 * @ref notify_breakpoint_state_dirty. */
                notify_breakpoint_state_dirty();
                new_hit_count = bp->hit_count;
                hit_target = bp->hit_count_target;

                /* Hit-count gate.
                 *
                 * Mode-driven test against @c hit_count_target. The
                 * gate is a no-op when target == 0 (every hit passes,
                 * matching the no-target semantics regardless of the
                 * stored mode). ONCE fires once on @c hit_count ==
                 * @c hit_target and then deactivates the breakpoint
                 * below.
                 */
                bool gate_passes = true;
                if (hit_target > 0)
                {
                    switch (bp->hit_count_mode)
                    {
                    case WSLUA_HIT_COUNT_MODE_EVERY:
                        /* Treat 0 % N as "not yet": users wrote a
                         * positive target so the first match they
                         * expect is at hit N, not at 0. */
                        gate_passes = (new_hit_count > 0) &&
                                      ((new_hit_count % hit_target) == 0);
                        break;
                    case WSLUA_HIT_COUNT_MODE_ONCE:
                        gate_passes = (new_hit_count == hit_target);
                        break;
                    case WSLUA_HIT_COUNT_MODE_FROM:
                    default:
                        gate_passes = (new_hit_count >= hit_target);
                        break;
                    }
                }

                if (!gate_passes)
                {
                    /* Below threshold (or not on a multiple): do not
                     * pause / log / evaluate condition. First-match
                     * wins, matching the existing single-pause-per-
                     * line semantics. */
                }
                else
                {
                    matched_active_bp = true;
                    if (bp->condition && bp->condition[0])
                        condition_snapshot = g_strdup(bp->condition);
                    if (bp->log_message && bp->log_message[0])
                        log_message_snapshot = g_strdup(bp->log_message);
                    log_also_pause_snapshot = bp->log_also_pause;
                    /* Capture and refresh the last-fire timestamp under
                     * the mutex so concurrent fires of the same bp on
                     * different threads see consistent {delta} values. */
                    last_fired_snapshot_us = bp->last_fired_us;
                    bp->last_fired_us = now_us;
                    /* One-shot: after this fire the breakpoint stops
                     * being a candidate until the user re-activates it
                     * (or restarts Wireshark). The deactivation lives
                     * here under the mutex so it's atomic with the
                     * gate-pass decision; the UI poll loop refreshes
                     * the active state on its next tick. */
                    if (bp->hit_count_mode == WSLUA_HIT_COUNT_MODE_ONCE &&
                        hit_target > 0)
                    {
                        bp->active = false;
                        /* Re-arm in one click: zero the runtime counter
                         * so simply re-ticking the row's Active checkbox
                         * is enough to trigger the next N-hit cycle —
                         * the user no longer needs a separate Reset Hit
                         * Count call. The {hits} log tag for THIS fire
                         * already snapshotted @c new_hit_count above, so
                         * the formatted log line still shows N. */
                        bp->hit_count = 0;
                        /* Auto-disable removes this site from the
                         * fast-path set immediately so subsequent
                         * line hooks for the same line skip it
                         * without taking @c debugger.mutex again. */
                        rebuild_bp_site_set_locked();
                    }
                }
                break;
            }
        }
        const int64_t debugger_start_snapshot_us = debugger_start_us;
        g_mutex_unlock(&debugger.mutex);

        if (matched_active_bp)
        {
            bool truthy = true;
            bool eval_invoked = false;

            if (condition_snapshot)
            {
                char *err = NULL;
                eval_invoked = true;
                const bool ok = wslua_debugger_eval_bool_at_level0(
                    L, condition_snapshot, &truthy, &err);
                /* Silent error policy: failed condition evaluation is
                 * treated as false. We still record the sticky flag
                 * AND keep the error text so the UI can surface the
                 * exact message in the row tooltip; ownership of
                 * @c err transfers to the breakpoint here. */
                if (!ok)
                {
                    truthy = false;
                }
                g_mutex_lock(&debugger.mutex);
                wslua_breakpoint_t *bp_now = find_breakpoint_locked(
                    norm_source, (int64_t)debug_info->currentline);
                if (bp_now)
                {
                    bp_now->condition_error = !ok;
                    g_free(bp_now->condition_error_msg);
                    bp_now->condition_error_msg = ok ? NULL : err;
                    /* Took ownership above (or err was NULL on
                     * success); avoid the post-unlock free below. */
                    err = NULL;
                }
                g_mutex_unlock(&debugger.mutex);
                /* If the breakpoint vanished between the eval and the
                 * relock (rare: another thread removed it), free the
                 * orphaned message rather than leak. */
                g_free(err);
            }

            if (truthy)
            {
                if (log_message_snapshot)
                {
                    /* Logpoint: format the template and emit. The
                     * breakpoint pauses execution iff the user has
                     * ticked "Pause" on the row (the
                     * @c log_also_pause snapshot below); otherwise
                     * it emits and resumes immediately, matching the
                     * historical "logpoints never pause" convention. */
                    eval_invoked = true;

                    /* Skip the expensive per-fire work for tags the
                     * template does not actually reference. For
                     * per-packet logpoints with a simple template
                     * this drops a full Lua-stack walk
                     * (count_stack_frames) and a push/topointer/pop
                     * pair from every fire. */
                    wslua_logpoint_tags_t tags = {0};
                    wslua_debugger_scan_log_tags(log_message_snapshot,
                                                  &tags);

                    bool is_main_thread = false;
                    const void *thread_ptr = NULL;
                    if (tags.needs_thread)
                    {
                        /* Identify the running thread without invoking
                         * any Lua. lua_pushthread returns 1 iff L is
                         * the main thread; otherwise the pushed
                         * thread's pointer is a stable id within the
                         * session. */
                        int is_main = lua_pushthread(L);
                        is_main_thread = (is_main != 0);
                        thread_ptr =
                            is_main ? NULL : lua_topointer(L, -1);
                        lua_pop(L, 1);
                    }

                    wslua_logpoint_context_t ctx = {0};
                    ctx.file_path = norm_source;
                    ctx.line = (int64_t)debug_info->currentline;
                    ctx.hit_count = new_hit_count;
                    ctx.delta_ms =
                        (last_fired_snapshot_us == 0)
                            ? 0
                            : (now_us - last_fired_snapshot_us) / 1000;
                    ctx.elapsed_ms =
                        (debugger_start_snapshot_us == 0)
                            ? 0
                            : (now_us - debugger_start_snapshot_us) / 1000;
                    ctx.fn_name = debug_info->name;
                    ctx.fn_what = debug_info->what;
                    ctx.depth = tags.needs_depth
                                    ? wslua_debugger_count_stack_frames(L)
                                    : 0;
                    ctx.is_main_thread = is_main_thread;
                    ctx.thread_ptr = thread_ptr;

                    char *formatted = wslua_debugger_format_log_message(
                        L, log_message_snapshot, &ctx);
                    wslua_debugger_emit_log_message(
                        norm_source,
                        (int64_t)debug_info->currentline, formatted);
                    g_free(formatted);
                    /* "Log AND pause": fall through to the pause path
                     * after the message has been emitted. The eval
                     * helper has already cleared the line hook; the
                     * pause path below reinstalls it on resume. */
                    if (log_also_pause_snapshot)
                    {
                        pause_for_bp = true;
                    }
                }
                else
                {
                    pause_for_bp = true;
                }
            }

            /* The eval helper installs its own count/call hooks and
             * leaves the line hook cleared on completion. The pause
             * path reinstalls it itself; on no-pause exits (logpoint
             * fired, condition false, condition error) we need to put
             * the line hook back so subsequent lines still trip it. */
            if (eval_invoked && !pause_for_bp)
            {
                g_mutex_lock(&debugger.mutex);
                const bool reinstall = wslua_debugger_should_install_hook_locked();
                g_mutex_unlock(&debugger.mutex);
                if (reinstall)
                {
                    lua_sethook(L, wslua_debug_hook, LUA_MASKLINE, 0);
                }
            }
        }

        g_free(condition_snapshot);
        g_free(log_message_snapshot);
    }

    bool hit = pause_for_step || pause_for_bp;

    /* Check temp breakpoint */
    if (!hit)
    {
        g_mutex_lock(&debugger.mutex);
        if (debugger.temporary_breakpoint.active &&
            wslua_debugger_breakpoint_matches(&debugger.temporary_breakpoint,
                                              norm_source,
                                              (int64_t)debug_info->currentline))
        {
            hit = true;
            /* Temp breakpoint is one-shot */
            debugger.temporary_breakpoint.active = false;
        }
        g_mutex_unlock(&debugger.mutex);
    }

    if (hit)
    {
        const char *pause_source = source;
        int64_t pause_line = (int64_t)debug_info->currentline;
        (void)wslua_debugger_first_lua_location(L, 0,
                                                &pause_source,
                                                &pause_line);

        g_mutex_lock(&debugger.mutex);
        debugger.state = WSLUA_DEBUGGER_PAUSED;
        debugger.paused_L = L;
        g_mutex_unlock(&debugger.mutex);

        if (debugger.ui_update_callback)
        {
            /*
             * Disable the hook while paused.
             *
             * The UI callback runs a nested Qt event loop and may trigger
             * additional Lua activity. Keeping the line hook installed during
             * that time can lead to re-entrancy and crashes.
             */
            lua_sethook(L, NULL, 0, 0);
            debugger.ui_update_callback(pause_source, pause_line);
        }

        /*
         * After the UI callback returns (nested event loop exited),
         * execution resumes normally. If a reload was requested while
         * we were paused, the reload was deferred — the UI quit the
         * event loop and scheduled a delayed reload. The hook simply
         * returns here, allowing the Lua script to finish its current
         * execution naturally. The deferred reload will run once the
         * Lua call stack has fully unwound.
         */

        /*
         * Re-install the hook on this thread (L) so that stepping
         * and breakpoints can fire on subsequent lines within the
         * same dissector call.  The hook was disabled on L above to
         * prevent re-entrancy during the nested event loop; now that
         * the event loop has exited we need it back.  Note: L may be
         * a coroutine thread created by lua_newthread(), which is
         * distinct from debugger.L (the main state).
         */
        g_mutex_lock(&debugger.mutex);
        bool reinstall_hook = wslua_debugger_should_install_hook_locked() &&
                              !debugger.reload_in_progress;
        g_mutex_unlock(&debugger.mutex);
        /* During deferred reload, keep this thread hook disabled so we don't
         * pause again on subsequent packets before reload restarts dissection. */
        if (reinstall_hook)
        {
            lua_sethook(L, wslua_debug_hook, LUA_MASKLINE, 0);
        }
    }
}

/**
 * @brief Get stack trace.
 * @param frame_count Output pointer for frame count.
 * @return Array of stack frames.
 */
wslua_stack_frame_t *wslua_debugger_get_stack(int32_t *frame_count)
{
    g_mutex_lock(&debugger.mutex);
    if (debugger.runtime_error_pause_active &&
        debugger.runtime_error_stack_count > 0)
    {
        wslua_stack_frame_t *snapshot =
            wslua_debugger_dup_stack_frames(debugger.runtime_error_stack,
                                            debugger.runtime_error_stack_count);
        *frame_count = debugger.runtime_error_stack_count;
        g_mutex_unlock(&debugger.mutex);
        return snapshot;
    }
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    g_mutex_unlock(&debugger.mutex);
    if (!target_L)
    {
        *frame_count = 0;
        return NULL;
    }

    GArray *stack_array =
        g_array_new(false, false, sizeof(wslua_stack_frame_t));
    wslua_debugger_collect_stack_frames(target_L, stack_array);
    *frame_count = (int32_t)stack_array->len;
    return (wslua_stack_frame_t *)g_array_free(stack_array, false);
}

/**
 * @brief Free stack trace.
 * @param stack The stack array.
 * @param frame_count The number of frames.
 */
void wslua_debugger_free_stack(wslua_stack_frame_t *stack, int32_t frame_count)
{
    wslua_debugger_free_stack_frames(stack, frame_count);
}

/**
 * @brief Fill @a ar for lua_getlocal / lua_getinfo for stack frame @a level.
 */
static bool
wslua_debugger_fill_activation(lua_State *L, int32_t level, lua_Debug *ar)
{
    return lua_getstack(L, level, ar);
}

/**
 * @brief After @a ar describes an activation, push the running closure so
 *        lua_getupvalue can enumerate upvalues (Lua debug library pattern).
 */
static bool wslua_debugger_push_function_for_ar(lua_State *L, lua_Debug *ar)
{
    const int base = lua_gettop(L);
    if (!lua_getinfo(L, "f", ar))
    {
        lua_settop(L, base);
        return false;
    }
    if (!lua_isfunction(L, -1))
    {
        lua_settop(L, base);
        return false;
    }
    return true;
}

/**
 * @brief Index the value at the stack top by a string key.
 *
 * Consumes the parent from the stack and pushes the resulting value on
 * success (returns true). Supports regular tables (via lua_getfield),
 * wslua userdata with attribute getters (via __getters), and any value
 * exposing the standard Lua __pairs protocol as a last resort. Returns
 * false with the parent popped if traversal fails.
 */
static bool wslua_debugger_index_by_string(lua_State *L, const char *key)
{
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, key);
        lua_remove(L, -2);
        return true;
    }
    if (lua_isuserdata(L, -1))
    {
        const int userdata_abs = lua_gettop(L);
        /* A class registered via WSLUA_REGISTER_META always ends up with
         * a __getters field on its metatable (wslua_register_classinstance_meta
         * installs one unconditionally when introspection is enabled), even
         * when the class declares no attributes. Only take the getter branch
         * when the table actually contains a visible getter so classes like
         * Prefs fall through to the __pairs fallback instead of being
         * silently swallowed by an empty getters table. */
        if (wslua_debugger_count_userdata_getters(L, userdata_abs) > 0 &&
            wslua_debugger_push_getters(L, userdata_abs))
        {
            /* Stack: ..., userdata, __getters */
            lua_pushstring(L, key);
            lua_rawget(L, -2);
            /* Stack: ..., userdata, __getters, getter_or_nil */
            if (!lua_iscfunction(L, -1))
            {
                lua_pop(L, 3); /* getter_or_nil, __getters, userdata */
                return false;
            }
            lua_pushvalue(L, userdata_abs); /* self */
            /* Stack: ..., userdata, __getters, getter, userdata */
            if (lua_pcall(L, 1, 1, 0) != 0)
            {
                lua_pop(L, 3); /* error, __getters, userdata */
                return false;
            }
            /* Stack: ..., userdata, __getters, result */
            lua_remove(L, -2); /* __getters */
            lua_remove(L, -2); /* userdata */
            return true;
        }
        if (wslua_debugger_push_pairs_iterator(L, userdata_abs))
        {
            /* Stack: ..., userdata, iter, state, initial_key.
             * Walk the iterator linearly until the requested key is
             * found. The iterator contract matches the enumeration
             * used when the userdata is expanded, so paths built from
             * expansion round-trip reliably. */
            while (wslua_debugger_pairs_next(L))
            {
                /* Stack: ..., userdata, iter, state, key, value */
                if (lua_type(L, -2) == LUA_TSTRING &&
                    g_strcmp0(lua_tostring(L, -2), key) == 0)
                {
                    /* Match: reduce stack to just the value. */
                    lua_remove(L, -2); /* key */
                    lua_remove(L, -2); /* state */
                    lua_remove(L, -2); /* iter */
                    lua_remove(L, -2); /* userdata */
                    return true;
                }
                lua_pop(L, 1); /* value; pairs_next keeps the key */
            }
            /* pairs_next cleaned up the iterator triple on exhaustion. */
            lua_pop(L, 1); /* userdata */
            return false;
        }
        lua_pop(L, 1); /* userdata */
        return false;
    }
    lua_pop(L, 1);
    return false;
}

/**
 * Resolve a global-like name: try the registry global table first, then the
 * current stack frame's _ENV upvalue (Lua 5.2+). Wireshark loads scripts with
 * a file environment that stores top-level bindings in _ENV while
 * lua_getglobal() only sees raw _G, so Globals.foo paths must fall back to
 * _ENV to match what Lua code actually resolves.
 *
 * Under a break-on-error pause the activation that ran the script no
 * longer exists on the live stack, so the @c lua_getupvalue path can't
 * find the chunk's @c _ENV. The captured snapshot already keeps a strong
 * registry ref to that _ENV upvalue (it is upvalue #1 of every Lua 5.2+
 * Wireshark-loaded chunk and is captured by
 * @ref wslua_debugger_capture_upvalues_for_activation), so we substitute
 * it here. This is what makes @c Globals.foo behave identically at a
 * regular pause and at a break-on-error pause.
 *
 * On success leaves one value on the stack; on failure leaves the stack clean.
 */
static bool
wslua_debugger_get_global_or_env_field(lua_State *L, int32_t stack_level,
                                       const char *name)
{
    if (!name || !*name)
    {
        return false;
    }

    lua_getglobal(L, name);
    if (!lua_isnil(L, -1))
    {
        return true;
    }
    lua_pop(L, 1);

#if LUA_VERSION_NUM >= 502
    /* Break-on-error path: the live frame is gone, but the snapshot
     * holds the function's _ENV upvalue. Same lookup, different source. */
    g_mutex_lock(&debugger.mutex);
    const bool snapshot_active =
        debugger.runtime_error_pause_active &&
        debugger.runtime_error_frame_snapshots != NULL;
    bool pushed_env_from_snapshot = false;
    if (snapshot_active)
    {
        pushed_env_from_snapshot =
            wslua_debugger_push_runtime_error_env_locked(L, stack_level);
    }
    g_mutex_unlock(&debugger.mutex);

    if (pushed_env_from_snapshot)
    {
        if (lua_type(L, -1) == LUA_TTABLE)
        {
            lua_getfield(L, -1, name);
            lua_remove(L, -2); /* _ENV table */
            if (!lua_isnil(L, -1))
            {
                return true;
            }
            lua_pop(L, 1);
            return false;
        }
        lua_pop(L, 1); /* non-table _ENV (defensive) */
        return false;
    }

    if (snapshot_active)
    {
        /* Snapshot active but no _ENV captured (e.g. C frame): no further
         * fallback is possible because the live activation does not exist
         * either. */
        return false;
    }

    {
        lua_Debug ar;
        if (!wslua_debugger_fill_activation(L, stack_level, &ar))
        {
            return false;
        }
        if (!wslua_debugger_push_function_for_ar(L, &ar))
        {
            return false;
        }
        int uv = 1;
        const char *nm;
        while ((nm = lua_getupvalue(L, -1, uv++)))
        {
            if (g_strcmp0(nm, "_ENV") == 0)
            {
                lua_remove(L, -2); /* function */
                lua_getfield(L, -1, name);
                lua_remove(L, -2); /* _ENV table */
                if (!lua_isnil(L, -1))
                {
                    return true;
                }
                lua_pop(L, 1);
                return false;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1); /* function */
    }
#endif
    return false;
}

/** How to resolve the first path segment (after optional Locals./Upvalues./Globals. strip). */
typedef enum
{
    /** Locals, then upvalues, then globals (unqualified / bare watch specs). */
    WSLUA_LOOKUP_FIRST_AUTO = 0,
    /** Path was written as Locals.… — first name is a local only. */
    WSLUA_LOOKUP_FIRST_LOCAL_ONLY = 1,
    /** Path was written as Upvalues.… */
    WSLUA_LOOKUP_FIRST_UPVALUE_ONLY = 2,
    /** Path was written as Globals.… — first name is _G[name] only. */
    WSLUA_LOOKUP_FIRST_GLOBAL_ONLY = 3,
} wslua_lookup_first_kind_t;

/* Forward declaration — defined with the path-grammar scanners below. */
static bool wslua_debugger_spec_scan_bracket_key(const char **pp, lua_State *L);

/**
 * @brief Walk a subpath against the value already at the top of the stack.
 *
 * The subpath uses the same grammar as the tail of a watch path (a sequence
 * of `.name` and `[key]` segments, possibly empty). On success the parent at
 * `-1` is replaced with the resolved descendant; on failure the parent is
 * popped and `false` is returned.
 *
 * This is shared by `wslua_debugger_lookup_path` (path watches and the
 * Variables tree) and by `wslua_debugger_watch_expr_*` (expression watches),
 * so the two flavors agree on subscript semantics, escape decoding, and
 * error handling.
 */
static bool
wslua_debugger_traverse_subpath_on_top(lua_State *L, const char *path_ptr)
{
    if (!path_ptr)
    {
        return true;
    }
    while (*path_ptr)
    {
        if (*path_ptr == '.')
        {
            path_ptr++;
            const char *end_ptr = path_ptr;
            while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
                end_ptr++;
            char *key = g_strndup(path_ptr, end_ptr - path_ptr);
            const bool ok = wslua_debugger_index_by_string(L, key);
            g_free(key);
            if (!ok)
            {
                return false;
            }
            path_ptr = end_ptr;
        }
        else if (*path_ptr == '[')
        {
            path_ptr++;
            const bool is_table = lua_istable(L, -1);
            const bool is_userdata = !is_table && lua_isuserdata(L, -1);
            if (!is_table && !is_userdata)
            {
                lua_pop(L, 1);
                return false;
            }

            /* Decode the bracket key and push it on the stack (above the
             * parent). */
            if (!wslua_debugger_spec_scan_bracket_key(&path_ptr, L))
            {
                lua_pop(L, 1); /* parent */
                return false;
            }

            if (is_table)
            {
                /* stack: parent, key → parent[key] */
                lua_gettable(L, -2);
                lua_remove(L, -2); /* parent */
            }
            else
            {
                /* Userdata indexing only makes sense with a string key. */
                if (lua_type(L, -1) != LUA_TSTRING)
                {
                    lua_pop(L, 2); /* key + parent */
                    return false;
                }
                size_t key_len = 0;
                const char *key_lua = lua_tolstring(L, -1, &key_len);
                char *key_copy = g_strndup(key_lua, key_len);
                lua_pop(L, 1); /* key */
                const bool ok =
                    wslua_debugger_index_by_string(L, key_copy);
                g_free(key_copy);
                if (!ok)
                {
                    return false;
                }
            }
        }
        else
        {
            break;
        }
    }
    return true;
}

/**
 * @brief Push @a name onto @a L resolved as the first segment of a watch
 *        path against the paused frame's bindings.
 *
 * Honors the break-on-error snapshot when active: at a runtime-error
 * pause the original activation has been unwound, so @c lua_getstack /
 * @c lua_getlocal / @c lua_getupvalue cannot reach it; the captured
 * @c (name, value_ref) pairs are consulted instead. @c Globals.… still
 * uses @ref wslua_debugger_get_global_or_env_field, which itself
 * substitutes the snapshot's @c _ENV upvalue when paused on an error.
 *
 * On hit returns true with the resolved value at the top of @a L; on
 * miss returns false and leaves the stack unchanged.
 */
static bool
wslua_debugger_push_first_path_segment(lua_State *L, int32_t stack_level,
                                       const char *first_component,
                                       wslua_lookup_first_kind_t first_kind)
{
    if (!first_component || !*first_component)
    {
        return false;
    }

    if (first_kind == WSLUA_LOOKUP_FIRST_GLOBAL_ONLY)
    {
        return wslua_debugger_get_global_or_env_field(L, stack_level,
                                                      first_component);
    }

    /* Locals/Upvalues/AUTO under a runtime-error pause: source of truth
     * is the captured per-frame bindings. The original activation is
     * gone, so the live lua_getstack path below would fail anyway. */
    g_mutex_lock(&debugger.mutex);
    const bool snapshot_active =
        debugger.runtime_error_pause_active &&
        debugger.runtime_error_frame_snapshots != NULL;
    bool found_in_snapshot = false;
    if (snapshot_active)
    {
        const int lookup_mode =
            (first_kind == WSLUA_LOOKUP_FIRST_LOCAL_ONLY) ? 1 :
            (first_kind == WSLUA_LOOKUP_FIRST_UPVALUE_ONLY) ? 2 : 0;
        found_in_snapshot =
            wslua_debugger_push_runtime_error_snapshot_binding_locked(
                L, stack_level, first_component, lookup_mode,
                /*search_all_frames=*/false);
    }
    g_mutex_unlock(&debugger.mutex);

    if (found_in_snapshot)
    {
        return true;
    }
    if (snapshot_active)
    {
        /* AUTO can still fall through to globals at a regular pause; do
         * the same here so Globals.string.format etc. work uniformly. */
        if (first_kind == WSLUA_LOOKUP_FIRST_AUTO)
        {
            return wslua_debugger_get_global_or_env_field(L, stack_level,
                                                          first_component);
        }
        /* LOCAL_ONLY / UPVALUE_ONLY at break-on-error: snapshot is authoritative,
         * a miss is a miss. */
        return false;
    }

    /* Live pause: walk the actual frame. */
    lua_Debug debug_info;
    if (!wslua_debugger_fill_activation(L, stack_level, &debug_info))
    {
        return false;
    }

    if (first_kind == WSLUA_LOOKUP_FIRST_LOCAL_ONLY ||
        first_kind == WSLUA_LOOKUP_FIRST_AUTO)
    {
        int32_t local_index = 1;
        const char *name;
        while ((name = lua_getlocal(L, &debug_info, local_index++)))
        {
            if (g_strcmp0(name, first_component) == 0)
            {
                return true;
            }
            lua_pop(L, 1);
        }
        if (first_kind == WSLUA_LOOKUP_FIRST_LOCAL_ONLY)
        {
            return false;
        }
    }

    if (first_kind == WSLUA_LOOKUP_FIRST_UPVALUE_ONLY ||
        first_kind == WSLUA_LOOKUP_FIRST_AUTO)
    {
        if (wslua_debugger_push_function_for_ar(L, &debug_info))
        {
            int32_t uv = 1;
            const char *nm;
            while ((nm = lua_getupvalue(L, -1, uv++)))
            {
                if (g_strcmp0(nm, first_component) == 0)
                {
                    lua_remove(L, -2); /* function */
                    return true;
                }
                lua_pop(L, 1);
            }
            lua_pop(L, 1); /* function */
        }
        if (first_kind == WSLUA_LOOKUP_FIRST_UPVALUE_ONLY)
        {
            return false;
        }
    }

    /* AUTO fall-through: globals (raw _G) or chunk _ENV. */
    return wslua_debugger_get_global_or_env_field(L, stack_level,
                                                  first_component);
}

/**
 * @brief Lookup a variable path in Lua state.
 * @param L The Lua state.
 * @param path The path to lookup (e.g. "a.b"), without Locals./Upvalues./Globals. prefix.
 * @param first_kind Where the first segment must be resolved (AUTO = legacy order).
 * @return true if found (value on stack), false otherwise.
 *
 * Uniform across regular and break-on-error pauses: the first segment
 * is resolved by @ref wslua_debugger_push_first_path_segment (which
 * honors the runtime-error snapshot transparently); the rest of the
 * walk is the same @ref wslua_debugger_traverse_subpath_on_top used by
 * expression watches and by the Variables tree.
 */
static bool wslua_debugger_lookup_path(lua_State *L, const char *path,
                                       int32_t stack_level,
                                       wslua_lookup_first_kind_t first_kind)
{
    if (!path || !*path)
        return false;

    const char *path_ptr = path;
    const char *end_ptr = path_ptr;
    while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
        end_ptr++;

    char *first_component = g_strndup(path_ptr, end_ptr - path_ptr);
    path_ptr = end_ptr;

    const bool ok = wslua_debugger_push_first_path_segment(
        L, stack_level, first_component, first_kind);
    g_free(first_component);
    if (!ok)
    {
        return false;
    }
    return wslua_debugger_traverse_subpath_on_top(L, path_ptr);
}

static int wslua_debugger_abs_index(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 502
    return lua_absindex(L, idx);
#else
    if (idx > 0 || idx <= LUA_REGISTRYINDEX)
    {
        return idx;
    }
    return lua_gettop(L) + idx + 1;
#endif
}

/**
 * @brief Basic (non-recursive) entry filter for the Variables view.
 *
 * Hides only the wslua __typeof marker that wslua_register_class
 * stores on class tables. Functions are surfaced as ordinary entries
 * (rendered as @c "function: 0xADDR") so that callbacks, methods, and
 * stdlib namespaces are visible the way other Lua debuggers show them.
 * Operates on the (key, value) pair at stack positions (-2, -1).
 */
static bool wslua_debugger_basic_entry_is_hidden(lua_State *L)
{
    if (lua_type(L, -2) == LUA_TSTRING)
    {
        const char *key = lua_tostring(L, -2);
        if (g_strcmp0(key, WSLUA_TYPEOF_FIELD) == 0)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Count raw and visible entries of a table in a single pass.
 *
 * "Visible" uses the basic (non-recursive) filter so the cost stays O(n)
 * and deep nesting does not blow up.
 */
static void wslua_debugger_basic_table_counts(lua_State *L, int idx,
                                              int64_t *total,
                                              int64_t *visible)
{
    const int tableIndex = wslua_debugger_abs_index(L, idx);
    int64_t total_count = 0;
    int64_t visible_count = 0;
    lua_pushnil(L);
    while (lua_next(L, tableIndex) != 0)
    {
        ++total_count;
        if (!wslua_debugger_basic_entry_is_hidden(L))
        {
            ++visible_count;
        }
        lua_pop(L, 1);
    }
    if (total)
    {
        *total = total_count;
    }
    if (visible)
    {
        *visible = visible_count;
    }
}

/**
 * @brief Returns true if the (key, value) pair at stack positions
 *        (-2, -1) should be hidden from the Variables view.
 *
 * Extends the basic filter by also collapsing tables whose entries
 * are entirely wslua internals (an empty class table left after the
 * @c __typeof marker is filtered out). An empty user-defined table
 * is preserved because the raw count distinguishes it from a
 * collapsed namespace.
 */
static bool wslua_debugger_entry_is_hidden(lua_State *L)
{
    if (wslua_debugger_basic_entry_is_hidden(L))
    {
        return true;
    }
    if (lua_type(L, -1) == LUA_TTABLE)
    {
        int64_t total = 0;
        int64_t visible = 0;
        wslua_debugger_basic_table_counts(L, -1, &total, &visible);
        if (total > 0 && visible == 0)
        {
            return true;
        }
    }
    return false;
}

/**
 * @brief Count only visible entries in a table (skipping wslua
 *        internals and namespace tables that collapse to empty).
 *
 * Functions are counted as visible entries — they are rendered like
 * any other value in the Variables view — so the displayed size and
 * expandability reflect everything the user can actually navigate.
 */
static int64_t wslua_debugger_count_visible_table_entries(lua_State *L, int idx)
{
    const int tableIndex = wslua_debugger_abs_index(L, idx);
    int64_t count = 0;
    lua_pushnil(L);
    while (lua_next(L, tableIndex) != 0)
    {
        if (!wslua_debugger_entry_is_hidden(L))
        {
            ++count;
        }
        lua_pop(L, 1);
    }
    return count;
}

/**
 * @brief Push the wslua __getters table for a userdata value onto the stack.
 *
 * Returns true with the __getters table at the top of the stack (the stack
 * otherwise unchanged). Returns false with the stack unchanged when the
 * value at @a idx is not a wslua userdata or has no getters table.
 */
static bool wslua_debugger_push_getters(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (lua_type(L, absIndex) != LUA_TUSERDATA)
    {
        return false;
    }
    if (!lua_getmetatable(L, absIndex))
    {
        return false;
    }
    lua_pushstring(L, "__getters");
    lua_rawget(L, -2);
    if (!lua_istable(L, -1))
    {
        lua_pop(L, 2);
        return false;
    }
    lua_remove(L, -2); /* Drop metatable, leave __getters on top */
    return true;
}

/**
 * @brief Push the Lua __pairs iterator triple for the value at @a idx.
 *
 * On success leaves [iterator, state, initial_key] on the stack (three
 * extra items) and returns true. On failure the stack is unchanged.
 *
 * The iterator is driven by @ref wslua_debugger_pairs_next, which wraps
 * the standard Lua generic-for protocol so the debugger can enumerate
 * any value that opts in via a __pairs metamethod — independently of
 * whether it is a wslua userdata with attribute getters.
 */
static bool wslua_debugger_push_pairs_iterator(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (!luaL_getmetafield(L, absIndex, "__pairs"))
    {
        return false;
    }
    /* Stack: ..., __pairs */
    lua_pushvalue(L, absIndex);
    if (lua_pcall(L, 1, 3, 0) != 0)
    {
        lua_pop(L, 1); /* error */
        return false;
    }
    /* Stack: ..., iterator, state, initial_key */
    return true;
}

/**
 * @brief Drive a __pairs iterator by one step.
 *
 * The top of the stack must hold [iterator, state, last_key] when called.
 * On success the stack holds [iterator, state, new_key, value] and the
 * function returns true. On exhaustion or error the three iterator slots
 * are popped and the function returns false.
 */
static bool wslua_debugger_pairs_next(lua_State *L)
{
    lua_pushvalue(L, -3); /* iterator */
    lua_pushvalue(L, -3); /* state */
    lua_pushvalue(L, -3); /* last key */
    if (lua_pcall(L, 2, 2, 0) != 0)
    {
        lua_pop(L, 1); /* error */
        lua_pop(L, 3); /* iterator, state, last key */
        return false;
    }
    /* Stack: ..., iterator, state, last_key, new_key, value */
    if (lua_isnil(L, -2))
    {
        lua_pop(L, 2); /* new_key (nil), value */
        lua_pop(L, 3); /* iterator, state, last key */
        return false;
    }
    /* Drop the previous key so the caller sees [iter, state, key, value]. */
    lua_remove(L, -3);
    return true;
}

/**
 * @brief Whether a userdata has at least one displayable entry when
 *        iterated via __pairs.
 *
 * Used as a cheap "is it worth offering an expand arrow" check when the
 * value does not expose wslua-style attribute getters. Short-circuits as
 * soon as a displayable entry is found so the cost stays bounded even
 * for large collections.
 */
static bool wslua_debugger_userdata_has_visible_pairs(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (!wslua_debugger_push_pairs_iterator(L, absIndex))
    {
        return false;
    }
    /* Stack: ..., iterator, state, initial_key */
    bool found = false;
    while (wslua_debugger_pairs_next(L))
    {
        /* Stack: ..., iterator, state, key, value */
        if (!wslua_debugger_basic_entry_is_hidden(L))
        {
            found = true;
            lua_pop(L, 2); /* value, key */
            lua_pop(L, 2); /* iterator, state */
            return found;
        }
        lua_pop(L, 1); /* value; pairs_next keeps new key for next step */
    }
    /* pairs_next cleaned up the iterator triple on exhaustion. */
    return found;
}

/**
 * @brief Count userdata attribute getters that are safe to display.
 *
 * Skips the sentinel __typeof entry and anything that is not a C function.
 */
static int64_t wslua_debugger_count_userdata_getters(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    if (!wslua_debugger_push_getters(L, absIndex))
    {
        return 0;
    }
    int64_t count = 0;
    lua_pushnil(L);
    while (lua_next(L, -2) != 0)
    {
        if (lua_type(L, -2) == LUA_TSTRING && lua_iscfunction(L, -1))
        {
            const char *key = lua_tostring(L, -2);
            if (g_strcmp0(key, WSLUA_TYPEOF_FIELD) != 0)
            {
                ++count;
            }
        }
        lua_pop(L, 1);
    }
    lua_pop(L, 1); /* __getters */
    return count;
}

/*
 * Cap preview strings at a modest length so one oversized leaf cannot
 * freeze the Variables view. Tvb's __tostring dumps the full packet as
 * hex; a 1500-byte frame becomes a ~4500 character preview. The raw,
 * untruncated value is reachable via
 * @ref wslua_debugger_read_variable_value_full (used by "Copy value"
 * in the Watch panel) and via the Evaluate pane.
 */
#define WSLUA_DEBUGGER_PREVIEW_MAX_BYTES 256

/*
 * Stringify the Lua value at @p idx. When @p truncate is true the result
 * is capped at WSLUA_DEBUGGER_PREVIEW_MAX_BYTES for display surfaces
 * (Variables tree, watch root/child preview). When false the full
 * luaL_tolstring output is returned so callers such as "Copy value" can
 * deliver the complete text to the clipboard.
 *
 * Function values flow through the generic luaL_tolstring path and
 * render as "function: 0xADDR" — the same shape used by the standard
 * Lua tostring(). They appear as ordinary entries in Locals,
 * Upvalues, Globals, table children, and userdata children, matching
 * how typical Lua debuggers list scopes.
 *
 * Some userdata classes deliberately return "" from __tostring when
 * no meaningful text is available (for example Column when
 * pinfo->cinfo is NULL during details-pane dissection — see
 * wslua_column.c). An empty preview therefore is not necessarily a
 * bug in describe_value; check the class's __tostring before
 * assuming the debugger is dropping data.
 */
static char *wslua_debugger_describe_value_ex(lua_State *L, int idx,
                                              bool truncate)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    const int valueType = lua_type(L, absIndex);
    if (valueType == LUA_TTABLE)
    {
        const int64_t entryCount =
            wslua_debugger_count_visible_table_entries(L, absIndex);
        return g_strdup_printf("table[%" PRId64 "]", entryCount);
    }
    size_t length = 0;
    const char *stringValue = luaL_tolstring(L, absIndex, &length);
    char *result;
    if (truncate && stringValue && length > WSLUA_DEBUGGER_PREVIEW_MAX_BYTES)
    {
        /* Use an ASCII ellipsis ("...") to avoid UTF-8 truncation concerns
         * when the raw preview is binary. */
        result = g_strdup_printf("%.*s...",
                                 WSLUA_DEBUGGER_PREVIEW_MAX_BYTES,
                                 stringValue);
    }
    else if (!truncate && stringValue)
    {
        /* Copy exactly @p length bytes so full values containing embedded
         * NULs (binary data produced by Tvb / ByteArray __tostring)
         * round-trip intact to the clipboard. g_strdup would stop at the
         * first NUL. */
        result = g_strndup(stringValue, length);
    }
    else
    {
        result = g_strdup(stringValue ? stringValue : "");
    }
    lua_pop(L, 1);
    return result;
}

static char *wslua_debugger_describe_value(lua_State *L, int idx)
{
    return wslua_debugger_describe_value_ex(L, idx, true);
}

static bool wslua_debugger_value_can_expand(lua_State *L, int idx)
{
    const int absIndex = wslua_debugger_abs_index(L, idx);
    const int valueType = lua_type(L, absIndex);
    if (valueType == LUA_TTABLE)
    {
        return wslua_debugger_count_visible_table_entries(L, absIndex) > 0;
    }
    if (valueType == LUA_TUSERDATA)
    {
        /* Prefer wslua attribute getters; fall back to the standard
         * Lua __pairs protocol so any iterable userdata can be drilled
         * into without the debugger knowing about the class. */
        if (wslua_debugger_count_userdata_getters(L, absIndex) > 0)
        {
            return true;
        }
        return wslua_debugger_userdata_has_visible_pairs(L, absIndex);
    }
    return false;
}

/**
 * @brief Lua typename, or "userdata (ClassName)" when metatable.__name is a string.
 */
static char *
wslua_debugger_format_value_type(lua_State *L, int idx)
{
#if LUA_VERSION_NUM >= 502
    const int absidx = lua_absindex(L, idx);
#else
    const int absidx =
        (idx > 0 || idx <= LUA_REGISTRYINDEX) ? idx : lua_gettop(L) + idx + 1;
#endif
    const int t = lua_type(L, absidx);
    if (t != LUA_TUSERDATA)
    {
        return g_strdup(lua_typename(L, t));
    }
    if (!lua_getmetatable(L, absidx))
    {
        return g_strdup("userdata");
    }
    const char *cls = NULL;
    if (lua_getfield(L, -1, "__name") && lua_type(L, -1) == LUA_TSTRING)
    {
        cls = lua_tostring(L, -1);
    }
    lua_pop(L, 1); /* __name or nil */
    lua_pop(L, 1); /* metatable */
    if (cls)
    {
        return g_strdup_printf("userdata (%s)", cls);
    }
    return g_strdup("userdata");
}

/**
 * Append child variable rows for the value at stack top (table or userdata).
 * Pops that value.
 * @param globals_subtree When true (Variables path "Globals."…), do not collapse
 *        whole "namespace" tables that only carry the wslua __typeof sentinel —
 *        same as the top-level Globals list — so class/proto tables remain
 *        navigable.
 */
static void
wslua_debugger_append_children_of_value(lua_State *target_L,
                                        GArray *variables_array,
                                        bool globals_subtree)
{
    if (lua_istable(target_L, -1))
    {
        lua_pushnil(target_L);
        while (lua_next(target_L, -2) != 0)
        {
            /* key at -2, value at -1 */

            /* Hide wslua internal markers; in non-globals subtrees
             * also collapse class tables that were only carrying the
             * __typeof sentinel. */
            if (globals_subtree
                    ? wslua_debugger_basic_entry_is_hidden(target_L)
                    : wslua_debugger_entry_is_hidden(target_L))
            {
                lua_pop(target_L, 1);
                continue;
            }

            wslua_variable_t variable;

            /* Key */
            if (lua_type(target_L, -2) == LUA_TSTRING)
            {
                variable.name = g_strdup(lua_tostring(target_L, -2));
            }
            else if (lua_type(target_L, -2) == LUA_TNUMBER)
            {
                /* Use lua_tonumber instead of lua_tostring to avoid
                 * modifying the key on the stack, which would break
                 * lua_next() iteration */
                lua_Number num_key = lua_tonumber(target_L, -2);
                variable.name =
                    g_strdup_printf("[%g]", (double)num_key);
            }
            else
            {
                variable.name = g_strdup(
                    lua_typename(target_L, lua_type(target_L, -2)));
            }

            /* Value */
            variable.type = wslua_debugger_format_value_type(target_L, -1);
            variable.value =
                wslua_debugger_describe_value(target_L, -1);
            if (globals_subtree && lua_istable(target_L, -1))
            {
                /* Match the top-level Globals path: a class table that
                 * only carries the __typeof sentinel still gets an
                 * expand arrow if it has any raw entries, so wslua
                 * namespaces are reachable from anywhere under
                 * Globals. */
                int64_t total = 0;
                wslua_debugger_basic_table_counts(target_L, -1, &total, NULL);
                variable.can_expand = total > 0;
            }
            else
            {
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);
            }
            g_array_append_val(variables_array, variable);
            lua_pop(target_L, 1);
        }
    }
    else if (lua_isuserdata(target_L, -1))
    {
        /* Two introspection protocols are supported, in order:
         *   1. wslua attribute getters (via __getters), which
         *      expose a class's declared properties.
         *   2. the standard Lua __pairs metamethod, for any
         *      iterable userdata (for example a wslua class
         *      backed by a C-side collection).
         *
         * Classes registered with WSLUA_REGISTER_META get an
         * empty __getters table installed by wslua_register_
         * classinstance_meta even when they declare no
         * attributes, so gate the first branch on an actual
         * visible entry rather than the table's existence. */
        const int userdata_abs = lua_gettop(target_L);
        if (wslua_debugger_count_userdata_getters(target_L,
                                                  userdata_abs) > 0 &&
            wslua_debugger_push_getters(target_L, userdata_abs))
        {
            lua_pushnil(target_L);
            while (lua_next(target_L, -2) != 0)
            {
                /* __getters stores: [name] = cfunction. Anything
                 * else (notably the __typeof marker) is ignored. */
                if (lua_type(target_L, -2) != LUA_TSTRING ||
                    !lua_iscfunction(target_L, -1))
                {
                    lua_pop(target_L, 1);
                    continue;
                }

                const char *attr_name = lua_tostring(target_L, -2);
                if (g_strcmp0(attr_name, WSLUA_TYPEOF_FIELD) == 0)
                {
                    lua_pop(target_L, 1);
                    continue;
                }

                /* Protected call: getter(userdata). Errors are
                 * surfaced as the value so traversal keeps working
                 * even if a single attribute raises. */
                lua_pushvalue(target_L, -1);           /* getter */
                lua_pushvalue(target_L, userdata_abs); /* self */
                const int call_status =
                    lua_pcall(target_L, 1, 1, 0);
                if (call_status != 0)
                {
                    wslua_variable_t variable;
                    variable.name = g_strdup(attr_name);
                    variable.type = g_strdup("error");
                    const char *err = lua_tostring(target_L, -1);
                    variable.value =
                        g_strdup(err ? err : "<getter error>");
                    variable.can_expand = false;
                    g_array_append_val(variables_array, variable);
                    lua_pop(target_L, 2); /* error + getter */
                    continue;
                }

                /* Skip attributes that evaluated to nil. A getter
                 * returning nil typically signals "not applicable
                 * for this object variant" (e.g. PseudoHeader
                 * fields that only make sense for a subset of
                 * encapsulations, or a Dumper that has been
                 * closed). Hiding these keeps the view focused on
                 * data that is actually present. */
                if (lua_type(target_L, -1) == LUA_TNIL)
                {
                    lua_pop(target_L, 2); /* result + getter */
                    continue;
                }

                wslua_variable_t variable;
                variable.name = g_strdup(attr_name);
                /*
                 * Tag attribute-backed rows so the UI tooltip makes
                 * the kind obvious: an "attribute" comes from a
                 * wslua __getters entry (class-declared property),
                 * while ordinary locals/upvalues/globals carry the
                 * raw Lua typename.
                 */
                {
                    char *inner =
                        wslua_debugger_format_value_type(target_L, -1);
                    variable.type =
                        g_strdup_printf("attribute (%s)", inner);
                    g_free(inner);
                }
                variable.value =
                    wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 2); /* result + getter */
            }
            lua_pop(target_L, 1); /* __getters */
        }
        else if (wslua_debugger_push_pairs_iterator(target_L,
                                                    userdata_abs))
        {
            /* Stack: ..., userdata, iterator, state, key */
            while (wslua_debugger_pairs_next(target_L))
            {
                /* Stack: ..., userdata, iterator, state, key,
                 *        value */
                /* Hide nil entries for the same reason as in the
                 * attribute path: nil typically marks a slot that
                 * is not meaningful for the current instance. */
                if (lua_type(target_L, -1) == LUA_TNIL)
                {
                    lua_pop(target_L, 1); /* value; keep key */
                    continue;
                }

                wslua_variable_t variable;
                if (lua_type(target_L, -2) == LUA_TSTRING)
                {
                    variable.name =
                        g_strdup(lua_tostring(target_L, -2));
                }
                else if (lua_type(target_L, -2) == LUA_TNUMBER)
                {
                    lua_Number num_key =
                        lua_tonumber(target_L, -2);
                    variable.name =
                        g_strdup_printf("[%g]", (double)num_key);
                }
                else
                {
                    variable.name = g_strdup(lua_typename(
                        target_L, lua_type(target_L, -2)));
                }

                /*
                 * Tag __pairs-sourced rows as "pair" so the UI can
                 * distinguish them from attribute-backed rows and
                 * regular locals in the tooltip.
                 */
                {
                    char *inner =
                        wslua_debugger_format_value_type(target_L, -1);
                    variable.type = g_strdup_printf("pair (%s)", inner);
                    g_free(inner);
                }
                variable.value =
                    wslua_debugger_describe_value(target_L, -1);
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);

                g_array_append_val(variables_array, variable);
                lua_pop(target_L, 1); /* value; keep key */
            }
            /* pairs_next cleaned up the iterator triple. */
        }
    }
    lua_pop(target_L, 1); /* Pop result */
}

/**
 * @brief Get variables for a path.
 * @param path The path (NULL for root).
 * @param variable_count Output pointer for variable count.
 * @return Array of variables.
 */
wslua_variable_t *wslua_debugger_get_variables(const char *path,
                                               int32_t *variable_count)
{
    g_mutex_lock(&debugger.mutex);
    lua_State *target_L = debugger.paused_L ? debugger.paused_L : debugger.L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    const bool runtime_error_snapshot_active =
        debugger.runtime_error_pause_active &&
        debugger.runtime_error_frame_snapshots != NULL &&
        variable_stack_level >= 0 &&
        variable_stack_level < debugger.runtime_error_stack_count;
    g_mutex_unlock(&debugger.mutex);

    if (!target_L)
    {
        *variable_count = 0;
        return NULL;
    }

    GArray *variables_array =
        g_array_new(false, false, sizeof(wslua_variable_t));

    if (!path || !*path)
    {
        /* Root: Locals, Upvalues, Globals */
        wslua_variable_t variable;

        variable.name = g_strdup("Locals");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);

        variable.name = g_strdup("Upvalues");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);

        variable.name = g_strdup("Globals");
        variable.type = g_strdup("section");
        variable.value = g_strdup("");
        variable.can_expand = true;
        g_array_append_val(variables_array, variable);
    }
    else if (g_strcmp0(path, "Locals") == 0)
    {
        if (runtime_error_snapshot_active)
        {
            /* Frame is unwound; iterate the captured (name, ref) pairs
             * and feed each pushed value through the same row formatter
             * used by the live branch. Visible result is identical. */
            g_mutex_lock(&debugger.mutex);
            if (variable_stack_level >= 0 &&
                variable_stack_level < debugger.runtime_error_stack_count)
            {
                const wslua_runtime_error_frame_snapshot_t *frame =
                    &debugger.runtime_error_frame_snapshots[
                        variable_stack_level];
                wslua_debugger_append_runtime_error_bindings_locked(
                    target_L, frame->locals, frame->locals_count,
                    variables_array);
            }
            g_mutex_unlock(&debugger.mutex);
        }
        else
        {
            lua_Debug debug_info;
            if (wslua_debugger_fill_activation(target_L, variable_stack_level,
                                               &debug_info))
            {
                int32_t local_index = 1;
                const char *name;
                while ((name = lua_getlocal(target_L, &debug_info,
                                            local_index++)))
                {
                    if (g_str_has_prefix(name, "("))
                    {
                        lua_pop(target_L, 1);
                        continue;
                    }

                    wslua_variable_t variable;
                    variable.name = g_strdup(name);
                    variable.type =
                        wslua_debugger_format_value_type(target_L, -1);
                    variable.value =
                        wslua_debugger_describe_value(target_L, -1);
                    variable.can_expand =
                        wslua_debugger_value_can_expand(target_L, -1);

                    g_array_append_val(variables_array, variable);
                    lua_pop(target_L, 1);
                }
            }
        }
    }
    else if (g_strcmp0(path, "Upvalues") == 0)
    {
        if (runtime_error_snapshot_active)
        {
            g_mutex_lock(&debugger.mutex);
            if (variable_stack_level >= 0 &&
                variable_stack_level < debugger.runtime_error_stack_count)
            {
                const wslua_runtime_error_frame_snapshot_t *frame =
                    &debugger.runtime_error_frame_snapshots[
                        variable_stack_level];
                wslua_debugger_append_runtime_error_bindings_locked(
                    target_L, frame->upvalues, frame->upvalues_count,
                    variables_array);
            }
            g_mutex_unlock(&debugger.mutex);
        }
        else
        {
            lua_Debug debug_info;
            if (wslua_debugger_fill_activation(target_L, variable_stack_level,
                                               &debug_info) &&
                wslua_debugger_push_function_for_ar(target_L, &debug_info))
            {
                int32_t upvalue_index = 1;
                const char *name;
                while ((name = lua_getupvalue(target_L, -1, upvalue_index)))
                {
                    wslua_variable_t variable;
                    /* C closures use "" as the name for each slot; use a
                     * label so the UI path is valid for expansion. */
                    if (name[0] == '\0')
                    {
                        variable.name =
                            g_strdup_printf("(closure #%d)", upvalue_index);
                    }
                    else
                    {
                        variable.name = g_strdup(name);
                    }
                    variable.type =
                        wslua_debugger_format_value_type(target_L, -1);
                    variable.value =
                        wslua_debugger_describe_value(target_L, -1);
                    variable.can_expand =
                        wslua_debugger_value_can_expand(target_L, -1);

                    g_array_append_val(variables_array, variable);
                    lua_pop(target_L, 1);
                    upvalue_index++;
                }
                lua_pop(target_L, 1); /* Function */
            }
        }
    }
    else if (g_strcmp0(path, "Globals") == 0)
    {
        /* Globals (_G) — limit to avoid freezing the UI */
#define WSLUA_GLOBALS_DISPLAY_LIMIT 500
        unsigned globals_count = 0;
        lua_pushglobaltable(target_L);
        /* Iterate table */
        lua_pushnil(target_L);
        while (lua_next(target_L, -2) != 0)
        {
            if (globals_count >= WSLUA_GLOBALS_DISPLAY_LIMIT)
            {
                lua_pop(target_L, 2); /* key + value */
                /* Add a sentinel entry so the user knows the list is truncated */
                wslua_variable_t truncated;
                truncated.name = g_strdup_printf(
                    "... (%u+ globals, showing first %u)",
                    WSLUA_GLOBALS_DISPLAY_LIMIT, WSLUA_GLOBALS_DISPLAY_LIMIT);
                truncated.type = g_strdup("");
                truncated.value = g_strdup("");
                truncated.can_expand = false;
                g_array_append_val(variables_array, truncated);
                break;
            }

            /* Hide only the wslua __typeof marker. Any other entry —
             * including functions, class tables, and stdlib namespaces
             * like @c string / @c table — is shown so the global scope
             * matches what a typical Lua debugger lists. */
            if (wslua_debugger_basic_entry_is_hidden(target_L))
            {
                lua_pop(target_L, 1);
                continue;
            }

            wslua_variable_t variable;

            if (lua_type(target_L, -2) == LUA_TSTRING)
            {
                variable.name = g_strdup(lua_tostring(target_L, -2));
            }
            else
            {
                /* Skip non-string globals for now or format them */
                lua_pop(target_L, 1);
                continue;
            }

            variable.type =
                wslua_debugger_format_value_type(target_L, -1);
            variable.value = wslua_debugger_describe_value(target_L, -1);
            /* value_can_expand() uses the "visible" filter and would hide
             * namespace tables we just listed; use raw count so they stay
             * navigable. */
            if (lua_istable(target_L, -1))
            {
                int64_t total = 0;
                wslua_debugger_basic_table_counts(target_L, -1, &total, NULL);
                variable.can_expand = total > 0;
            }
            else
            {
                variable.can_expand =
                    wslua_debugger_value_can_expand(target_L, -1);
            }

            g_array_append_val(variables_array, variable);
            lua_pop(target_L, 1);
            globals_count++;
        }
        lua_pop(target_L, 1); /* Table */
    }
    else
    {
        /* Lookup path */
        /* Strip prefix if present; honor explicit section (no shadowing). */
        const char *lookup_path = path;
        wslua_lookup_first_kind_t lk_first = WSLUA_LOOKUP_FIRST_AUTO;
        if (g_str_has_prefix(path, "Locals."))
        {
            lookup_path = path + 7;
            lk_first = WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
        }
        else if (g_str_has_prefix(path, "Upvalues."))
        {
            lookup_path = path + 9;
            lk_first = WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
        }
        else if (g_str_has_prefix(path, "Globals."))
        {
            lookup_path = path + 8;
            lk_first = WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
        }

        if (wslua_debugger_lookup_path(target_L, lookup_path,
                                       variable_stack_level, lk_first))
        {
            const bool globals_subtree =
                path && g_str_has_prefix(path, "Globals.");
            wslua_debugger_append_children_of_value(target_L, variables_array,
                                                    globals_subtree);
        }
    }

    *variable_count = (int32_t)variables_array->len;
    return (wslua_variable_t *)g_array_free(variables_array, false);
}

/**
 * @brief Free variables array.
 * @param variables The array.
 * @param variable_count The count.
 */
void wslua_debugger_free_variables(wslua_variable_t *variables,
                                   int32_t variable_count)
{
    wslua_debugger_free_variable_records(variables, variable_count);
}

/**
 * @brief Get breakpoint count.
 * @return The number of breakpoints.
 */
unsigned wslua_debugger_get_breakpoint_count(void)
{
    ensure_breakpoints_initialized();
    g_mutex_lock(&debugger.mutex);
    const unsigned len = breakpoints_array->len;
    g_mutex_unlock(&debugger.mutex);
    return len;
}

bool wslua_debugger_get_breakpoint(unsigned idx, const char **file_path,
                                   int64_t *line, bool *active)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    if (idx >= breakpoints_array->len)
    {
        g_mutex_unlock(&debugger.mutex);
        return false;
    }

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    *file_path = bp->file_path;
    *line = bp->line;
    *active = bp->active;
    g_mutex_unlock(&debugger.mutex);
    return true;
}

bool wslua_debugger_get_breakpoint_extended(
    unsigned idx, const char **file_path, int64_t *line, bool *active,
    const char **condition, int64_t *hit_count_target, int64_t *hit_count,
    bool *condition_error, const char **log_message,
    wslua_hit_count_mode_t *hit_count_mode,
    bool *log_also_pause)
{
    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    if (idx >= breakpoints_array->len)
    {
        g_mutex_unlock(&debugger.mutex);
        return false;
    }

    wslua_breakpoint_t *bp =
        &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
    if (file_path)        *file_path = bp->file_path;
    if (line)             *line = bp->line;
    if (active)           *active = bp->active;
    if (condition)        *condition = bp->condition;
    if (hit_count_target) *hit_count_target = bp->hit_count_target;
    if (hit_count)        *hit_count = bp->hit_count;
    if (condition_error)  *condition_error = bp->condition_error;
    if (log_message)      *log_message = bp->log_message;
    if (hit_count_mode)   *hit_count_mode = bp->hit_count_mode;
    if (log_also_pause)   *log_also_pause = bp->log_also_pause;
    g_mutex_unlock(&debugger.mutex);
    return true;
}

char *
wslua_debugger_get_breakpoint_condition_error_message(unsigned idx)
{
    ensure_breakpoints_initialized();

    char *out = NULL;
    g_mutex_lock(&debugger.mutex);
    if (idx < breakpoints_array->len)
    {
        const wslua_breakpoint_t *bp =
            &g_array_index(breakpoints_array, wslua_breakpoint_t, idx);
        if (bp->condition_error_msg)
        {
            out = g_strdup(bp->condition_error_msg);
        }
    }
    g_mutex_unlock(&debugger.mutex);
    return out;
}

/* Reload callback */
static wslua_debugger_reload_callback_t reload_callback = NULL;

/* Logpoint emit callback. Stored as @c gpointer so the line hook can
 * read it with @c g_atomic_pointer_get without taking a lock; the
 * dialog's destructor sets it back to NULL on the GUI thread, which
 * would otherwise race with the hook on the Lua thread. */
static gpointer log_emit_callback = NULL;

/* Silent-bump notification: the line hook sets this 0->1 the first
 * time it advances any breakpoint's @c hit_count in an "epoch" and
 * (only on that 0->1 transition) dispatches the registered
 * callback. The UI clears the flag during its drain via
 * @ref wslua_debugger_clear_breakpoint_state_dirty so the next bump
 * re-arms the trampoline. The single-bit gate keeps the dispatch
 * cost on a per-packet hot line to one notification per Qt
 * event-loop tick — see @ref notify_breakpoint_state_dirty. */
static gint     breakpoint_state_dirty_atomic   = 0;
static gpointer breakpoint_state_dirty_callback = NULL;

static inline void notify_breakpoint_state_dirty(void)
{
    if (g_atomic_int_compare_and_exchange(
            &breakpoint_state_dirty_atomic, 0, 1))
    {
        wslua_debugger_breakpoint_state_dirty_callback_t cb =
            (wslua_debugger_breakpoint_state_dirty_callback_t)
                g_atomic_pointer_get(&breakpoint_state_dirty_callback);
        if (cb)
            cb();
    }
}

void wslua_debugger_register_breakpoint_state_dirty_callback(
    wslua_debugger_breakpoint_state_dirty_callback_t callback)
{
    g_atomic_pointer_set(&breakpoint_state_dirty_callback,
                          (gpointer)callback);
}

void wslua_debugger_clear_breakpoint_state_dirty(void)
{
    g_atomic_int_set(&breakpoint_state_dirty_atomic, 0);
}

/**
 * @brief Register a callback to be notified before Lua plugins are reloaded.
 *
 * The debugger UI uses this to reload script files from disk before
 * Lua executes them, ensuring breakpoints show current code.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_reload_callback(
    wslua_debugger_reload_callback_t callback)
{
    reload_callback = callback;
}

void wslua_debugger_register_log_emit_callback(
    wslua_debugger_log_emit_callback_t callback)
{
    g_atomic_pointer_set(&log_emit_callback, (gpointer)callback);
}

/**
 * @brief Notify the debugger that a reload is about to happen.
 *
 * Saves the debugger enabled state, disables the debugger, detaches
 * from the current Lua state, and calls the reload callback so the
 * UI can refresh script files from disk.
 *
 * If the debugger is paused, it is disabled (which continues execution)
 * and the reload callback is invoked so the UI can exit its nested
 * event loop and schedule a deferred reload.
 *
 * @return true if the caller should proceed with the reload immediately;
 *         false if the reload was deferred (debugger was paused).
 */
bool wslua_debugger_notify_reload(void)
{
    bool should_disable = false;
    bool was_paused = false;
    bool is_first_notify = false;

    g_mutex_lock(&debugger.mutex);
    if (!debugger.reload_in_progress)
    {
        debugger.reload_in_progress = true;
        debugger.was_enabled_before_reload = debugger.enabled;
        debugger.error_break_was_enabled_before_reload =
            debugger.error_break_enabled;
        debugger.error_break_enabled = false;
        is_first_notify = true;
    }
    /* Reload starts with a fresh Lua state; clear stale one-shot error markers
     * so they don't leak across reload boundaries and desynchronize pause UI. */
    debugger.error_break_occurred = false;
    debugger.explicit_error_break_recent = false;
    should_disable = debugger.enabled;
    was_paused = debugger.state == WSLUA_DEBUGGER_PAUSED;

    if (was_paused)
    {
        debugger.state = WSLUA_DEBUGGER_RUNNING;
        wslua_debugger_clear_transient_state_locked(true);
    }

    g_mutex_unlock(&debugger.mutex);

    if (should_disable)
    {
        wslua_debugger_set_enabled(false);
    }

    debugger.L = NULL;

    /* Only fire callback on first notify to avoid duplicate UI reloads. */
    if (is_first_notify && reload_callback)
    {
        reload_callback();
    }

    return !was_paused;
}

/**
 * @brief Post-reload callback storage.
 */
static wslua_debugger_post_reload_callback_t post_reload_callback = NULL;

/**
 * @brief Register a callback to be notified after Lua plugins are reloaded.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_post_reload_callback(
    wslua_debugger_post_reload_callback_t callback)
{
    post_reload_callback = callback;
}

/**
 * @brief Notify listeners that reload has completed.
 *
 * Called by wslua_reload_plugins() AFTER wslua_init() completes.
 * Clears the reload_in_progress flag and fires the post-reload UI
 * callback so the file tree is refreshed with newly loaded scripts.
 *
 * The debugger is NOT re-enabled here.  The UI must call
 * wslua_debugger_restore_after_reload() once cf_reload / redissect
 * has finished, to avoid the debug hook firing while packets are
 * still being re-read.
 *
 * Break-on-error IS restored here (before the post-reload UI callback)
 * because break-on-error state has no dissection-reentrancy concern: the line hook
 * stays uninstalled until restore_after_reload runs, and the error/assert
 * wrappers are not installed until enabled is flipped back on. Restoring
 * break-on-error early keeps the UI's break-on-error button in sync when the post-reload
 * callback chain refreshes it from the core state.
 */
void wslua_debugger_notify_post_reload(void)
{
    bool restore_break_on_error = false;

    g_mutex_lock(&debugger.mutex);
    debugger.reload_in_progress = false;
    /* Restore break-on-error if we snapshotted it in notify_reload, unless the user
     * has since turned the whole debugger off on purpose. */
    if (debugger.error_break_was_enabled_before_reload &&
        !debugger.user_explicitly_disabled)
    {
        restore_break_on_error = true;
    }
    debugger.error_break_was_enabled_before_reload = false;
    g_mutex_unlock(&debugger.mutex);

    if (restore_break_on_error)
    {
        wslua_debugger_set_error_break_enabled(true);
    }

    if (post_reload_callback)
    {
        post_reload_callback();
    }
}

/**
 * @brief Re-enable the debugger after a reload + cf_reload cycle.
 *
 * If the debugger was enabled before the reload, re-enable it now
 * that the file has been fully re-read.  This must be called AFTER
 * cf_reload / redissectPackets completes.
 */
void wslua_debugger_restore_after_reload(void)
{
    bool need_enable = false;

    g_mutex_lock(&debugger.mutex);
    if (!debugger.was_enabled_before_reload)
    {
        g_mutex_unlock(&debugger.mutex);
        return;
    }
    debugger.was_enabled_before_reload = false;
    if (debugger.user_explicitly_disabled)
    {
        g_mutex_unlock(&debugger.mutex);
        return;
    }
    need_enable = !debugger.enabled && debugger.L != NULL;
    g_mutex_unlock(&debugger.mutex);

    if (need_enable)
    {
        wslua_debugger_set_enabled(true);
    }
}

/**
 * @brief Script-loaded callback storage.
 */
static wslua_debugger_script_loaded_callback_t script_loaded_callback = NULL;

/**
 * @brief Register a callback to be notified when a Lua script is loaded.
 *
 * @param callback The callback function, or NULL to unregister.
 */
void wslua_debugger_register_script_loaded_callback(
    wslua_debugger_script_loaded_callback_t callback)
{
    script_loaded_callback = callback;
}

/**
 * @brief Notify the debugger that a Lua script has been loaded.
 *
 * Called by the Lua loader when a script is successfully loaded.
 *
 * @param file_path The full path to the loaded script file.
 */
void wslua_debugger_notify_script_loaded(const char *file_path)
{
    if (script_loaded_callback && file_path)
    {
        script_loaded_callback(file_path);
    }
}

/**
 * @brief Check if the debugger is currently paused.
 * @return true if paused at a breakpoint, false otherwise.
 */
bool wslua_debugger_is_paused(void)
{
    g_mutex_lock(&debugger.mutex);
    bool paused = debugger.state == WSLUA_DEBUGGER_PAUSED &&
                  debugger.paused_L != NULL;
    g_mutex_unlock(&debugger.mutex);
    return paused;
}

void wslua_debugger_forget_lua_thread(lua_State *L)
{
    if (L == NULL)
    {
        return;
    }

    bool need_hook_update = false;

    g_mutex_lock(&debugger.mutex);

    if (debugger.paused_L == L)
    {
        debugger.paused_L = NULL;
        debugger.runtime_error_pause_active = false;
        if (debugger.state == WSLUA_DEBUGGER_PAUSED)
        {
            debugger.state = WSLUA_DEBUGGER_RUNNING;
            debugger.step_kind = WSLUA_STEP_KIND_NONE;
            need_hook_update = debugger.enabled;
        }
    }

    if (debugger.runtime_error_stack_L == L)
    {
        wslua_debugger_clear_runtime_error_snapshot_locked();
    }

    g_mutex_unlock(&debugger.mutex);

    if (need_hook_update)
    {
        wslua_debugger_update_hook();
    }
}

/**
 * @brief Maximum number of Lua instructions allowed during evaluation.
 *
 * This prevents infinite loops from hanging Wireshark.  The limit is
 * generous enough for any reasonable inspection expression but will
 * abort runaway code within a fraction of a second.
 */
#define WSLUA_EVAL_INSTRUCTION_LIMIT 1000000

/**
 * @brief Maximum call depth allowed during evaluation.
 *
 * This catches deep recursion that could overflow the C stack before
 * the instruction-count limit triggers.
 */
#define WSLUA_EVAL_MAX_CALL_DEPTH 100

/** @brief Current call depth during expression evaluation. */
static int eval_call_depth;

/**
 * @brief Mirror of the @c lua_State prefix needed to reach @c allowhook.
 *
 * Lua's @c luaD_hook flips @c L->allowhook to 0 before invoking any debug
 * hook (to block hook re-entry). The Lua Debugger runs the entire Qt event
 * loop *inside* its line hook, so by the time the Watch/Evaluate panel calls
 * @ref wslua_debugger_run_expr_chunk, @c allowhook is still 0 and Lua's
 * @c luaD_hook silently swallows our timeout-hook callbacks. Without
 * restoring it, a runaway expression like @c "while true do end" loops
 * unbounded and freezes Wireshark.
 *
 * @c lstate.h is private (Homebrew/distro Lua packages do not install it),
 * so we mirror just enough of @c struct @c lua_State to access the byte.
 *
 * Layouts on Lua 5.4 and 5.5 differ only in whether @c status precedes
 * @c allowhook; both put @c allowhook a few bytes after @c CommonHeader:
 *   - Lua 5.4: @c CommonHeader; @c status; @c allowhook; ...
 *   - Lua 5.5: @c CommonHeader; @c allowhook; @c status; ...
 *
 * On Lua 5.3 (which Wireshark still nominally supports as a build floor)
 * @c allowhook sits at the *end* of @c struct @c lua_State, behind a long
 * trail of variably-sized fields. Encoding that layout safely from outside
 * @c lstate.h would mean re-deriving offsets per architecture and per
 * 5.3.x patch release, so on @c < @c 5.4 we ship no-op stubs instead: the
 * timeout hook is silently inactive (matching the pre-existing 5.3
 * behavior, since the same @c allowhook gate applied there too) and a
 * one-shot @c g_warning surfaces the limitation at runtime. The
 * @c #error below catches future Lua releases until the mirror is
 * taught their prefix layout.
 */
#if LUA_VERSION_NUM >= 504
typedef struct
{
    void *_next;            /* CommonHeader: GCObject *next */
    unsigned char _tt;      /* CommonHeader: lu_byte tt     */
    unsigned char _marked;  /* CommonHeader: lu_byte marked */
#if LUA_VERSION_NUM == 504
    unsigned char _status;
    unsigned char allowhook;
#elif LUA_VERSION_NUM == 505
    unsigned char allowhook;
#else
#  error "wslua_debugger: unsupported Lua version (need 5.3 or 5.4 or 5.5)"
#endif
} wslua_dbg_lstate_prefix;

static inline unsigned char wslua_dbg_get_allowhook(lua_State *L)
{
    return ((wslua_dbg_lstate_prefix *)L)->allowhook;
}

static inline void wslua_dbg_set_allowhook(lua_State *L, unsigned char v)
{
    ((wslua_dbg_lstate_prefix *)L)->allowhook = v;
}

#define WSLUA_DBG_HAS_ALLOWHOOK_FLIP 1

#else  /* LUA_VERSION_NUM < 504 */

static inline unsigned char wslua_dbg_get_allowhook(lua_State *L _U_)
{
    return 0;
}

static inline void wslua_dbg_set_allowhook(lua_State *L _U_,
                                           unsigned char v _U_)
{
}

#define WSLUA_DBG_HAS_ALLOWHOOK_FLIP 0

#endif  /* LUA_VERSION_NUM */

/**
 * @brief Hook that aborts evaluation on instruction limit or deep recursion.
 */
static void wslua_eval_timeout_hook(lua_State *L, lua_Debug *ar)
{
    if (ar->event == LUA_HOOKCALL || ar->event == LUA_HOOKTAILCALL)
    {
        eval_call_depth++;
        if (eval_call_depth > WSLUA_EVAL_MAX_CALL_DEPTH)
        {
            luaL_error(L, "Evaluation aborted: call depth limit (%d) exceeded "
                       "(possible infinite recursion)",
                       WSLUA_EVAL_MAX_CALL_DEPTH);
        }
        return;
    }
    if (ar->event == LUA_HOOKRET)
    {
        if (eval_call_depth > 0)
        {
            eval_call_depth--;
        }
        return;
    }
    /* LUA_HOOKCOUNT — instruction limit reached */
    luaL_error(L, "Evaluation aborted: instruction limit (%d) exceeded "
               "(possible infinite loop)",
               WSLUA_EVAL_INSTRUCTION_LIMIT);
}

/**
 * Build a compilable Lua chunk from a user expression.
 *
 * Three forms are tried, in order, and the first one that compiles is
 * returned:
 *
 *   1. If the text starts with '=', use @c "return <rest>" verbatim
 *      (no surrounding parens). Kept as a back-compat shortcut for
 *      Evaluate-panel users who type @c =f() to preserve all return
 *      values; no other shape relies on this.
 *   2. @c "return (<expr>)" — captures any value-returning expression
 *      (function calls, arithmetic, indexing, table constructors, …).
 *      The parentheses adjust a multi-valued call to exactly one value,
 *      mirroring Lua's own @c (f()) idiom.
 *   3. @c "<expr>" as a plain chunk — the fallback for shapes that
 *      cannot be returned (statements, blocks, declarations: @c "x = 1",
 *      @c "if … then … end", @c "local x = …", @c "for … do … end").
 *
 * Compilation is side-effect-free in Lua, so trying step 2 and falling
 * through to step 3 on a syntax error costs nothing at runtime; the user
 * code only runs when the chosen form is later @c lua_pcall'd.
 *
 * @return Newly allocated source for luaL_loadstring(), or NULL on failure.
 */
static char *
wslua_debugger_expression_compilable_chunk(lua_State *L,
                                             const char *expression,
                                             char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }

    char *trimmed = g_strdup(expression);
    g_strstrip(trimmed);
    if (!*trimmed)
    {
        g_free(trimmed);
        if (error_msg)
        {
            *error_msg = g_strdup("Empty expression");
        }
        return NULL;
    }

    if (trimmed[0] == '=')
    {
        char *chunk = g_strdup_printf("return %s", trimmed + 1);
        g_free(trimmed);
        if (luaL_loadstring(L, chunk) != LUA_OK)
        {
            if (error_msg)
            {
                *error_msg =
                    g_strdup(lua_tostring(L, -1) ? lua_tostring(L, -1)
                                                : "Syntax error");
            }
            lua_pop(L, 1);
            g_free(chunk);
            return NULL;
        }
        lua_pop(L, 1);
        return chunk;
    }

    /* Prefer the value-capturing form so a bare function/method call
     * (@c f(), @c pkt:src_eth():tostring()) shows its return value
     * instead of running as a value-discarding statement. */
    char *chunk = g_strdup_printf("return (%s)", trimmed);
    if (luaL_loadstring(L, chunk) == LUA_OK)
    {
        lua_pop(L, 1);
        g_free(trimmed);
        return chunk;
    }
    lua_pop(L, 1);
    g_free(chunk);

    /* Statements / blocks / declarations: re-try as a plain chunk so
     * @c "x = 1", @c "if … then … end", @c "local x = …", and
     * @c "for … do … end" still execute for their side effects. */
    chunk = g_strdup(trimmed);
    if (luaL_loadstring(L, chunk) == LUA_OK)
    {
        lua_pop(L, 1);
        g_free(trimmed);
        return chunk;
    }
    /* Surface the chunk-form syntax error: it is more representative of
     * what the user actually typed than the @c "return (…)" wrapper
     * complaint, which tends to point at the inserted parens. */
    if (error_msg)
    {
        *error_msg =
            g_strdup(lua_tostring(L, -1) ? lua_tostring(L, -1)
                                          : "Syntax error");
    }
    lua_pop(L, 1);
    g_free(chunk);
    g_free(trimmed);
    return NULL;
}

bool wslua_debugger_check_condition_syntax(const char *expression,
                                           char **err_msg)
{
    if (err_msg)
        *err_msg = NULL;
    if (!expression || !expression[0])
    {
        if (err_msg)
            *err_msg = g_strdup("Empty expression");
        return false;
    }
    /* Use a throwaway state so the syntax check has no observable side
     * effects on the live debugger Lua state. luaL_loadstring is a parse-
     * only operation, so creating a fresh state for it is cheap and lets
     * us run the same checker that the runtime evaluator uses. */
    lua_State *L = luaL_newstate();
    if (!L)
    {
        if (err_msg)
            *err_msg = g_strdup("Failed to create Lua state");
        return false;
    }
    char *chunk =
        wslua_debugger_expression_compilable_chunk(L, expression, err_msg);
    const bool ok = (chunk != NULL);
    g_free(chunk);
    lua_close(L);
    return ok;
}

void wslua_debugger_set_breakpoint_condition_error(const char *file_path,
                                                    int64_t line,
                                                    const char *err_msg)
{
    char *norm_file_path = wslua_debugger_dup_canonical_path(file_path);
    if (!norm_file_path)
        return;

    ensure_breakpoints_initialized();

    g_mutex_lock(&debugger.mutex);
    wslua_breakpoint_t *bp = find_breakpoint_locked(norm_file_path, line);
    if (bp)
    {
        g_free(bp->condition_error_msg);
        if (err_msg && err_msg[0])
        {
            bp->condition_error = true;
            bp->condition_error_msg = g_strdup(err_msg);
        }
        else
        {
            bp->condition_error = false;
            bp->condition_error_msg = NULL;
        }
    }
    g_mutex_unlock(&debugger.mutex);
    g_free(norm_file_path);
}

/**
 * Section-proxy kinds — index into the static metadata table below and
 * also distinguish the @c __index closure flavors. Order matches the
 * @c WSLUA_LOOKUP_FIRST_* enum's local/upvalue/global ordering for clarity.
 */
enum
{
    WSLUA_SECTION_LOCALS = 0,
    WSLUA_SECTION_UPVALUES = 1,
    WSLUA_SECTION_GLOBALS = 2,
};

/** Map a section-proxy kind to the matching first-segment lookup mode. */
static wslua_lookup_first_kind_t
wslua_debugger_section_lookup_kind(int section_kind)
{
    switch (section_kind)
    {
    case WSLUA_SECTION_LOCALS:
        return WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
    case WSLUA_SECTION_UPVALUES:
        return WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
    case WSLUA_SECTION_GLOBALS:
        return WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
    default:
        return WSLUA_LOOKUP_FIRST_AUTO;
    }
}

/** Display name for a section proxy (used by @c __tostring / debug output). */
static const char *
wslua_debugger_section_name(int section_kind)
{
    switch (section_kind)
    {
    case WSLUA_SECTION_LOCALS:
        return "Locals";
    case WSLUA_SECTION_UPVALUES:
        return "Upvalues";
    case WSLUA_SECTION_GLOBALS:
        return "Globals";
    default:
        return "Section";
    }
}

/**
 * @brief Recompute the live stack level inside an env / section metamethod.
 *
 * At a regular pause the chunk and any callees the chunk has entered all
 * sit on top of the originally paused frames in the call stack, so the
 * user-selected "paused" level needs the live call-depth delta added
 * back in to refer to the same activation record.
 *
 * At a break-on-error pause the original frame has already been unwound,
 * so all snapshot-aware lookups (locals/upvalues bindings and the
 * captured @c _ENV) treat @a paused_level as a frame index into
 * @c runtime_error_frame_snapshots — independent of the chunk's
 * recursion depth on the live stack. Returning @a paused_level unchanged
 * here keeps Globals/Upvalues/Locals lookups pointed at the correct
 * captured frame.
 */
static int32_t
wslua_debugger_effective_paused_level(lua_State *L, int32_t paused_level,
                                      int32_t baseline_depth)
{
    g_mutex_lock(&debugger.mutex);
    const bool snapshot_active =
        debugger.runtime_error_pause_active &&
        debugger.runtime_error_frame_snapshots != NULL;
    g_mutex_unlock(&debugger.mutex);
    if (snapshot_active)
    {
        return paused_level;
    }

    int32_t now_depth = 0;
    lua_Debug ar;
    while (lua_getstack(L, now_depth, &ar))
        now_depth++;
    const int32_t added = now_depth - baseline_depth;
    return (added > 0 ? added : 0) + paused_level;
}

/**
 * @brief @c __index for a Locals/Upvalues/Globals section proxy.
 *
 * Closure upvalues:
 *   1. paused_stack_level (lua_Integer) — same as @c env_index.
 *   2. paused_call_depth  (lua_Integer) — same as @c env_index.
 *   3. section_kind       (lua_Integer) — one of @c WSLUA_SECTION_*.
 *
 * Indexing the proxy with a string key resolves the key as a name in
 * exactly that section: a Locals.x lookup never falls through to upvalues
 * or globals. This mirrors the path-watch grammar where @c Locals.foo /
 * @c Upvalues.foo / @c Globals.foo bind the first segment to a single
 * section. Misses return @c nil; non-string keys also return @c nil
 * (a section is "named" only by identifier).
 */
static int wslua_debugger_section_index(lua_State *L)
{
    const int32_t paused_level =
        (int32_t)lua_tointeger(L, lua_upvalueindex(1));
    const int32_t baseline_depth =
        (int32_t)lua_tointeger(L, lua_upvalueindex(2));
    const int section_kind = (int)lua_tointeger(L, lua_upvalueindex(3));

    if (lua_type(L, 2) != LUA_TSTRING)
    {
        lua_pushnil(L);
        return 1;
    }
    const char *key = lua_tostring(L, 2);
    if (!key || !*key)
    {
        lua_pushnil(L);
        return 1;
    }

    const wslua_lookup_first_kind_t lk =
        wslua_debugger_section_lookup_kind(section_kind);

    /* Locals/Upvalues at a runtime-error pause: the live frame is gone,
     * so we resolve straight from the captured per-frame bindings rather
     * than walk a stack that no longer contains the original activation.
     * Globals is intentionally excluded here — globals don't live on a
     * frame, and the lookup_path call below is snapshot-aware via
     * wslua_debugger_get_global_or_env_field, which handles _ENV
     * fallback against the captured chunk environment. */
    if (lk == WSLUA_LOOKUP_FIRST_LOCAL_ONLY ||
        lk == WSLUA_LOOKUP_FIRST_UPVALUE_ONLY)
    {
        g_mutex_lock(&debugger.mutex);
        const bool snapshot_active =
            debugger.runtime_error_pause_active &&
            debugger.runtime_error_frame_snapshots != NULL;
        bool found_in_snapshot = false;
        if (snapshot_active)
        {
            found_in_snapshot =
                wslua_debugger_push_runtime_error_snapshot_binding_locked(
                    L, paused_level, key,
                    (lk == WSLUA_LOOKUP_FIRST_LOCAL_ONLY) ? 1 : 2,
                    false);
        }
        g_mutex_unlock(&debugger.mutex);

        if (found_in_snapshot)
        {
            return 1;
        }
        if (snapshot_active)
        {
            /* Section is authoritative: a miss is a miss. */
            lua_pushnil(L);
            return 1;
        }
    }

    const int32_t effective_level = wslua_debugger_effective_paused_level(
        L, paused_level, baseline_depth);
    if (wslua_debugger_lookup_path(L, key, effective_level, lk))
    {
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

/**
 * @brief @c __tostring for a section proxy: yields "Locals" / "Upvalues" /
 *        "Globals" so a bare-section watch row shows a readable preview
 *        instead of @c "table: 0x…".
 *
 * Single closure upvalue: the section_kind integer (same encoding as
 * @ref wslua_debugger_section_index's third upvalue).
 */
static int wslua_debugger_section_tostring(lua_State *L)
{
    const int section_kind = (int)lua_tointeger(L, lua_upvalueindex(1));
    lua_pushstring(L, wslua_debugger_section_name(section_kind));
    return 1;
}

/**
 * @brief Push a fresh "section proxy" table whose @c __index resolves
 *        string keys against the named section of the originally paused
 *        frame.
 *
 * The proxy itself is an empty table with a sealed metatable
 * (@c __metatable is set to a string so @c getmetatable returns the
 * label rather than the underlying mt). It is constructed fresh on every
 * env_index hit so the closure upvalues capture the current paused-frame
 * coordinates; this is cheap and avoids cross-pause aliasing.
 */
static void
wslua_debugger_push_section_proxy(lua_State *L, int32_t paused_level,
                                  int32_t baseline_depth, int section_kind)
{
    lua_newtable(L); /* proxy */
    lua_newtable(L); /* metatable */

    lua_pushinteger(L, paused_level);
    lua_pushinteger(L, baseline_depth);
    lua_pushinteger(L, section_kind);
    lua_pushcclosure(L, wslua_debugger_section_index, 3);
    lua_setfield(L, -2, "__index");

    lua_pushinteger(L, section_kind);
    lua_pushcclosure(L, wslua_debugger_section_tostring, 1);
    lua_setfield(L, -2, "__tostring");

    /* Sealed metatable: getmetatable(Locals) returns the label string,
     * keeping user code from swapping the proxy's __index out from under
     * us mid-expression. */
    lua_pushstring(L, wslua_debugger_section_name(section_kind));
    lua_setfield(L, -2, "__metatable");

    lua_setmetatable(L, -2);
}

/**
 * @brief @c __index for the chunk environment used by the eval/watch
 *        expression runner; resolves a name against the originally paused
 *        frame's locals → upvalues → globals (with @c _ENV fallback).
 *
 * Closure upvalues:
 *   1. paused_stack_level (lua_Integer) — the user-selected variable stack
 *      level at pause entry.
 *   2. paused_call_depth   (lua_Integer) — the number of Lua activation
 *      records on @p paused_L at the moment the chunk was about to run.
 *      Used to translate @a paused_stack_level into the "live" level seen
 *      from inside this metamethod, which is buried under the chunk and
 *      whatever the chunk has called.
 *
 * Notes:
 *   - Resolution mirrors @ref WSLUA_LOOKUP_FIRST_AUTO so a bare identifier
 *     in an expression watch behaves the same as a bare identifier in a
 *     path watch (locals, then upvalues, then globals/_ENV).
 *   - The names @c Locals, @c Upvalues, and @c Globals are reserved tokens
 *     and resolve to virtual section-proxy tables (see
 *     @ref wslua_debugger_push_section_proxy) so expressions like
 *     @c "Locals.x + 1" or @c "#Globals.list" work the same way the
 *     section prefix works in path-style watches. This shadows any user
 *     binding of the same name, mirroring the path-watch grammar where
 *     these tokens are reserved as well.
 *   - Non-string keys (e.g. anything Lua's @c <name>.foo could not produce)
 *     are returned as @c nil rather than walking the lookup chain; this is
 *     defensive — Lua only generates string keys for the @c "global"-style
 *     accesses that drive the chunk's @c _ENV.
 */
static int wslua_debugger_env_index(lua_State *L)
{
    /* upvalue 1: paused stack level (int); upvalue 2: paused call depth. */
    const int32_t paused_level =
        (int32_t)lua_tointeger(L, lua_upvalueindex(1));
    const int32_t baseline_depth =
        (int32_t)lua_tointeger(L, lua_upvalueindex(2));

    if (lua_type(L, 2) != LUA_TSTRING)
    {
        lua_pushnil(L);
        return 1;
    }
    const char *key = lua_tostring(L, 2);
    if (!key || !*key)
    {
        lua_pushnil(L);
        return 1;
    }

    /* Section names are reserved: hand back a virtual proxy that resolves
     * further indexing in a single section, before falling through to the
     * normal local→upvalue→global auto-lookup. Mirrors path-watch
     * canonicalization which also treats these as reserved tokens. */
    int section_kind = -1;
    if (g_strcmp0(key, "Locals") == 0)
    {
        section_kind = WSLUA_SECTION_LOCALS;
    }
    else if (g_strcmp0(key, "Upvalues") == 0)
    {
        section_kind = WSLUA_SECTION_UPVALUES;
    }
    else if (g_strcmp0(key, "Globals") == 0)
    {
        section_kind = WSLUA_SECTION_GLOBALS;
    }
    if (section_kind >= 0)
    {
        wslua_debugger_push_section_proxy(L, paused_level, baseline_depth,
                                          section_kind);
        return 1;
    }

    g_mutex_lock(&debugger.mutex);
    const bool snapshot_active =
        debugger.runtime_error_pause_active &&
        debugger.runtime_error_frame_snapshots != NULL;
    bool found_in_snapshot = false;
    if (snapshot_active)
    {
        found_in_snapshot =
            wslua_debugger_push_runtime_error_snapshot_binding_locked(
                L, paused_level, key, 0, false);
    }
    g_mutex_unlock(&debugger.mutex);

    if (found_in_snapshot)
    {
        return 1;
    }

    if (snapshot_active)
    {
        if (wslua_debugger_get_global_or_env_field(L, paused_level, key))
        {
            return 1;
        }
    }

    /* Translate @a paused_level to the level visible from this metamethod:
     * the chunk and any callees the chunk has entered all sit on top of the
     * originally paused frames in the call stack. */
    const int32_t effective_level = wslua_debugger_effective_paused_level(
        L, paused_level, baseline_depth);

    if (wslua_debugger_lookup_path(L, key, effective_level,
                                   WSLUA_LOOKUP_FIRST_AUTO))
    {
        return 1;
    }

    lua_pushnil(L);
    return 1;
}

/**
 * @brief @c __newindex for the chunk environment; writes go to the global
 *        table, preserving the existing Eval-panel contract that a bare
 *        @c x @c = @c v assigns to @c _G.x.
 *
 * Locals cannot be reached from a foreign chunk (Lua only exposes them
 * through @c debug.setlocal), so writes to a bare identifier intentionally
 * fall through to globals; users who need to mutate a local should call
 * @c debug.setlocal explicitly.
 */
static int wslua_debugger_env_newindex(lua_State *L)
{
    /* arg 1 = env table, arg 2 = key, arg 3 = value */
    if (lua_type(L, 2) != LUA_TSTRING)
    {
        return 0;
    }
    const char *key = lua_tostring(L, 2);
    if (!key || !*key)
    {
        return 0;
    }
    lua_pushvalue(L, 3);
    lua_setglobal(L, key);
    return 0;
}

/**
 * @brief Compile @a expression, install a custom @c _ENV that exposes the
 *        paused frame's locals/upvalues/globals, run it under the eval
 *        timeout hook, and leave @a nresults values on the stack.
 *
 * On success, returns @c true with @a nresults values (@c LUA_MULTRET
 * supported) at the new top of the stack; the caller is responsible for
 * consuming them.
 *
 * On failure, the stack is left as it was on entry, @c *error_msg is set
 * to a g_strdup'd description, and @c false is returned.
 *
 * Used by both the Evaluate panel (@ref wslua_debugger_evaluate) and the
 * expression-watch APIs (@ref wslua_debugger_watch_expr_read_root and
 * friends) so the two share the same scoping rules and timeout protection.
 */
static bool wslua_debugger_run_expr_chunk(lua_State *L,
                                          const char *expression,
                                          int32_t stack_level, int nresults,
                                          char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }

    char *code_to_eval =
        wslua_debugger_expression_compilable_chunk(L, expression, error_msg);
    if (!code_to_eval)
    {
        return false;
    }

    /* The chunk name doubles as the source label Lua splices into runtime
     * errors (e.g. messages produced by @c assert / @c error). The leading
     * "=" tells Lua to use the name verbatim instead of wrapping it in
     * @c [string "<source-truncated>"]:N:, which would otherwise leak the
     * @c return (...) wrapping we add in
     * @ref wslua_debugger_expression_compilable_chunk back into the user's
     * error text. The same value is used for both the Watch and Evaluate
     * panels, since the message is shown in different places anyway. */
    if (luaL_loadbuffer(L, code_to_eval, strlen(code_to_eval), "=watch") !=
        LUA_OK)
    {
        const char *lua_err = lua_tostring(L, -1);
        if (error_msg)
        {
            *error_msg = g_strdup(lua_err ? lua_err : "Syntax error");
        }
        lua_pop(L, 1);
        g_free(code_to_eval);
        return false;
    }
    g_free(code_to_eval);

    /* Build the custom _ENV table with locals/upvalues/globals fallback.
     * Stack: ..., chunk_fn */
    lua_newtable(L); /* env table E */
    lua_newtable(L); /* metatable M */

    /* Capture the call-stack depth before running the chunk so the env
     * __index closure can translate @a stack_level to the level visible
     * from inside the chunk regardless of how deep the chunk recurses. */
    int32_t baseline_depth = 0;
    {
        lua_Debug ar;
        while (lua_getstack(L, baseline_depth, &ar))
            baseline_depth++;
    }

    lua_pushinteger(L, stack_level);
    lua_pushinteger(L, baseline_depth);
    lua_pushcclosure(L, wslua_debugger_env_index, 2);
    lua_setfield(L, -2, "__index");

    lua_pushcfunction(L, wslua_debugger_env_newindex);
    lua_setfield(L, -2, "__newindex");

    /* setmetatable(E, M); stack: ..., chunk_fn, E */
    lua_setmetatable(L, -2);

    /* Replace the chunk's _ENV (Lua 5.2+) / fenv (Lua 5.1) with E.
     * lua_setupvalue / lua_setfenv pop their argument regardless of
     * outcome, so on failure we just continue with the default env. */
#if LUA_VERSION_NUM >= 502
    lua_setupvalue(L, -2, 1);
#else
    lua_setfenv(L, -2);
#endif

    /* Install hooks to abort runaway code:
     * - LUA_MASKCOUNT: instruction-count cap.
     * - LUA_MASKCALL / LUA_MASKRET: track call depth to catch deep
     *   recursion that could overflow the C stack before the count fires.
     */
    eval_call_depth = 0;
    lua_sethook(L, wslua_eval_timeout_hook,
                LUA_MASKCOUNT | LUA_MASKCALL | LUA_MASKRET,
                WSLUA_EVAL_INSTRUCTION_LIMIT);

#if WSLUA_DBG_HAS_ALLOWHOOK_FLIP
    /* Lua's luaD_hook flipped allowhook to 0 before invoking the line hook
     * that owns the surrounding Qt event loop; without restoring it for the
     * duration of this pcall, our timeout hook is silently dropped and a
     * runaway expression (e.g. `while true do end`) hangs the GUI. See the
     * comment on wslua_dbg_lstate_prefix for the layout rationale. */
    const unsigned char saved_allowhook = wslua_dbg_get_allowhook(L);
    wslua_dbg_set_allowhook(L, 1);
#else
    /* Lua < 5.4: the allowhook offset isn't safely reachable from outside
     * lstate.h, so the count/call-depth hooks installed above are inert
     * during the paused-debugger context. Surface this once per process so
     * users hit by a runaway expression know why. */
    static bool warned_inactive_timeout = false;
    if (!warned_inactive_timeout)
    {
        warned_inactive_timeout = true;
        g_warning("Lua Debugger: expression-watch instruction-count and "
                  "call-depth caps are inactive on %s; a runaway watch or "
                  "Evaluate expression can freeze Wireshark. Build against "
                  "Lua 5.4 or newer to enable the caps.",
                  LUA_RELEASE);
    }
#endif

    const int call_result = lua_pcall(L, 0, nresults, 0);

#if WSLUA_DBG_HAS_ALLOWHOOK_FLIP
    wslua_dbg_set_allowhook(L, saved_allowhook);
#endif
    lua_sethook(L, NULL, 0, 0);

    if (call_result != LUA_OK)
    {
        const char *lua_err = lua_tostring(L, -1);
        if (error_msg)
        {
            *error_msg = g_strdup(lua_err ? lua_err : "Runtime error");
        }
        lua_pop(L, 1);
        return false;
    }
    return true;
}

/**
 * @brief Evaluate @a expr at stack level 0 of @a L and report its truthiness.
 *
 * Wraps @ref wslua_debugger_run_expr_chunk. The chunk is run with @c LUA_MULTRET
 * narrowed to a single result so we read exactly one value off the top.
 */
static bool
wslua_debugger_eval_bool_at_level0(lua_State *L, const char *expr,
                                   bool *out_truthy, char **error_msg)
{
    if (!wslua_debugger_run_expr_chunk(L, expr, /*stack_level=*/0,
                                       /*nresults=*/1, error_msg))
    {
        return false;
    }
    if (out_truthy)
    {
        *out_truthy = lua_toboolean(L, -1) != 0;
    }
    lua_pop(L, 1);
    return true;
}

/**
 * @brief Evaluate @a expr at stack level 0 of @a L and stringify the result.
 *
 * Uses @c luaL_tolstring so userdata / table metatables get a chance to
 * provide a friendly @c __tostring. Returns a freshly @c g_strdup'd buffer
 * on success; the caller must @c g_free it. On failure returns NULL and
 * writes a @c g_strdup'd description to @c *error_msg (if non-NULL).
 *
 * @c nil is rendered as the literal text @c "nil" (matching @c print()).
 */
static char *
wslua_debugger_eval_expr_to_string_at_level0(lua_State *L, const char *expr,
                                             char **error_msg)
{
    if (!wslua_debugger_run_expr_chunk(L, expr, /*stack_level=*/0,
                                       /*nresults=*/1, error_msg))
    {
        return NULL;
    }
    size_t len = 0;
    const char *s = luaL_tolstring(L, -1, &len); /* pushes the string */
    char *out = (s != NULL) ? g_strndup(s, len) : g_strdup("");
    lua_pop(L, 2); /* pop the tolstring result and the original value */
    return out;
}

/**
 * @brief Format a logpoint message template by substituting @c {expr}
 *        placeholders with values from @a L's current frame and the
 *        per-fire snapshot in @a ctx.
 *
 * Syntax:
 *   - @c {{ and @c }} produce literal @c { / @c } characters.
 *   - An unmatched @c { (no closing @c }) emits the rest of the template
 *     verbatim.
 *   - @c } not paired with @c {{...}} or @c }} is emitted verbatim.
 *
 * Reserved tags (resolved without invoking the Lua evaluator). Each one
 * shadows any same-named Lua local/upvalue/global; users who actually
 * want to log a Lua variable @c filename should write
 * @c {tostring(filename)} (or any other expression):
 *
 *   Origin
 *     - @c {filename}  — @c ctx->file_path verbatim.
 *     - @c {basename}  — last path component of @c ctx->file_path
 *                        (e.g. @c "printer.lua"). Empty when
 *                        @c file_path is NULL or empty.
 *     - @c {line}      — @c ctx->line as a decimal integer.
 *     - @c {function}  — current function's @c debug.getinfo "n" name,
 *                        or @c "?" if anonymous / tail / main chunk.
 *     - @c {what}      — current frame's @c what field
 *                        (@c "Lua" / @c "C" / @c "main" / @c "tail").
 *
 *   Counters / scope
 *     - @c {hits}      — this breakpoint's hit counter after the fire.
 *     - @c {depth}     — Lua-frame stack depth at the fire site.
 *     - @c {thread}    — @c "main" for the main thread, otherwise
 *                        @c "coro@<ptr>" with the coroutine's stable
 *                        in-process pointer.
 *
 *   Time
 *     - @c {timestamp} — local wall-clock @c HH:MM:SS.mmm at fire time.
 *     - @c {datetime}  — local @c YYYY-MM-DD HH:MM:SS.mmm at fire time.
 *     - @c {epoch}     — Unix time, seconds with millisecond fraction.
 *     - @c {epoch_ms}  — Unix time as integer milliseconds.
 *     - @c {elapsed}   — milliseconds since the debugger was last
 *                        attached (0 if not measurable).
 *     - @c {delta}     — milliseconds since this breakpoint last fired
 *                        (0 on the first fire).
 *
 * Anything else inside @c {} is evaluated as a Lua expression at stack
 * level 0; the @c luaL_tolstring representation of the result is
 * spliced in. Per-placeholder evaluation errors substitute
 * @c "<error: msg>" so a bad expression in the middle of a long
 * template doesn't lose the surrounding text.
 *
 * @return Newly allocated string; caller must @c g_free.
 */
static char *
wslua_debugger_format_log_message(lua_State *L, const char *fmt,
                                  const wslua_logpoint_context_t *ctx)
{
    GString *out = g_string_new(NULL);
    if (!fmt || !ctx)
    {
        return g_string_free(out, FALSE);
    }
    /* Lazy-init wall-clock snapshot: a single GDateTime serves both
     * @c {timestamp} and @c {datetime} for this fire, and we never
     * allocate one when the template uses neither. */
    GDateTime *now_local = NULL;
    const char *p = fmt;
    while (*p)
    {
        if (p[0] == '{' && p[1] == '{')
        {
            g_string_append_c(out, '{');
            p += 2;
            continue;
        }
        if (p[0] == '}' && p[1] == '}')
        {
            g_string_append_c(out, '}');
            p += 2;
            continue;
        }
        if (*p == '{')
        {
            const char *start = p + 1;
            const char *end = strchr(start, '}');
            if (!end)
            {
                /* Unterminated placeholder: emit the rest verbatim so the
                 * user sees what they typed. */
                g_string_append(out, p);
                break;
            }
            char *expr = g_strndup(start, (gsize)(end - start));
            g_strstrip(expr);
            if (*expr)
            {
                if (g_strcmp0(expr, "filename") == 0)
                {
                    g_string_append(out,
                                    ctx->file_path ? ctx->file_path : "");
                }
                else if (g_strcmp0(expr, "basename") == 0)
                {
                    /* Last path component of {filename} — e.g.
                     * "printer.lua". GLib returns a freshly allocated
                     * string we own. Empty file_path collapses to the
                     * empty string. */
                    if (ctx->file_path && ctx->file_path[0])
                    {
                        char *base = g_path_get_basename(ctx->file_path);
                        g_string_append(out, base ? base : "");
                        g_free(base);
                    }
                }
                else if (g_strcmp0(expr, "line") == 0)
                {
                    /* Match the Lua-side line counting (1-based). The
                     * value is debugger-side context, so we never run
                     * the Lua evaluator for this tag — that keeps
                     * {line} reliable even if the user has shadowed
                     * the global with a local of the same name. */
                    g_string_append_printf(out, "%" PRId64, ctx->line);
                }
                else if (g_strcmp0(expr, "function") == 0)
                {
                    /* debug.getinfo's `name` is NULL for anonymous /
                     * tail / main chunks. "?" matches the convention
                     * Lua's own traceback formatter uses. */
                    g_string_append(out,
                                    (ctx->fn_name && ctx->fn_name[0])
                                        ? ctx->fn_name
                                        : "?");
                }
                else if (g_strcmp0(expr, "what") == 0)
                {
                    g_string_append(out,
                                    (ctx->fn_what && ctx->fn_what[0])
                                        ? ctx->fn_what
                                        : "");
                }
                else if (g_strcmp0(expr, "hits") == 0)
                {
                    g_string_append_printf(out, "%" PRId64, ctx->hit_count);
                }
                else if (g_strcmp0(expr, "depth") == 0)
                {
                    g_string_append_printf(out, "%d", ctx->depth);
                }
                else if (g_strcmp0(expr, "thread") == 0)
                {
                    if (ctx->is_main_thread)
                    {
                        g_string_append(out, "main");
                    }
                    else
                    {
                        g_string_append_printf(out, "coro@%p",
                                                ctx->thread_ptr);
                    }
                }
                else if (g_strcmp0(expr, "timestamp") == 0)
                {
                    if (!now_local)
                        now_local = g_date_time_new_now_local();
                    if (now_local)
                    {
                        char *base =
                            g_date_time_format(now_local, "%H:%M:%S");
                        g_string_append_printf(
                            out, "%s.%03d", base ? base : "",
                            (int)(g_date_time_get_microsecond(now_local) /
                                  1000));
                        g_free(base);
                    }
                }
                else if (g_strcmp0(expr, "datetime") == 0)
                {
                    if (!now_local)
                        now_local = g_date_time_new_now_local();
                    if (now_local)
                    {
                        char *base = g_date_time_format(
                            now_local, "%Y-%m-%d %H:%M:%S");
                        g_string_append_printf(
                            out, "%s.%03d", base ? base : "",
                            (int)(g_date_time_get_microsecond(now_local) /
                                  1000));
                        g_free(base);
                    }
                }
                else if (g_strcmp0(expr, "epoch") == 0)
                {
                    /* g_get_real_time() is microseconds since the Unix
                     * epoch (UTC). Format as seconds with a 3-digit
                     * fractional component so it's easy to feed into
                     * downstream tooling. */
                    const int64_t real_us = g_get_real_time();
                    g_string_append_printf(out, "%" PRId64 ".%03d",
                                            real_us / 1000000,
                                            (int)((real_us / 1000) % 1000));
                }
                else if (g_strcmp0(expr, "epoch_ms") == 0)
                {
                    g_string_append_printf(out, "%" PRId64,
                                            g_get_real_time() / 1000);
                }
                else if (g_strcmp0(expr, "elapsed") == 0)
                {
                    g_string_append_printf(out, "%" PRId64, ctx->elapsed_ms);
                }
                else if (g_strcmp0(expr, "delta") == 0)
                {
                    g_string_append_printf(out, "%" PRId64, ctx->delta_ms);
                }
                else
                {
                    char *err = NULL;
                    char *value =
                        wslua_debugger_eval_expr_to_string_at_level0(
                            L, expr, &err);
                    if (value)
                    {
                        g_string_append(out, value);
                        g_free(value);
                    }
                    else
                    {
                        g_string_append_printf(out, "<error: %s>",
                                                err ? err : "?");
                        g_free(err);
                    }
                }
            }
            g_free(expr);
            p = end + 1;
            continue;
        }
        g_string_append_c(out, *p);
        p++;
    }
    if (now_local)
    {
        g_date_time_unref(now_local);
    }
    return g_string_free(out, FALSE);
}

/**
 * @brief One-pass scan of a logpoint template, recording which
 *        expensive built-in tags it references.
 *
 * Mirrors @ref wslua_debugger_format_log_message's @c {expr} parsing
 * (with @c {{ and @c }} escapes, and the unmatched-@c { rule) so the
 * scanner sees exactly the same placeholder set the formatter does.
 * Whitespace inside @c {} is trimmed before the comparison so
 * @c { depth } and @c {depth} are equivalent — same as the formatter.
 *
 * Currently only the tags whose computation has measurable per-fire
 * cost are tracked: @c {depth} requires walking the Lua call stack
 * (@ref wslua_debugger_count_stack_frames), and @c {thread} requires
 * a @c lua_pushthread / @c lua_topointer / @c lua_pop sequence.
 * Cheap tags (line, hits, file_path …) are always populated.
 */
static void
wslua_debugger_scan_log_tags(const char *fmt,
                             wslua_logpoint_tags_t *out)
{
    out->needs_depth = false;
    out->needs_thread = false;
    if (!fmt)
        return;
    const char *p = fmt;
    while (*p)
    {
        if (p[0] == '{' && p[1] == '{')
        {
            p += 2;
            continue;
        }
        if (p[0] == '}' && p[1] == '}')
        {
            p += 2;
            continue;
        }
        if (*p == '{')
        {
            const char *start = p + 1;
            const char *end = strchr(start, '}');
            if (!end)
                break;
            const char *s = start;
            const char *e = end;
            while (s < e && g_ascii_isspace((guchar)*s))
                s++;
            while (e > s && g_ascii_isspace((guchar)*(e - 1)))
                e--;
            const size_t m = (size_t)(e - s);
            if (m == 5 && memcmp(s, "depth", 5) == 0)
                out->needs_depth = true;
            else if (m == 6 && memcmp(s, "thread", 6) == 0)
                out->needs_thread = true;
            p = end + 1;
            continue;
        }
        p++;
    }
}

/**
 * @brief Emit a logpoint message: ws_debug() + registered UI callback.
 *
 * Runs on the Lua thread that hit the line; the UI callback is expected
 * to marshal to its own thread if needed.
 *
 * The emitted message is the user's template verbatim — origin
 * (file / line) is intentionally not prefixed. Users who want to see
 * either of those in the log line can include them via the
 * @c {filename}, @c {basename}, or @c {line} tags.
 *
 * The mirror copy goes through @c ws_debug rather than @c ws_info so a
 * logpoint that fires on every packet does not pay the per-fire cost
 * of the logging subsystem (lock + sink dispatch + I/O) at the
 * default log level. The Evaluate panel still receives every line via
 * the registered UI callback. Raise @c LOG_LEVEL_DEBUG to mirror the
 * stream into Wireshark's log.
 */
static void
wslua_debugger_emit_log_message(const char *file_path, int64_t line,
                                const char *message)
{
    ws_debug("%s", message ? message : "");
    /* Atomic load: the dialog's destructor may clear the callback on
     * the GUI thread while the line hook reads it on the Lua thread.
     * @c g_atomic_pointer_get is a relaxed acquire — sufficient here
     * because we only need the freshly written NULL or a still-valid
     * function pointer; we don't synchronise any other state. */
    wslua_debugger_log_emit_callback_t cb =
        (wslua_debugger_log_emit_callback_t)
            g_atomic_pointer_get(&log_emit_callback);
    if (cb)
    {
        cb(file_path, line, message);
    }
}

/**
 * Scan one [A-Za-z_][A-Za-z0-9_]*; advance *pp past it on success.
 */
static bool
wslua_debugger_spec_scan_identifier(const char **pp)
{
    const char *p = *pp;
    if (!p || (!g_ascii_isalpha((guchar)*p) && *p != '_'))
        return false;
    p++;
    while (g_ascii_isalnum((guchar)*p) || *p == '_')
        p++;
    *pp = p;
    return true;
}

/**
 * @brief Consume one Lua string escape starting at **pp (which must point at
 * '\\'). If @a out is non-NULL, append the decoded bytes.
 *
 * Accepted escapes match the Lua 5.x reference manual:
 *   \\a \\b \\f \\n \\r \\t \\v   C-style control bytes
 *   \\\\ \\" \\' \\?              literal punctuation
 *   \\NNN                         decimal byte, 1..3 digits, value <= 255
 *   \\xHH                         hex byte, exactly 2 hex digits
 *   \\u{H..}                      Unicode codepoint (1..8 hex digits,
 *                                 <= 0x7FFFFFFF), encoded as UTF-8
 *   \\z                           skip following whitespace (no bytes emitted)
 *
 * Returns false on a malformed escape.
 */
static bool
wslua_debugger_spec_consume_escape(const char **pp, GString *out)
{
    const char *p = *pp;
    if (*p != '\\' || !p[1])
        return false;
    p++;
    char c = *p;
    switch (c)
    {
    case 'a':  if (out) g_string_append_c(out, '\a'); p++; break;
    case 'b':  if (out) g_string_append_c(out, '\b'); p++; break;
    case 'f':  if (out) g_string_append_c(out, '\f'); p++; break;
    case 'n':  if (out) g_string_append_c(out, '\n'); p++; break;
    case 'r':  if (out) g_string_append_c(out, '\r'); p++; break;
    case 't':  if (out) g_string_append_c(out, '\t'); p++; break;
    case 'v':  if (out) g_string_append_c(out, '\v'); p++; break;
    case '\\': if (out) g_string_append_c(out, '\\'); p++; break;
    case '"':  if (out) g_string_append_c(out, '"'); p++; break;
    case '\'': if (out) g_string_append_c(out, '\''); p++; break;
    case '?':  if (out) g_string_append_c(out, '?'); p++; break;
    case 'z':
        p++;
        while (*p && g_ascii_isspace((guchar)*p))
            p++;
        break;
    case 'x':
    {
        p++;
        if (!g_ascii_isxdigit((guchar)p[0]) ||
            !g_ascii_isxdigit((guchar)p[1]))
            return false;
        if (out)
        {
            unsigned v = ((unsigned)g_ascii_xdigit_value(p[0]) << 4) |
                         (unsigned)g_ascii_xdigit_value(p[1]);
            g_string_append_c(out, (char)v);
        }
        p += 2;
        break;
    }
    case 'u':
    {
        p++;
        if (*p != '{')
            return false;
        p++;
        guint64 v = 0;
        int hexcount = 0;
        while (g_ascii_isxdigit((guchar)*p) && hexcount < 8)
        {
            v = (v << 4) | (guint64)g_ascii_xdigit_value(*p);
            p++;
            hexcount++;
        }
        if (hexcount == 0 || *p != '}' || v > 0x7FFFFFFFu)
            return false;
        p++;
        if (out)
            g_string_append_unichar(out, (gunichar)v);
        break;
    }
    default:
        if (g_ascii_isdigit((guchar)c))
        {
            unsigned v = 0;
            int digits = 0;
            while (g_ascii_isdigit((guchar)*p) && digits < 3)
            {
                v = v * 10 + (unsigned)(*p - '0');
                p++;
                digits++;
            }
            if (v > 255)
                return false;
            if (out)
                g_string_append_c(out, (char)v);
        }
        else
        {
            return false;
        }
        break;
    }
    *pp = p;
    return true;
}

/**
 * @brief Scan a Lua short literal string (double- or single-quoted) starting
 * at **pp. If @a out is non-NULL, decode the contents into it (without the
 * surrounding quotes). Advances *pp past the closing quote on success.
 */
static bool
wslua_debugger_spec_scan_quoted(const char **pp, GString *out)
{
    const char *p = *pp;
    char quote = *p;
    if (quote != '"' && quote != '\'')
        return false;
    p++;
    while (*p && *p != quote)
    {
        if (*p == '\\')
        {
            if (!wslua_debugger_spec_consume_escape(&p, out))
                return false;
            continue;
        }
        if (*p == '\n' || *p == '\r')
            return false;
        if (out)
            g_string_append_c(out, *p);
        p++;
    }
    if (*p != quote)
        return false;
    p++;
    *pp = p;
    return true;
}

/**
 * @brief Scan an integer literal at **pp with optional leading '-' and
 * decimal or hex ("0x" / "0X") digits. Advances *pp past the literal.
 * If @a out_value is non-NULL, stores the parsed value.
 */
static bool
wslua_debugger_spec_scan_integer(const char **pp, int64_t *out_value)
{
    const char *p = *pp;
    bool neg = false;
    if (*p == '-')
    {
        neg = true;
        p++;
    }
    if (!g_ascii_isdigit((guchar)*p))
        return false;

    char *endp = NULL;
    guint64 mag;
    if (*p == '0' && (p[1] == 'x' || p[1] == 'X') &&
        g_ascii_isxdigit((guchar)p[2]))
    {
        mag = g_ascii_strtoull(p + 2, &endp, 16);
    }
    else
    {
        mag = g_ascii_strtoull(p, &endp, 10);
    }
    if (!endp || endp == p)
        return false;

    if (out_value)
        *out_value = neg ? -(int64_t)mag : (int64_t)mag;
    *pp = endp;
    return true;
}

/**
 * @brief Scan a bracket key starting at **pp (after the opening '[' has been
 * consumed). Advances *pp past the closing ']'. Whitespace around the key is
 * tolerated. If @a L is non-NULL, pushes the decoded Lua value on top of @a L.
 *
 * Accepts:
 *   integer                 decimal or hex, optional leading '-'
 *   true / false            Lua boolean literals
 *   "string" / 'string'     Lua short literal string with full escape set
 */
static bool
wslua_debugger_spec_scan_bracket_key(const char **pp, lua_State *L)
{
    const char *p = *pp;
    while (*p && g_ascii_isspace((guchar)*p))
        p++;
    if (!*p)
        return false;

    bool pushed = false;
    if (strncmp(p, "true", 4) == 0 &&
        !(g_ascii_isalnum((guchar)p[4]) || p[4] == '_'))
    {
        if (L)
        {
            lua_pushboolean(L, 1);
            pushed = true;
        }
        p += 4;
    }
    else if (strncmp(p, "false", 5) == 0 &&
             !(g_ascii_isalnum((guchar)p[5]) || p[5] == '_'))
    {
        if (L)
        {
            lua_pushboolean(L, 0);
            pushed = true;
        }
        p += 5;
    }
    else if (*p == '-' || g_ascii_isdigit((guchar)*p))
    {
        int64_t v;
        if (!wslua_debugger_spec_scan_integer(&p, &v))
            return false;
        if (L)
        {
            lua_pushinteger(L, (lua_Integer)v);
            pushed = true;
        }
    }
    else if (*p == '"' || *p == '\'')
    {
        GString *decoded = L ? g_string_new(NULL) : NULL;
        if (!wslua_debugger_spec_scan_quoted(&p, decoded))
        {
            if (decoded)
                g_string_free(decoded, true);
            return false;
        }
        if (L)
        {
            lua_pushlstring(L, decoded->str, decoded->len);
            pushed = true;
            g_string_free(decoded, true);
        }
    }
    else
    {
        return false;
    }

    while (*p && g_ascii_isspace((guchar)*p))
        p++;
    if (*p != ']')
    {
        if (pushed)
            lua_pop(L, 1);
        return false;
    }
    p++;
    *pp = p;
    return true;
}

/**
 * @brief Validate a path body.
 *
 * Grammar (after any section prefix has already been stripped):
 *   body        := ident ( '.' ident | '[' bracket-key ']' )*
 *   ident       := [A-Za-z_] [A-Za-z0-9_]*
 *   bracket-key := ws? ( integer | 'true' | 'false' | string ) ws?
 *   integer     := '-'? ( decimal-digits | '0x' hex-digits | '0X' hex-digits )
 *   string      := '"' ( char-except-"\\\\\" | escape )* '"'
 *                | '\'' ( char-except-'\\\\\' | escape )* '\''
 *   escape      — see wslua_debugger_spec_consume_escape()
 *
 * Same surface syntax as wslua_debugger_lookup_path after the first segment.
 */
static bool
wslua_debugger_spec_validate_path_body(const char *body)
{
    const char *p = body;

    if (!body || !*body)
        return false;
    if (!wslua_debugger_spec_scan_identifier(&p))
        return false;
    while (*p)
    {
        if (*p == '.')
        {
            p++;
            if (!wslua_debugger_spec_scan_identifier(&p))
                return false;
        }
        else if (*p == '[')
        {
            p++;
            if (!wslua_debugger_spec_scan_bracket_key(&p, NULL))
                return false;
        }
        else
        {
            return false;
        }
    }
    return true;
}

/**
 * Remove spaces and tabs adjacent to '.' outside of bracket [...] string
 * literals. Modifies @a s in place.
 */
static void
wslua_debugger_watch_collapse_ws_around_dots(char *s)
{
    if (!s || !*s)
        return;

    GString *o = g_string_sized_new(strlen(s) + 4);
    const char *p = s;
    bool in_bracket = false;
    bool in_dq = false;
    bool in_sq = false;

    while (*p)
    {
        unsigned char c = (unsigned char)*p;

        if (!in_bracket)
        {
            if (c == '[')
            {
                in_bracket = true;
                g_string_append_c(o, (char)c);
                p++;
                continue;
            }
            if (g_ascii_isspace(c))
            {
                const char *q = p;
                while (*q && g_ascii_isspace((unsigned char)*q))
                    q++;
                if (*q == '.' && o->len > 0 && o->str[o->len - 1] != '.')
                {
                    p = q;
                    continue;
                }
                if (o->len > 0 && o->str[o->len - 1] == '.' &&
                    (*q == '_' || g_ascii_isalpha((guchar)*q) || *q == '['))
                {
                    p = q;
                    continue;
                }
            }
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }

        /* in_bracket */
        if ((in_dq || in_sq) && c == '\\' && p[1])
        {
            /* Keep the backslash and the escaped byte together so that
             * \" / \' inside a bracket string literal do not toggle the
             * in-string state. */
            g_string_append_c(o, (char)c);
            g_string_append_c(o, p[1]);
            p += 2;
            continue;
        }
        if (!in_dq && !in_sq && c == ']')
        {
            in_bracket = false;
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }
        if (!in_sq && c == '"')
        {
            in_dq = !in_dq;
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }
        if (!in_dq && c == '\'')
        {
            in_sq = !in_sq;
            g_string_append_c(o, (char)c);
            p++;
            continue;
        }
        g_string_append_c(o, (char)c);
        p++;
    }

    /* o is built by copying/skipping bytes from s, so o->len <= strlen(s)
     * and writing o->len + 1 bytes back into s is safe.
     */
    memcpy(s, o->str, o->len + 1);
    g_string_free(o, true);
}

/**
 * Count of '.' and '[' in @a path — the same metric as the Qt Watch panel
 * (watchSubpathBoundaryCount) and @ref WSLUA_WATCH_MAX_PATH_SEGMENTS.
 */
static unsigned
wslua_debugger_watch_path_boundary_count(const char *path)
{
    unsigned n = 0;

    if (!path)
    {
        return 0;
    }
    for (const char *p = path; *p; p++)
    {
        if (*p == '.' || *p == '[')
        {
            n++;
        }
    }
    return n;
}

/**
 * @return Heap-allocated canonical variable-tree path, or NULL if @a spec is
 *         not a valid path-shaped watch. Applies trim, @c _G / @c _G. alias
 *         to @c Globals / @c Globals., whitespace collapse around dots, and
 *         path-body validation. Caller must @c g_free when non-NULL.
 */
static char *
wslua_debugger_watch_canonical_path(const char *spec)
{
    if (!spec || !*spec)
        return NULL;

    char *work = g_strdup(spec);
    g_strstrip(work);
    if (!*work)
    {
        g_free(work);
        return NULL;
    }

    if (g_strcmp0(work, "_G") == 0)
    {
        g_free(work);
        return g_strdup("Globals");
    }
    if (g_str_has_prefix(work, "_G."))
    {
        char *t = g_strdup_printf("Globals.%s", work + 3);
        g_free(work);
        work = t;
    }

    wslua_debugger_watch_collapse_ws_around_dots(work);

    if (g_str_has_prefix(work, "Locals."))
    {
        if (!wslua_debugger_spec_validate_path_body(work + 7))
            goto fail;
        goto canon_ok;
    }
    if (g_str_has_prefix(work, "Upvalues."))
    {
        if (!wslua_debugger_spec_validate_path_body(work + 9))
            goto fail;
        goto canon_ok;
    }
    if (g_str_has_prefix(work, "Globals."))
    {
        if (!wslua_debugger_spec_validate_path_body(work + 8))
            goto fail;
        goto canon_ok;
    }
    if (g_strcmp0(work, "Locals") == 0 || g_strcmp0(work, "Upvalues") == 0 ||
        g_strcmp0(work, "Globals") == 0)
    {
        goto canon_ok;
    }
    if (!wslua_debugger_spec_validate_path_body(work))
        goto fail;
    /* Bare path body: caller decides whether to prepend Locals. */
canon_ok:
    if (wslua_debugger_watch_path_boundary_count(work) >=
        WSLUA_WATCH_MAX_PATH_SEGMENTS)
    {
        goto fail;
    }
    return work;

fail:
    g_free(work);
    return NULL;
}

bool
wslua_debugger_watch_spec_uses_path_resolution(const char *spec)
{
    char *c = wslua_debugger_watch_canonical_path(spec);
    if (!c)
        return false;
    g_free(c);
    return true;
}

char *
wslua_debugger_watch_variable_path_for_spec(const char *spec)
{
    char *canon = wslua_debugger_watch_canonical_path(spec);
    if (!canon)
        return NULL;

    if (g_str_has_prefix(canon, "Locals.") ||
        g_str_has_prefix(canon, "Upvalues.") ||
        g_str_has_prefix(canon, "Globals.") ||
        g_strcmp0(canon, "Locals") == 0 ||
        g_strcmp0(canon, "Upvalues") == 0 ||
        g_strcmp0(canon, "Globals") == 0)
    {
        return canon;
    }

    char *out = g_strdup_printf("Locals.%s", canon);
    g_free(canon);
    return out;
}

/**
 * @return 0 if @a first_component matches a local, 1 upvalue, 2 global, -1 not found.
 *         Clears transient values from the Lua stack.
 *
 * Honors the runtime-error snapshot when active, so a bare watch like
 * @c "foo" canonicalises to @c "Locals.foo" / @c "Upvalues.foo" /
 * @c "Globals.foo" identically at a regular pause and at a
 * break-on-error pause.
 */
static int
wslua_debugger_first_segment_binding_kind(lua_State *L, int32_t stack_level,
                                          const char *first_component)
{
    if (!first_component || !*first_component)
    {
        return -1;
    }

    g_mutex_lock(&debugger.mutex);
    const bool snapshot_active =
        debugger.runtime_error_pause_active &&
        debugger.runtime_error_frame_snapshots != NULL &&
        stack_level >= 0 &&
        stack_level < debugger.runtime_error_stack_count;
    int snapshot_kind = -1;
    if (snapshot_active)
    {
        const wslua_runtime_error_frame_snapshot_t *frame =
            &debugger.runtime_error_frame_snapshots[stack_level];
        if (wslua_debugger_find_runtime_error_binding(
                frame->locals, frame->locals_count, first_component))
        {
            snapshot_kind = 0;
        }
        else if (wslua_debugger_find_runtime_error_binding(
                     frame->upvalues, frame->upvalues_count, first_component))
        {
            snapshot_kind = 1;
        }
    }
    g_mutex_unlock(&debugger.mutex);

    if (snapshot_kind >= 0)
    {
        return snapshot_kind;
    }

    if (snapshot_active)
    {
        /* Snapshot wins for Locals/Upvalues at break-on-error: the live frame is
         * gone and lua_getlocal would just return nothing. Fall through
         * to globals via the snapshot-aware get_global_or_env_field. */
        if (wslua_debugger_get_global_or_env_field(L, stack_level,
                                                   first_component))
        {
            lua_pop(L, 1);
            return 2;
        }
        return -1;
    }

    lua_Debug debug_info;
    if (!wslua_debugger_fill_activation(L, stack_level, &debug_info))
    {
        return -1;
    }

    int32_t local_index = 1;
    const char *name;
    while ((name = lua_getlocal(L, &debug_info, local_index++)))
    {
        if (g_strcmp0(name, first_component) == 0)
        {
            lua_pop(L, 1);
            return 0;
        }
        lua_pop(L, 1);
    }

    if (wslua_debugger_push_function_for_ar(L, &debug_info))
    {
        local_index = 1;
        while ((name = lua_getupvalue(L, -1, local_index++)))
        {
            if (g_strcmp0(name, first_component) == 0)
            {
                lua_remove(L, -2); /* function */
                lua_pop(L, 1);     /* value */
                return 1;
            }
            lua_pop(L, 1);
        }
        lua_pop(L, 1); /* function */
    }

    if (wslua_debugger_get_global_or_env_field(L, stack_level,
                                               first_component))
    {
        lua_pop(L, 1);
        return 2;
    }
    return -1;
}

char *
wslua_debugger_watch_resolved_variable_path_for_spec(const char *spec)
{
    char *canon = wslua_debugger_watch_canonical_path(spec);
    if (!canon)
        return NULL;

    /* Already qualified or a section-only spec → done. */
    if (g_str_has_prefix(canon, "Locals.") ||
        g_str_has_prefix(canon, "Upvalues.") ||
        g_str_has_prefix(canon, "Globals.") ||
        g_strcmp0(canon, "Locals") == 0 ||
        g_strcmp0(canon, "Upvalues") == 0 ||
        g_strcmp0(canon, "Globals") == 0)
    {
        return canon;
    }

    /* Bare path body: if we have a paused frame, classify by first segment
     * binding, otherwise fall back to "Locals.<body>". */
    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;

    if (!paused || !L)
    {
        g_mutex_unlock(&debugger.mutex);
        char *out = g_strdup_printf("Locals.%s", canon);
        g_free(canon);
        return out;
    }

    const char *end_ptr = canon;
    while (*end_ptr && *end_ptr != '.' && *end_ptr != '[')
        end_ptr++;

    char *first_component = g_strndup(canon, (size_t)(end_ptr - canon));
    if (!first_component || !*first_component)
    {
        g_mutex_unlock(&debugger.mutex);
        g_free(first_component);
        return canon;
    }

    g_mutex_unlock(&debugger.mutex);
    /* wslua_debugger_first_segment_binding_kind is snapshot-aware, so a
     * single call covers both regular and break-on-error pauses. */
    int kind = wslua_debugger_first_segment_binding_kind(
        L, variable_stack_level, first_component);
    g_free(first_component);

    const char *section = "Locals";
    if (kind == 1)
        section = "Upvalues";
    else if (kind == 2)
        section = "Globals";
    /* kind < 0 falls back to Locals (matches variable_path_for_spec). */

    char *out = g_strdup_printf("%s.%s", section, canon);
    g_free(canon);
    return out;
}

bool wslua_debugger_watch_read_root(const char *spec,
                                    char **value_out, char **type_out,
                                    bool *can_expand_out, char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }
    if (type_out)
    {
        *type_out = NULL;
    }
    if (can_expand_out)
    {
        *can_expand_out = false;
    }
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!spec || !*spec)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty watch specification");
        }
        return false;
    }

    if (!wslua_debugger_watch_spec_uses_path_resolution(spec))
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Invalid watch path");
        }
        return false;
    }

    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);

    if (!paused || !L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return false;
    }

    char *varpath = wslua_debugger_watch_resolved_variable_path_for_spec(spec);
    if (!varpath)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Invalid watch path");
        }
        return false;
    }

    const int32_t watch_stack_level = variable_stack_level;

    /* Section-only specs ("Locals" / "Upvalues" / "Globals") have no root
     * value to look up: they are purely container rows whose children are
     * produced by wslua_debugger_get_variables(section). Report them as an
     * empty, expandable "section" entry so the Qt layer shows the expansion
     * indicator and lazy-fills children on demand. Same in regular and
     * break-on-error pause modes. */
    if (g_strcmp0(varpath, "Locals") == 0 ||
        g_strcmp0(varpath, "Upvalues") == 0 ||
        g_strcmp0(varpath, "Globals") == 0)
    {
        if (type_out)
        {
            *type_out = g_strdup("section");
        }
        if (value_out)
        {
            *value_out = g_strdup("");
        }
        if (can_expand_out)
        {
            *can_expand_out = true;
        }
        g_free(varpath);
        return true;
    }

    /* Strip Locals./Upvalues./Globals. prefix and pick first-segment
     * resolver. wslua_debugger_lookup_path is snapshot-aware (see
     * wslua_debugger_push_first_path_segment), so the same call resolves
     * both regular and break-on-error pause paths. */
    const char *lookup_path = varpath;
    wslua_lookup_first_kind_t lk_first = WSLUA_LOOKUP_FIRST_AUTO;
    if (g_str_has_prefix(varpath, "Locals."))
    {
        lookup_path = varpath + 7;
        lk_first = WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
    }
    else if (g_str_has_prefix(varpath, "Upvalues."))
    {
        lookup_path = varpath + 9;
        lk_first = WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
    }
    else if (g_str_has_prefix(varpath, "Globals."))
    {
        lookup_path = varpath + 8;
        lk_first = WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
    }

    if (!wslua_debugger_lookup_path(L, lookup_path, watch_stack_level,
                                    lk_first))
    {
        g_free(varpath);
        if (error_msg)
        {
            *error_msg = g_strdup("Path not found");
        }
        return false;
    }

    const bool globals_subtree = g_str_has_prefix(varpath, "Globals.") ||
                                 g_strcmp0(varpath, "Globals") == 0;
    g_free(varpath);

    if (type_out)
    {
        *type_out = wslua_debugger_format_value_type(L, -1);
    }
    if (value_out)
    {
        if (lua_type(L, -1) == LUA_TNIL)
        {
            *value_out = g_strdup("nil");
        }
        else
        {
            *value_out = wslua_debugger_describe_value(L, -1);
        }
    }
    if (can_expand_out)
    {
        /* Under Globals.*, namespace tables full of functions still expand so
         * class/proto tables stay navigable (same rule as get_variables). */
        if (globals_subtree && lua_istable(L, -1))
        {
            int64_t total = 0;
            wslua_debugger_basic_table_counts(L, -1, &total, NULL);
            *can_expand_out = total > 0;
        }
        else
        {
            *can_expand_out = wslua_debugger_value_can_expand(L, -1);
        }
    }
    lua_pop(L, 1);
    return true;
}

bool wslua_debugger_read_variable_value_full(const char *variable_path,
                                             char **value_out,
                                             char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!variable_path || !*variable_path)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty variable path");
        }
        return false;
    }

    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);

    if (!paused || !L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return false;
    }

    /* Mirror wslua_debugger_watch_read_root's first-segment resolver so
     * "Locals.x", "Upvalues.y" and "Globals.z" resolve from the intended
     * section even when a local shadows a global. wslua_debugger_lookup_path
     * is snapshot-aware (see wslua_debugger_push_first_path_segment) so this
     * call resolves both regular and break-on-error pauses identically. */
    const char *lookup_path = variable_path;
    wslua_lookup_first_kind_t lk_first = WSLUA_LOOKUP_FIRST_AUTO;
    if (g_str_has_prefix(variable_path, "Locals."))
    {
        lookup_path = variable_path + 7;
        lk_first = WSLUA_LOOKUP_FIRST_LOCAL_ONLY;
    }
    else if (g_str_has_prefix(variable_path, "Upvalues."))
    {
        lookup_path = variable_path + 9;
        lk_first = WSLUA_LOOKUP_FIRST_UPVALUE_ONLY;
    }
    else if (g_str_has_prefix(variable_path, "Globals."))
    {
        lookup_path = variable_path + 8;
        lk_first = WSLUA_LOOKUP_FIRST_GLOBAL_ONLY;
    }

    if (!wslua_debugger_lookup_path(L, lookup_path, variable_stack_level,
                                    lk_first))
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Path not found");
        }
        return false;
    }

    if (value_out)
    {
        if (lua_type(L, -1) == LUA_TNIL)
        {
            *value_out = g_strdup("nil");
        }
        else
        {
            *value_out = wslua_debugger_describe_value_ex(L, -1,
                                                          /*truncate=*/false);
        }
    }
    lua_pop(L, 1);
    return true;
}

/* Break-on-error APIs */

void wslua_debugger_set_error_break_enabled(bool enabled)
{
    g_mutex_lock(&debugger.mutex);
    debugger.error_break_enabled = enabled;
    g_mutex_unlock(&debugger.mutex);
}

bool wslua_debugger_get_error_break_enabled(void)
{
    g_mutex_lock(&debugger.mutex);
    bool enabled = debugger.error_break_enabled;
    g_mutex_unlock(&debugger.mutex);
    return enabled;
}

/**
 * @brief Consume one pending explicit break-on-error marker from the
 *        global error()/assert() wrappers.
 *
 * Used by the post-pcall path to avoid a duplicate pause for the same
 * underlying failure. Internal: external callers should use
 * @ref wslua_debugger_after_pcall_failure which folds this in.
 *
 * @return true if an explicit wrapper break was pending and has now
 *         been consumed; false otherwise.
 */
static bool wslua_debugger_consume_explicit_error_break(void)
{
    g_mutex_lock(&debugger.mutex);
    bool occurred = debugger.explicit_error_break_recent;
    debugger.explicit_error_break_recent = false;
    g_mutex_unlock(&debugger.mutex);
    return occurred;
}

void wslua_debugger_after_pcall_failure(lua_State *L)
{
    if (wslua_debugger_consume_explicit_error_break())
    {
        return;
    }
    wslua_debugger_on_runtime_error(L, lua_tostring(L, -1));
}

const char *wslua_debugger_consume_error_text(void)
{
    g_mutex_lock(&debugger.mutex);
    const char *text = NULL;
    if (debugger.error_break_occurred)
    {
        debugger.error_break_occurred = false;
        text = debugger.last_error_text;
    }
    g_mutex_unlock(&debugger.mutex);
    return text;
}

/**
 * @brief Evaluate a Lua expression in the context of the paused debugger.
 *
 * This function evaluates the given expression using the paused Lua state.
 * It supports the '=' prefix shorthand: "=expr" becomes "return expr".
 *
 * An instruction-count hook is installed for the duration of the call so
 * that infinite loops are caught instead of hanging Wireshark.
 *
 * WARNING: The expression runs in the live dissector Lua state.  Modifying
 * globals (e.g. _G.some_proto = nil) can corrupt ongoing analysis.
 *
 * @param expression The Lua expression to evaluate.
 * @param error_msg Output pointer for error message (caller frees).
 * @return Result string (caller frees), or NULL on error.
 */
char *wslua_debugger_evaluate(const char *expression, char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }

    if (!expression || !*expression)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty expression");
        }
        return NULL;
    }

    g_mutex_lock(&debugger.mutex);
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);
    if (!L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return NULL;
    }

    const int top_before = lua_gettop(L);

    /* Run with locals/upvalues/globals visible via the shared chunk runner;
     * LUA_MULTRET keeps the existing Eval-panel contract that
     * "return a, b" tabulates both values into the output. */
    if (!wslua_debugger_run_expr_chunk(L, expression, variable_stack_level,
                                       LUA_MULTRET, error_msg))
    {
        return NULL;
    }

    const int top_after = lua_gettop(L);
    const int num_results = top_after - top_before;

    if (num_results == 0)
    {
        return g_strdup(""); /* No return value */
    }

    GString *result = g_string_new(NULL);
    for (int i = 0; i < num_results; i++)
    {
        const int idx = top_before + 1 + i;
        if (i > 0)
        {
            g_string_append(result, "\t");
        }

        char *value_str = wslua_debugger_describe_value(L, idx);
        if (value_str)
        {
            g_string_append(result, value_str);
            g_free(value_str);
        }
        else
        {
            g_string_append(result, "nil");
        }
    }

    lua_pop(L, num_results);

    return g_string_free(result, FALSE);
}

/**
 * @brief Internal helper for the four public watch-expression entry points.
 *
 * Acquires @c paused_L / @c variable_stack_level under the mutex, runs
 * @a spec via @ref wslua_debugger_run_expr_chunk (one return value
 * requested), then walks @a subpath on the result. On success the resolved
 * value is left at the top of the stack and a non-NULL @c lua_State
 * pointer is returned; the caller must @c lua_pop(L, 1) once finished.
 *
 * On failure returns @c NULL with @c *error_msg populated and the stack
 * left as it was on entry.
 */
static lua_State *
wslua_debugger_watch_expr_resolve_value(const char *spec, const char *subpath,
                                        char **error_msg)
{
    if (error_msg)
    {
        *error_msg = NULL;
    }
    if (!spec || !*spec)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Empty watch expression");
        }
        return NULL;
    }

    g_mutex_lock(&debugger.mutex);
    const bool paused =
        debugger.state == WSLUA_DEBUGGER_PAUSED && debugger.paused_L != NULL;
    lua_State *L = debugger.paused_L;
    const int32_t variable_stack_level = debugger.variable_stack_level;
    g_mutex_unlock(&debugger.mutex);

    if (!paused || !L)
    {
        if (error_msg)
        {
            *error_msg = g_strdup("Debugger is not paused");
        }
        return NULL;
    }

    if (!wslua_debugger_run_expr_chunk(L, spec, variable_stack_level, 1,
                                       error_msg))
    {
        return NULL;
    }
    /* Stack: ..., result */

    if (subpath && *subpath)
    {
        if (!wslua_debugger_traverse_subpath_on_top(L, subpath))
        {
            if (error_msg)
            {
                *error_msg = g_strdup("Path not found");
            }
            return NULL;
        }
    }
    return L;
}

/**
 * @brief Evaluate @a spec, walk @a subpath on the result, and report
 *        the resolved descendant's Value/Type/expand bit.
 *
 * @a subpath uses the same syntax as the tail of a path watch
 * (e.g. @c "[1].name"). An empty / NULL @a subpath returns the same
 * data as @ref wslua_debugger_watch_expr_read_root. The expression is
 * re-evaluated on every call; the same instruction and call-depth
 * caps as @ref wslua_debugger_evaluate apply.
 *
 * Internal: external callers funnel through
 * @ref wslua_debugger_watch_expr_read_root or
 * @ref wslua_debugger_watch_expr_get_variables, which both delegate to
 * this helper.
 */
static bool wslua_debugger_watch_expr_read_subpath(const char *spec,
                                                   const char *subpath,
                                                   char **value_out,
                                                   char **type_out,
                                                   bool *can_expand_out,
                                                   char **error_msg);

bool wslua_debugger_watch_expr_read_root(const char *spec, char **value_out,
                                         char **type_out,
                                         bool *can_expand_out,
                                         char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }
    if (type_out)
    {
        *type_out = NULL;
    }
    if (can_expand_out)
    {
        *can_expand_out = false;
    }
    return wslua_debugger_watch_expr_read_subpath(spec, NULL, value_out,
                                                  type_out, can_expand_out,
                                                  error_msg);
}

static bool wslua_debugger_watch_expr_read_subpath(const char *spec,
                                                   const char *subpath,
                                                   char **value_out,
                                                   char **type_out,
                                                   bool *can_expand_out,
                                                   char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }
    if (type_out)
    {
        *type_out = NULL;
    }
    if (can_expand_out)
    {
        *can_expand_out = false;
    }

    lua_State *L =
        wslua_debugger_watch_expr_resolve_value(spec, subpath, error_msg);
    if (!L)
    {
        return false;
    }

    if (type_out)
    {
        *type_out = wslua_debugger_format_value_type(L, -1);
    }
    if (value_out)
    {
        if (lua_type(L, -1) == LUA_TNIL)
        {
            *value_out = g_strdup("nil");
        }
        else
        {
            *value_out = wslua_debugger_describe_value(L, -1);
        }
    }
    if (can_expand_out)
    {
        *can_expand_out = wslua_debugger_value_can_expand(L, -1);
    }
    lua_pop(L, 1);
    return true;
}

bool wslua_debugger_watch_expr_get_variables(const char *spec,
                                             const char *subpath,
                                             wslua_variable_t **variables_out,
                                             int32_t *count_out,
                                             char **error_msg)
{
    if (variables_out)
    {
        *variables_out = NULL;
    }
    if (count_out)
    {
        *count_out = 0;
    }

    lua_State *L =
        wslua_debugger_watch_expr_resolve_value(spec, subpath, error_msg);
    if (!L)
    {
        return false;
    }

    /* The expression-watch tree mirrors the non-Globals branch of
     * wslua_debugger_get_variables: we never came in via Globals.* so
     * functions and the wslua __typeof marker are filtered out the same
     * way the Variables tree filters nested tables. */
    GArray *variables_array =
        g_array_new(false, false, sizeof(wslua_variable_t));
    wslua_debugger_append_children_of_value(L, variables_array,
                                            /*globals_subtree=*/false);
    /* append_children_of_value pops the value at the top of the stack on
     * exit, so no further lua_pop is needed here. */

    if (count_out)
    {
        *count_out = (int32_t)variables_array->len;
    }
    if (variables_out)
    {
        *variables_out =
            (wslua_variable_t *)g_array_free(variables_array, false);
    }
    else
    {
        /* Caller did not ask for the array; free the rows we built. */
        for (guint i = 0; i < variables_array->len; ++i)
        {
            wslua_variable_t *v =
                &g_array_index(variables_array, wslua_variable_t, i);
            g_free(v->name);
            g_free(v->value);
            g_free(v->type);
        }
        g_array_free(variables_array, true);
    }
    return true;
}

bool wslua_debugger_watch_expr_read_full(const char *spec, const char *subpath,
                                         char **value_out, char **error_msg)
{
    if (value_out)
    {
        *value_out = NULL;
    }

    lua_State *L =
        wslua_debugger_watch_expr_resolve_value(spec, subpath, error_msg);
    if (!L)
    {
        return false;
    }

    if (value_out)
    {
        if (lua_type(L, -1) == LUA_TNIL)
        {
            *value_out = g_strdup("nil");
        }
        else
        {
            *value_out =
                wslua_debugger_describe_value_ex(L, -1, /*truncate=*/false);
        }
    }
    lua_pop(L, 1);
    return true;
}

/**
 * @brief Helper callback for wslua_debugger_foreach_loaded_script.
 *
 * This callback receives plugin descriptions from
 * wslua_plugins_get_descriptions and forwards only the filename to the user's
 * callback.
 */
static void loaded_script_description_callback(const char *name _U_,
                                               const char *version _U_,
                                               const char *description _U_,
                                               const char *filename,
                                               void *user_data)
{
    /* user_data is a two-element array: [0] = user callback, [1] = user data */
    void **context = (void **)user_data;
    wslua_debugger_loaded_script_callback_t user_callback =
        (wslua_debugger_loaded_script_callback_t)context[0];
    void *user_context = context[1];

    if (user_callback && filename)
    {
        user_callback(filename, user_context);
    }
}

/**
 * @brief Iterate over all currently loaded Lua plugin scripts.
 *
 * This function calls the provided callback once for each Lua script
 * that has been loaded by the Wireshark Lua subsystem.
 *
 * @param callback Function to call for each loaded script.
 * @param user_data Context pointer passed to the callback.
 */
void wslua_debugger_foreach_loaded_script(
    wslua_debugger_loaded_script_callback_t callback, void *user_data)
{
    if (!callback)
    {
        return;
    }

    /* Pack callback and user_data into array for inner callback */
    void *context[2] = {(void *)callback, user_data};
    wslua_plugins_get_descriptions(loaded_script_description_callback, context);
}
