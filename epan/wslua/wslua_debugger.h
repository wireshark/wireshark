/* wslua_debugger.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSLUA_DEBUGGER_H__
#define __WSLUA_DEBUGGER_H__

#include "ws_symbol_export.h"
#include <glib.h>
#include <stdbool.h>

typedef struct lua_State lua_State;

#ifdef __cplusplus
extern "C"
{
#endif

    /**
     * @brief Debugger state enum.
     */
    typedef enum
    {
        WSLUA_DEBUGGER_OFF,     /**< Debugger is off */
        WSLUA_DEBUGGER_RUNNING, /**< Debugger is running (enabled but not
                                   paused) */
        WSLUA_DEBUGGER_PAUSED   /**< Debugger is paused at a breakpoint */
    } wslua_debugger_state_t;

    /**
     * @brief Code view theme enum.
     */
    typedef enum
    {
        WSLUA_DEBUGGER_THEME_AUTO = 0, /**< Follow Wireshark theme (default) */
        WSLUA_DEBUGGER_THEME_DARK = 1, /**< Dark theme */
        WSLUA_DEBUGGER_THEME_LIGHT = 2 /**< Light theme */
    } wslua_debugger_theme_t;

    /**
     * @brief Hit-count comparison mode used by the line hook gate.
     *
     * Persisted as a string in the Qt JSON settings file (the lower-cased
     * suffix of each enum name: @c "from", @c "every", @c "once"). The
     * numeric values are an internal implementation detail; renumbering is
     * safe as long as the writer/reader in the Qt UI keep mapping the
     * string form correctly.
     */
    typedef enum
    {
        /** @c hits >= target (default; "pause from hit N onward"). */
        WSLUA_HIT_COUNT_MODE_FROM = 0,
        /** @c hits % target == 0 — pause on hits N, 2N, 3N, … */
        WSLUA_HIT_COUNT_MODE_EVERY = 1,
        /** @c hits == target, then deactivate the breakpoint (one-shot). */
        WSLUA_HIT_COUNT_MODE_ONCE = 2,
    } wslua_hit_count_mode_t;

    /**
     * @brief Breakpoint structure for in-memory storage.
     *
     * Breakpoints are persisted via the Qt UI's JSON settings file,
     * not via Wireshark's UAT system.
     *
     * @c condition / @c hit_count_target / @c log_message are optional:
     * NULL/empty/zero means "not set". When set, the line hook applies
     * the gates in order: hit-count, condition, then logpoint vs pause.
     * @c hit_count is a runtime counter and is not persisted.
     * @c last_fired_us is a runtime monotonic timestamp (microseconds,
     * @c g_get_monotonic_time scale) used to compute the
     * @c {delta} logpoint tag; @c 0 means the breakpoint has not fired
     * yet. Not persisted.
     */
    typedef struct _wslua_breakpoint_t
    {
        char *file_path;          /**< File path of the script */
        int64_t line;             /**< Line number */
        bool active;              /**< Whether the breakpoint is active */
        char *condition;          /**< Optional Lua expression; pause when truthy */
        int64_t hit_count_target; /**< Optional hit count threshold; 0 = none */
        int64_t hit_count;        /**< Runtime hit counter (not persisted) */
        wslua_hit_count_mode_t hit_count_mode; /**< How the gate compares
                                       *  @c hit_count against
                                       *  @c hit_count_target. Ignored when
                                       *  @c hit_count_target == 0. */
        bool condition_error;     /**< Last condition eval errored (sticky) */
        char *condition_error_msg;/**< Last condition error text; NULL = none.
                                   *   Owned by the breakpoint, freed on edit /
                                   *   reset / remove. Not persisted. */
        char *log_message;        /**< Optional logpoint template with {expr} */
        bool log_also_pause;      /**< Logpoint *and* pause: when @c log_message
                                   *   is set, true means the breakpoint formats
                                   *   and emits the message AND pauses. Default
                                   *   false (matches the historical
                                   *   "logpoints never pause" behavior). */
        int64_t last_fired_us;    /**< Monotonic ts of previous fire; 0 = never */
    } wslua_breakpoint_t;

    /**
     * @brief Initialize the debugger subsystem.
     * @param L The Lua state.
     */
    WS_DLL_PUBLIC void wslua_debugger_init(lua_State *L);

    /**
     * @brief Check if debugger is enabled.
     * @return true if enabled, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_is_enabled(void);

    /**
     * @brief Enable or disable the debugger.
     * @param enabled true to enable, false to disable.
     */
    WS_DLL_PUBLIC void wslua_debugger_set_enabled(bool enabled);

    /**
     * @brief Set whether the user asked to keep the debugger off.
     *
     * When @a user_wants_debugger_stay_off is true, also invalidates
     * @c was_enabled_before_reload so a pending
     * wslua_debugger_restore_after_reload() will not re-enable. When false,
     * the user has explicitly enabled the debugger in the UI again; auto-enable
     * and restore logic may then apply.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_user_explicitly_disabled(bool user_wants_debugger_stay_off);

    /**
     * @brief True if the user has explicitly asked to keep the debugger off.
     *
     * Tracks the @c user_explicitly_disabled intent flag (set via
     * @ref wslua_debugger_set_user_explicitly_disabled). The visible
     * "Debugger enabled" core flag can be off without this being true
     * (for example, no active breakpoints and Break on Error off — the
     * line hook is simply uninstalled). The UI persists this intent so
     * a close/reopen cycle does not turn an automatic-off into an
     * explicit-off.
     */
    WS_DLL_PUBLIC bool
    wslua_debugger_get_user_explicitly_disabled(void);

    /**
     * @brief True if the UI may auto-enable the debugger for breakpoint-like
     *        triggers.
     *
     * Returns true only when the user has not explicitly disabled the
     * debugger and at least one auto-break trigger exists (an active
     * breakpoint or Break on Error).
     *
     * Does not consider capture; the UI may combine this with live-capture
     * gating.
     */
    WS_DLL_PUBLIC bool
    wslua_debugger_may_auto_enable_for_breakpoints(void);

    /**
     * @brief Clear state saved for wslua_debugger_restore_after_reload() so
     *        a pending call will not re-enable. Call e.g. when the debugger
     *        dialog is closed and no delayed restore is desired.
     */
    WS_DLL_PUBLIC void wslua_debugger_renounce_restore_after_reload(void);

    /**
     * @brief Callback type for UI update when paused.
     * @param file_path The file path where execution is paused.
     * @param line The line number where execution is paused.
     */
    typedef void (*wslua_debugger_ui_update_cb_t)(const char *file_path,
                                                  int64_t line);

    /**
     * @brief Register the UI callback.
     * @param cb The callback function.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_register_ui_callback(wslua_debugger_ui_update_cb_t cb);

    /**
     * @brief Continue execution from a paused state.
     */
    WS_DLL_PUBLIC void wslua_debugger_continue(void);

    /**
     * @brief Step into the next executed line (enters called functions).
     *
     * Resumes execution and pauses at the very next line hook,
     * regardless of breakpoints.
     */
    WS_DLL_PUBLIC void wslua_debugger_step_in(void);

    /**
     * @brief Step over the current line (skips line hooks inside callees).
     *
     * Resumes execution and pauses at the next line hook that runs in the
     * current stack frame or an outer frame (after returns).
     */
    WS_DLL_PUBLIC void wslua_debugger_step_over(void);

    /**
     * @brief Step out of the current function (pause in the caller).
     *
     * If there is only one Lua stack frame, behaves like
     * wslua_debugger_continue().
     */
    WS_DLL_PUBLIC void wslua_debugger_step_out(void);

    /**
     * @brief Set which call stack frame supplies Locals and Upvalues in the
     *        variables view.
     *
     * @a level is the index passed to @c lua_getstack (0 = innermost Lua/C
     * activation). Globals are unaffected. If the debugger is not paused, the
     * value is still stored for the next pause.
     */
    WS_DLL_PUBLIC void wslua_debugger_set_variable_stack_level(int32_t level);

    /**
     * @brief Run execution until a specific line is reached.
     * @param file_path The file path.
     * @param line The line number.
     */
    WS_DLL_PUBLIC void wslua_debugger_run_to_line(const char *file_path,
                                                  int64_t line);

    /**
     * @brief Add a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     */
    WS_DLL_PUBLIC void wslua_debugger_add_breakpoint(const char *file_path,
                                                     int64_t line);

    /**
     * @brief Remove a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     */
    WS_DLL_PUBLIC void wslua_debugger_remove_breakpoint(const char *file_path,
                                                        int64_t line);

    /**
     * @brief Set the active state of a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     * @param active The new active state.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_active(const char *file_path, int64_t line,
                                         bool active);

    /**
     * @brief Clear all breakpoints.
     */
    WS_DLL_PUBLIC void wslua_debugger_clear_breakpoints(void);

    /**
     * @brief Set (or clear) the Lua condition expression on a breakpoint.
     *
     * The expression is evaluated each time control reaches the line, in the
     * breakpoint's frame, with the same custom @c _ENV used by Watch /
     * Evaluate (locals, upvalues, then globals). The breakpoint pauses only
     * when the expression is truthy. Runtime errors are silent and set the
     * @c condition_error flag (cleared by editing the condition or resetting
     * the breakpoint).
     *
     * Pass @c NULL or an empty string to clear an existing condition.
     * Setting or clearing the condition resets @c condition_error and the
     * runtime @c hit_count to zero.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_condition(const char *file_path, int64_t line,
                                            const char *condition);

    /**
     * @brief Set (or clear) the hit-count target on a breakpoint.
     *
     * Semantics depend on the breakpoint's @c hit_count_mode (default
     * @ref WSLUA_HIT_COUNT_MODE_FROM: pause / log when
     * @c hit_count >= @a target). @a target == 0 disables the gate
     * regardless of mode. The runtime @c hit_count is preserved across
     * target edits unless the new target is below the current count
     * (in which case it rolls back so the breakpoint can wait for the
     * "next N" hits instead of pausing every line forever).
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_hit_count_target(const char *file_path,
                                                   int64_t line,
                                                   int64_t target);

    /**
     * @brief Set the hit-count comparison mode on a breakpoint.
     *
     * Picks how the line hook compares @c hit_count to
     * @c hit_count_target. Ignored when @c hit_count_target == 0. The
     * @ref WSLUA_HIT_COUNT_MODE_ONCE variant also deactivates the
     * breakpoint after the matching fire (one-shot).
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_hit_count_mode(const char *file_path,
                                                  int64_t line,
                                                  wslua_hit_count_mode_t mode);

    /**
     * @brief Set (or clear) the logpoint message template on a breakpoint.
     *
     * A non-empty template makes the breakpoint a *logpoint*: when it would
     * pause, it instead formats the template (see @ref wslua_debugger_format_log_message)
     * and emits the result, then continues. The hit-count and condition gates
     * still apply before the logpoint fires.
     *
     * Pass @c NULL or empty to clear (the breakpoint reverts to a regular
     * pausing breakpoint).
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_log_message(const char *file_path,
                                              int64_t line,
                                              const char *message);

    /**
     * @brief Toggle the "log AND pause" behavior on a logpoint.
     *
     * When @a also_pause is @c true, a breakpoint that has a non-empty
     * @c log_message will format and emit the message *and* still pause
     * execution. When @c false (the default), logpoints emit and resume,
     * matching the historical convention. Has no effect on breakpoints
     * with no @c log_message set.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_log_also_pause(const char *file_path,
                                                  int64_t line,
                                                  bool also_pause);

    /**
     * @brief Reset the runtime @c hit_count for a single breakpoint to zero.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_reset_breakpoint_hit_count(const char *file_path,
                                              int64_t line);

    /**
     * @brief Reset the runtime @c hit_count for every breakpoint to zero.
     */
    WS_DLL_PUBLIC void wslua_debugger_reset_all_breakpoint_hit_counts(void);

    /**
     * @brief Validate that @a expression compiles as a Lua chunk.
     *
     * Uses @c luaL_loadstring (no execution) on the same wrapped form used
     * by the runtime expression evaluator, so syntactic acceptance here
     * matches what the line hook will accept at runtime. Used by the inline
     * editor to reject obvious typos before saving.
     *
     * @param expression  Expression to validate; may not be NULL.
     * @param err_msg     On error, set to a g_strdup'd description; caller
     *                    must g_free(). May be NULL.
     * @return true on syntactically-valid input.
     */
    WS_DLL_PUBLIC bool
    wslua_debugger_check_condition_syntax(const char *expression,
                                          char **err_msg);

    /**
     * @brief Stamp / clear a parse-time condition error on the breakpoint.
     *
     * Set @a err_msg to a non-empty string to mark the breakpoint as
     * having an unusable condition; pass @c NULL or @c "" to clear any
     * prior error. The string is copied; the caller retains ownership of
     * @a err_msg.
     *
     * Used by the inline editor: after calling
     * @ref wslua_debugger_set_breakpoint_condition with new text the UI
     * runs @ref wslua_debugger_check_condition_syntax and reports the
     * parse failure here, so the @c condition_error flag and the row
     * tooltip light up immediately, without waiting for the line hook to
     * try evaluating the (still broken) condition.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_set_breakpoint_condition_error(const char *file_path,
                                                   int64_t line,
                                                   const char *err_msg);

    /**
     * @brief Get the state of a breakpoint.
     * @param file_path The file path.
     * @param line The line number.
     * @return 1 if active, 0 if inactive, -1 if not found.
     */
    WS_DLL_PUBLIC int32_t
    wslua_debugger_get_breakpoint_state(const char *file_path, int64_t line);

    /**
     * @brief Return a newly allocated canonical path.
     * @param file_path The raw file path.
     * @return Canonical path (caller must g_free), or NULL on failure.
     */
    WS_DLL_PUBLIC char *wslua_debugger_canonical_path(const char *file_path);

    /**
     * @brief Variable structure for inspection.
     */
    typedef struct
    {
        char *name;  /**< Variable name */
        char *value; /**< Variable value as string */
        char *type;  /**< Variable type (e.g. "string", "number", "table") */
        bool can_expand; /**< true when the debugger can drill into children */
    } wslua_variable_t;

    /**
     * @brief Stack frame structure.
     */
    typedef struct
    {
        char *source;        /**< Source filename */
        int64_t line;        /**< Currently-executing line */
        int64_t linedefined; /**< First line of the function's definition; together
                                  with @c source forms a stable identity for this
                                  Lua activation (used by the Qt dialog to decide
                                  whether the previous-pause Locals/Upvalues
                                  baseline still refers to the same function). */
        char *name;          /**< Function name */
    } wslua_stack_frame_t;

    /**
     * @brief Get the current stack trace.
     * @param frame_count Output pointer for the number of frames.
     * @return Array of stack frames. Caller must free using
     * wslua_debugger_free_stack.
     */
    WS_DLL_PUBLIC wslua_stack_frame_t *
    wslua_debugger_get_stack(int32_t *frame_count);

    /**
     * @brief Free the stack trace array.
     * @param stack The stack array.
     * @param frame_count The number of frames.
     */
    WS_DLL_PUBLIC void wslua_debugger_free_stack(wslua_stack_frame_t *stack,
                                                 int32_t frame_count);

    /**
     * @brief Get variables for a specific path.
     * @param path The path to the variable (e.g. "a.b[1]"). NULL or empty for
     * root (Locals, Upvalues, Globals).
     * @param variable_count Output pointer for the number of variables.
     * @return Array of variables. Caller must free using
     * wslua_debugger_free_variables.
     */
    WS_DLL_PUBLIC wslua_variable_t *
    wslua_debugger_get_variables(const char *path, int32_t *variable_count);

    /**
     * @brief Free the variables array.
     * @param vars The variables array.
     * @param variable_count The number of variables.
     */
    WS_DLL_PUBLIC void wslua_debugger_free_variables(wslua_variable_t *vars,
                                                     int32_t variable_count);

    /**
     * @brief Get the total number of breakpoints.
     * @return The number of breakpoints.
     */
    WS_DLL_PUBLIC unsigned wslua_debugger_get_breakpoint_count(void);

    /**
     * @brief Get breakpoint details by index.
     * @param idx The index of the breakpoint.
     * @param file_path Output pointer for the file path.
     * @param line Output pointer for the line number.
     * @param active Output pointer for the active state.
     * @return true if found, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_get_breakpoint(unsigned idx,
                                                     const char **file_path,
                                                     int64_t *line,
                                                     bool *active);

    /**
     * @brief Get full breakpoint details by index.
     *
     * Superset of @ref wslua_debugger_get_breakpoint. The returned string
     * pointers are owned by the breakpoint storage and are valid until the
     * next mutation of the breakpoints list (add/remove/clear/set_*); copy
     * with @c g_strdup if you need to outlive that. Any @c out-pointer may
     * be NULL to skip that field.
     */
    WS_DLL_PUBLIC bool wslua_debugger_get_breakpoint_extended(
        unsigned idx, const char **file_path, int64_t *line, bool *active,
        const char **condition, int64_t *hit_count_target,
        int64_t *hit_count, bool *condition_error,
        const char **log_message,
        wslua_hit_count_mode_t *hit_count_mode,
        bool *log_also_pause);

    /**
     * @brief Return a copy of the last condition error message for the
     *        breakpoint at @a idx.
     *
     * Returns the most recent error string from a failed condition
     * evaluation (treated as false at runtime), or NULL when no error is
     * recorded. The returned pointer is newly allocated; the caller owns
     * it and must release it with @c g_free.
     *
     * Use with @c condition_error from
     * @ref wslua_debugger_get_breakpoint_extended: that boolean stays
     * sticky across line hits, this getter is the matching human-readable
     * detail for the row tooltip.
     *
     * @return Newly allocated message or @c NULL when @a idx is out of
     *         range or no error has been recorded.
     */
    WS_DLL_PUBLIC char *
    wslua_debugger_get_breakpoint_condition_error_message(unsigned idx);

    /**
     * @brief Get state and a "has extras" flag in one mutex acquisition.
     *
     * Combined accessor for the gutter painter, which calls this once per
     * visible line: doing two separate locked queries (state + extras)
     * would double the contention with the line hook on busy scripts.
     *
     * @c *has_extras is set to @c true when the breakpoint at @a canonical_path
     * / @a line carries at least one of: non-empty condition, hit-count
     * target > 0, or non-empty log message. Pass @c NULL to skip.
     *
     * @return -1 if no breakpoint exists, 0 if inactive, 1 if active.
     */
    WS_DLL_PUBLIC int32_t
    wslua_debugger_get_breakpoint_state_canonical(const char *canonical_path,
                                                  int64_t line,
                                                  bool *has_extras);

    /**
     * @brief Callback type for logpoint output.
     *
     * Invoked by the line hook when a logpoint fires (after the hit-count
     * and condition gates have been satisfied). @a file_path / @a line
     * identify the breakpoint; @a message is the fully-formatted text with
     * any @c {expr} placeholders already substituted. The callback runs on
     * the Lua thread (i.e. the same thread that hit the line); the
     * implementation should marshal to its UI thread if needed.
     */
    typedef void (*wslua_debugger_log_emit_callback_t)(const char *file_path,
                                                       int64_t line,
                                                       const char *message);

    /**
     * @brief Register (or unregister with NULL) a logpoint output sink.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_log_emit_callback(
        wslua_debugger_log_emit_callback_t callback);

    /**
     * @brief Callback invoked when the line hook bumps any breakpoint's
     *        @c hit_count without firing a pause or a logpoint.
     *
     * This is the silent-bump notification: the engine-side counter has
     * advanced, but no other UI-visible event (pause / logpoint emit)
     * has happened. The debugger UI uses it to refresh the
     * Breakpoints @em Hits column live so users see the running
     * counter even on below-threshold hits of a @c from / @c every /
     * @c once row that has no log message.
     *
     * The callback runs on the Lua thread; the implementation must
     * marshal to its UI thread. It receives no payload — the UI is
     * expected to re-read engine state on the GUI thread (and call
     * @ref wslua_debugger_clear_breakpoint_state_dirty before doing
     * so to allow concurrent bumps during the refresh to re-arm the
     * notification).
     *
     * Coalescing: the first bump after a clear dispatches the
     * callback; subsequent bumps stop at a single atomic CAS until
     * the UI calls @ref wslua_debugger_clear_breakpoint_state_dirty.
     * On a per-packet hot line this keeps the dispatch rate to one
     * per Qt event-loop tick regardless of the firing rate.
     */
    typedef void (*wslua_debugger_breakpoint_state_dirty_callback_t)(void);

    /**
     * @brief Register (or unregister with NULL) the silent-bump sink.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_breakpoint_state_dirty_callback(
        wslua_debugger_breakpoint_state_dirty_callback_t callback);

    /**
     * @brief Reset the dirty bit so the next silent bump re-arms the
     *        registered callback.
     *
     * Must be called by the drain handler @em before re-reading
     * engine state, so any concurrent @c bp->hit_count++ that lands
     * during the read still triggers a follow-up notification.
     */
    WS_DLL_PUBLIC void wslua_debugger_clear_breakpoint_state_dirty(void);

    /**
     * @brief Callback type for reload notification.
     *
     * This callback is invoked BEFORE Lua plugins are reloaded, allowing
     * the UI to reload script files from disk before they are executed.
     */
    typedef void (*wslua_debugger_reload_callback_t)(void);

    /**
     * @brief Register a callback to be notified before Lua plugins are
     * reloaded.
     *
     * The callback is invoked by wslua_reload_plugins() BEFORE any Lua scripts
     * are unloaded or reloaded. This allows the debugger UI to:
     * - Reload script files from disk (user may have edited them)
     * - Prepare for potential breakpoints during reload
     *
     * @param callback The callback function, or NULL to unregister.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_reload_callback(
        wslua_debugger_reload_callback_t callback);

    /**
     * @brief Notify the debugger that a reload is about to happen.
     *
     * Saves the debugger enabled state, disables the debugger, detaches
     * from the current Lua state, and calls the reload callback so the
     * UI can refresh script files from disk.
     *
     * If the debugger is paused, it is disabled (which continues
     * execution) and the reload callback is invoked so the UI can exit
     * its nested event loop and schedule a deferred reload.
     *
     * @return true if the caller should proceed with the reload;
     *         false if the reload was deferred (debugger was paused).
     */
    WS_DLL_PUBLIC bool wslua_debugger_notify_reload(void);

    /**
     * @brief Callback type for post-reload notification.
     *
     * This callback is invoked AFTER Lua plugins have been reloaded,
     * allowing the UI to refresh the file tree with newly loaded scripts.
     */
    typedef void (*wslua_debugger_post_reload_callback_t)(void);

    /**
     * @brief Register a callback to be notified after Lua plugins are
     * reloaded.
     *
     * The callback is invoked by wslua_reload_plugins() AFTER all Lua scripts
     * have been loaded. This allows the debugger UI to refresh the file tree
     * with the newly loaded scripts.
     *
     * @param callback The callback function, or NULL to unregister.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_post_reload_callback(
        wslua_debugger_post_reload_callback_t callback);

    /**
     * @brief Notify registered listeners that a reload has completed.
     *
     * Called internally by wslua_reload_plugins() after reloading.
     * Clears the reload_in_progress flag and invokes the registered
     * post-reload callback.  Does NOT re-enable the debugger.
     */
    WS_DLL_PUBLIC void wslua_debugger_notify_post_reload(void);

    /**
     * @brief Re-enable the debugger after a reload + cf_reload cycle.
     *
     * If the debugger was enabled before the reload, re-enable it.
     * Must be called AFTER cf_reload / redissectPackets completes.
     */
    WS_DLL_PUBLIC void wslua_debugger_restore_after_reload(void);

    /**
     * @brief Evaluate a Lua expression in the context of the paused debugger.
     *
     * This function evaluates the given expression using the paused Lua state.
     * It can only be called when the debugger is paused at a breakpoint.
     *
     * If the expression starts with '=', it is treated as a return statement
     * (e.g., "=x" becomes "return x"). This allows easy inspection of values.
     *
     * @param expression The Lua expression to evaluate.
     * @param error_msg Output pointer for error message if evaluation fails.
     *                  Caller must free with g_free() if non-NULL.
     * @return The result as a string (caller must free with g_free()),
     *         or NULL if evaluation failed (check error_msg).
     */
    WS_DLL_PUBLIC char *wslua_debugger_evaluate(const char *expression,
                                                char **error_msg);

    /**
     * @brief Check if the debugger is currently paused.
     * @return true if paused at a breakpoint, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_is_paused(void);

    /**
     * @brief Drop references to a Lua coroutine that is about to be reset/freed.
     *
     * The Lua dissection path runs each call in a temporary coroutine. If one
     * of those coroutines is being destroyed, any debugger pointer to it
     * (paused state or runtime-error snapshot state) must be invalidated first
     * to avoid later dereferences of freed Lua state.
     */
    WS_DLL_PUBLIC void wslua_debugger_forget_lua_thread(lua_State *L);

    /**
     * @brief Callback type for script-loaded notification.
     *
     * This callback is invoked each time a Lua script file is loaded
     * by the Wireshark Lua subsystem. It provides the full path to the
     * script file, allowing the debugger UI to update its file tree.
     *
     * @param file_path The full path to the loaded Lua script file.
     */
    typedef void (*wslua_debugger_script_loaded_callback_t)(
        const char *file_path);

    /**
     * @brief Register a callback to be notified when a Lua script is loaded.
     *
     * The callback is invoked each time a Lua plugin script is loaded,
     * allowing the debugger UI to add the file to its file tree immediately.
     *
     * @param callback The callback function, or NULL to unregister.
     */
    WS_DLL_PUBLIC void wslua_debugger_register_script_loaded_callback(
        wslua_debugger_script_loaded_callback_t callback);

    /**
     * @brief Notify the debugger that a Lua script has been loaded.
     *
     * Called internally by the Lua loader (init_wslua.c) when a script
     * is successfully loaded. This triggers the registered callback.
     *
     * @param file_path The full path to the loaded script file.
     */
    WS_DLL_PUBLIC void
    wslua_debugger_notify_script_loaded(const char *file_path);

    /**
     * @brief Callback type for iterating over loaded Lua scripts.
     *
     * @param file_path The full path to the loaded Lua script file.
     * @param user_data User-provided context pointer.
     */
    typedef void (*wslua_debugger_loaded_script_callback_t)(
        const char *file_path, void *user_data);

    /**
     * @brief Iterate over all currently loaded Lua plugin scripts.
     *
     * This function calls the provided callback once for each Lua script
     * that has been loaded by the Wireshark Lua subsystem. This includes
     * scripts from both the global and personal plugin directories.
     *
     * Use this to populate the debugger's file tree with actually loaded
     * scripts rather than scanning directories.
     *
     * @param callback Function to call for each loaded script.
     * @param user_data Context pointer passed to the callback.
     */
    WS_DLL_PUBLIC void wslua_debugger_foreach_loaded_script(
        wslua_debugger_loaded_script_callback_t callback, void *user_data);

    /**
     * @brief Enable or disable break-on-error mode.
     *
     * When enabled, any Lua error (from error(), assert(), or uncaught errors)
     * will pause the debugger. The error message and location are captured and
     * made available for inspection.
     *
     * @param enabled true to enable, false to disable.
     */
    WS_DLL_PUBLIC void wslua_debugger_set_error_break_enabled(bool enabled);

    /**
     * @brief Check if break-on-error is enabled.
     * @return true if enabled, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_get_error_break_enabled(void);

    /**
     * @brief Capture runtime-error location and stack while Lua is still in
     *        the message-handler phase.
     *
     * This records file/line/message and a stack snapshot, but does not pause.
     * Callers typically invoke this from an error handler and then call
     * @ref wslua_debugger_after_pcall_failure after @c lua_pcall returns to
     * trigger the deferred break-on-error pause path with this snapshot in hand.
     * @param L   The Lua state.
     * @param msg The error message (may be NULL).
     * @return true if debugger and break-on-error enabled, false otherwise.
     */
    WS_DLL_PUBLIC bool wslua_debugger_capture_runtime_error(lua_State *L,
                                                            const char *msg);

    /**
     * @brief Standard pcall-failure handling.
     *
     * Convenience wrapper that triggers the deferred runtime-error pause
     * path so break-on-error pauses fire from the post-pcall path.  Use this directly
     * after a non-OK @c lua_pcall return.
     *
     * @param L The Lua state whose top-of-stack holds the error message.
     */
    WS_DLL_PUBLIC void wslua_debugger_after_pcall_failure(lua_State *L);

    /**
     * @brief Consume the most recent break-on-error message, if any.
     *
     * Returns the captured error text (file/line prefix included as Lua
     * produced it) and clears the "an error pause occurred" flag, so the
     * next call returns @c NULL until another break-on-error fires.
     * Returns @c NULL when no pending error pause is present.
     *
     * The returned pointer is owned by the debugger and remains valid
     * until the next break-on-error capture.
     */
    WS_DLL_PUBLIC const char *wslua_debugger_consume_error_text(void);

    /*
     * Watch path APIs (below) take @c debugger.mutex when they touch the
     * paused Lua state. Call them from the same execution context as the Lua
     * debugger UI (typically the Qt GUI thread), matching
     * @ref wslua_debugger_get_variables and other variable accessors. Do not
     * interleave them with code that resumes the debugger or replaces
     * @c paused_L from another thread.
     */

    /** Maximum count of '.' and '[' in a canonical watch path (same metric as the Qt Watch panel; enforced in wslua_debugger_watch_canonical_path()). */
#define WSLUA_WATCH_MAX_PATH_SEGMENTS 32

    /**
     * @brief True when @a spec resolves like a Variables path: @c Locals./
     *        @c Upvalues./ @c Globals. prefix, a section root name, or a
     *        single identifier (meaning @c Locals.name).
     *
     * The parser tolerates leading/trailing whitespace, the @c _G / @c _G.
     * alias for @c Globals / @c Globals., whitespace around @c "." outside
     * bracket string literals, and @c \\" / @c \\\\ escapes inside @c "..."
     * / @c '...' bracket keys.
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_spec_uses_path_resolution(
        const char *spec);

    /**
     * @brief Full variable-tree path for path-style specs (e.g. @c Locals.foo
     *        for @c "foo"). Caller must @c g_free when non-NULL.
     * @return NULL for non-path specs (operators, calls, invalid paths).
     */
    WS_DLL_PUBLIC char *wslua_debugger_watch_variable_path_for_spec(
        const char *spec);

    /**
     * @brief Full variable-tree path for UI (e.g. tooltips) matching Variables resolution.
     *
     * For unqualified specs, the first path segment is resolved in the same order as
     * variable lookup (locals, then upvalues, then globals), so a global-only name
     * maps to @c Globals.name rather than @c Locals.name.
     *
     * When the debugger is not paused, falls back to
     * wslua_debugger_watch_variable_path_for_spec(). Caller must @c g_free when non-NULL.
     */
    WS_DLL_PUBLIC char *wslua_debugger_watch_resolved_variable_path_for_spec(
        const char *spec);

    /**
     * @brief Read root Value/Type/expand for one watch while paused.
     *
     * @a spec must validate as a path under
     * wslua_debugger_watch_spec_uses_path_resolution(); otherwise the call
     * fails with an "Invalid watch path" error.
     *
     * Children (if any) are fetched with wslua_debugger_get_variables() on
     * the path returned by
     * wslua_debugger_watch_resolved_variable_path_for_spec().
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_read_root(
        const char *spec, char **value_out, char **type_out,
        bool *can_expand_out, char **error_msg);

    /**
     * @brief Read the full, untruncated value of a resolved variable path
     *        while the debugger is paused.
     *
     * Unlike the preview returned by @ref wslua_debugger_watch_read_root
     * or @ref wslua_debugger_get_variables — which cap the stringified
     * value at an internal display limit — this variant returns the
     * complete @c luaL_tolstring() output so the UI can offer a true
     * "Copy value" action for both watch roots and nested sub-elements.
     *
     * @p variable_path uses the same surface syntax as the Variables tree
     * (e.g. @c Locals.foo, @c Globals.bar[1].baz); the leading
     * @c Locals./Upvalues./Globals. prefix selects the resolution
     * section exactly as in @ref wslua_debugger_watch_read_root.
     *
     * Tables are still summarised as @c "table[N]" since a table has no
     * meaningful full-text form; binary string values (e.g. @c Tvb
     * @c __tostring output) are preserved verbatim including embedded
     * NULs.
     *
     * @param variable_path Resolved variable path.
     * @param value_out Output pointer; caller frees with g_free().
     * @param error_msg Optional error description; caller frees with g_free().
     * @return true on success, false on error.
     */
    WS_DLL_PUBLIC bool wslua_debugger_read_variable_value_full(
        const char *variable_path, char **value_out, char **error_msg);

    /*
     * Watch expression APIs (below) evaluate an arbitrary Lua expression
     * against the paused state. They share the same instruction-count and
     * call-depth safety hooks as @ref wslua_debugger_evaluate, and run with
     * a custom @c _ENV that exposes the paused frame's locals, upvalues,
     * and globals — so a bare identifier in an expression resolves the
     * same way an unqualified path watch does.
     *
     * Use these for any spec that does not validate as a path under
     * @ref wslua_debugger_watch_spec_uses_path_resolution. Like the path
     * APIs above, they take @c debugger.mutex when they touch the paused
     * Lua state and must be called from the same execution context as the
     * Qt debugger UI (typically the GUI thread).
     */

    /**
     * @brief Evaluate @a spec as a Lua expression and report the root
     *        Value/Type/expand bit.
     *
     * Behaves like @ref wslua_debugger_watch_read_root but with no
     * "must be a variable path" restriction — any expression that
     * compiles and runs is acceptable. The result is the first (and only)
     * return value of the evaluated chunk.
     *
     * Outputs are caller-owned (@c g_free); on failure the function
     * returns @c false and writes a descriptive @a *error_msg.
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_expr_read_root(
        const char *spec, char **value_out, char **type_out,
        bool *can_expand_out, char **error_msg);

    /**
     * @brief Evaluate @a spec, walk @a subpath, and enumerate the
     *        descendant's children into @c wslua_variable_t records.
     *
     * Mirrors @ref wslua_debugger_get_variables on a path watch's
     * sub-table — children are produced from the same enumerator
     * (@c wslua_debugger_append_children_of_value), so the Qt layer can
     * reuse its row-building helpers.
     *
     * @return @c true with @c *variables_out / @c *count_out filled
     *         (caller frees with @c wslua_debugger_free_variables);
     *         @c false on evaluation / lookup failure.
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_expr_get_variables(
        const char *spec, const char *subpath,
        wslua_variable_t **variables_out, int32_t *count_out,
        char **error_msg);

    /**
     * @brief Read the full untruncated stringified value of an expression
     *        watch (root or sub-element) for the Copy Value action.
     *
     * @a subpath uses the same path-tail syntax as
     * @ref wslua_debugger_watch_expr_get_variables (e.g. @c "[1].name");
     * an empty / NULL subpath targets the root expression result. Tables
     * still summarise as @c "table[N]"; binary string values (e.g. @c Tvb
     * @c __tostring) are preserved verbatim including embedded NULs.
     */
    WS_DLL_PUBLIC bool wslua_debugger_watch_expr_read_full(
        const char *spec, const char *subpath, char **value_out,
        char **error_msg);

#ifdef __cplusplus
}
#endif

#endif /* __WSLUA_DEBUGGER_H__ */
