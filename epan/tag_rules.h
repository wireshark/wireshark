/* tag_rules.h
 * Definitions for tagging rules
 * Copyright 2026, Mark Stout <mark.stout@markstout.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

struct epan_dfilter;
struct epan_dissect;

#define TAGRULES_FILE_NAME         "tagrules"         /**< Per-profile tagrules file. */

/** @file
 *  Tagging rules — associate user-defined tags with packets via display filters.
 */

/**
 * @brief Controls how a tag link is activated in the packet list.
 */
typedef enum {
    TAG_LINK_CLICK_SINGLE = 0, /**< Single left-click opens the link. */
    TAG_LINK_CLICK_CTRL,       /**< Ctrl+Shift+left-click opens the link. */
    TAG_LINK_CLICK_NONE        /**< Right-click menu only; click/double-click disabled. */
} tag_link_click_mode_t;

/**
 * @brief Display preferences for the tagging subsystem.
 *
 * Stored in the profile's tagrules file as a header comment:
 * #prefs:sep=XX,emoji_size=N,click=N
 */
typedef struct _tag_prefs {
    char                  separator;    /**< Between tags when >1 match; '\0' = none. */
    int                   emoji_size;   /**< Emoji size as % of row height: 100, 90, 80, 70, 60, 50. 0 = 100%. Does not affect text tag labels or the separator character. */
    tag_link_click_mode_t link_click;   /**< How to activate a tag link. */
} tag_prefs_t;

/**
 * @brief Data for a single tagging rule.
 */
typedef struct _tag_rule {
    char     *rule_name;              /* Name — also the frame.tag value for filtering */
    char     *filter_text;            /* Display filter expression */
    char     *tag_content;            /* Visual content shown in COL_TAG column (emoji / text) */
    char     *tag_url;                /* Optional URL opened when cell is clicked */
    char     *comment;                /* Optional reference comment */
    bool      disabled;
    struct epan_dfilter *c_tagfilter; /* compiled dfilter, NULL if disabled or invalid */
} tag_rule_t;

/** @brief A tag rule was added (while importing or cloning).
 * (tag_rules.c calls this for every rule coming in)
 *
 * @param rule  the new tag rule
 * @param user_data from caller
 */
typedef void (*tag_rule_add_cb_func)(tag_rule_t *rule, void *user_data);

/**
 * @brief Initialize the tag rules subsystem (read from file).
 *
 * Loads from the active profile's tagrules file.
 */
WS_DLL_PUBLIC void tag_rules_init(void);

/**
 * @brief Reload the tag rules from disk.
 *
 * Frees the current list and re-runs tag_rules_init().
 */
WS_DLL_PUBLIC void tag_rules_reload(void);

/**
 * @brief Write tag rules to the active profile's tagrules file.
 *
 * @return true if the write succeeded, false otherwise.
 */
WS_DLL_PUBLIC bool tag_rules_write(void);

/**
 * @brief Create a new tag rule (g_new0-allocated).
 *
 * @param name        Rule name (also used as frame.tag value).
 * @param filter      Display filter expression.
 * @param tag_content Visual content for the COL_TAG column.
 * @param comment     Optional reference comment (may be NULL).
 * @return Newly allocated tag_rule_t; caller takes ownership.
 */
WS_DLL_PUBLIC tag_rule_t *tag_rule_new(const char *name, const char *filter,
                                       const char *tag_content,
                                       const char *tag_url,
                                       const char *comment);

/**
 * @brief Delete a single tag rule and free all its memory.
 *
 * @param rule the tag rule to free
 */
WS_DLL_PUBLIC void tag_rule_delete(tag_rule_t *rule);

/**
 * @brief Clone the currently active tag rule list.
 *
 * Iterates the list, clones each rule, and calls @p cb for each clone.
 *
 * @param cb        Callback invoked for each cloned rule.
 * @param user_data Opaque pointer forwarded to @p cb.
 */
WS_DLL_PUBLIC void tag_rules_clone(tag_rule_add_cb_func cb, void *user_data);

/**
 * @brief Apply a new tag rule list (called when the dialog OK is pressed).
 *
 * Replaces the current list with @p new_list and compiles all filters.
 *
 * @param new_list GSList of tag_rule_t* to install as the active list.
 */
WS_DLL_PUBLIC void tag_rules_apply(GSList *new_list);

/**
 * @brief Return the currently active tag rule list.
 *
 * @return Pointer to the internal GSList; do not modify or free.
 */
WS_DLL_PUBLIC const GSList *tag_rules_get_list(void);

/**
 * @brief Prime an epan_dissect_t with all compiled tag rule filters.
 *
 * Must be called before epan_dissect_run() so the dissector extracts
 * all fields referenced by any tag rule filter.
 *
 * @param edt The epan_dissect_t to prime.
 */
WS_DLL_PUBLIC void tag_rules_prime_edt(struct epan_dissect *edt);

/** Returns true if there is at least one tag rule (enabled or disabled). */
WS_DLL_PUBLIC bool tag_rules_used(void);

/**
 * @brief Get the current display preferences.
 */
WS_DLL_PUBLIC tag_prefs_t tag_rules_get_prefs(void);

/**
 * @brief Set the display preferences (does not write to disk).
 */
WS_DLL_PUBLIC void tag_rules_set_prefs(const tag_prefs_t *prefs);

/**
 * @brief Read tag rules from a file into a new GSList without touching the active list.
 *
 * @param path     Full path to a tagrules file.
 * @param err_msg  Set to error string on failure; caller g_frees. May be NULL.
 * @return Newly allocated GSList of tag_rule_t*, or NULL on error. Caller owns the list.
 */
WS_DLL_PUBLIC GSList *tag_rules_read_path(const char *path, char **err_msg);

/**
 * @brief Write a rule list to an arbitrary file path.
 *
 * Does not modify the active list.
 *
 * @param list     GSList of tag_rule_t* to write.
 * @param path     Full path to write.
 * @param prefs    Prefs to embed in the file header (may be NULL for defaults).
 * @param err_msg  Set to error string on failure; caller g_frees.
 * @return true on success.
 */
WS_DLL_PUBLIC bool tag_rules_write_path(GSList *list, const char *path,
                                        const tag_prefs_t *prefs,
                                        char **err_msg);


/**
 * @brief Write an arbitrary tag rule GSList to a file without touching the active list.
 *
 * @param list    GSList of tag_rule_t* to write (not freed by this function).
 * @param path    Path of the file to write.
 * @param err_msg Set to a newly allocated error string on failure; caller g_frees.
 * @return true on success, false on failure.
 */
WS_DLL_PUBLIC bool tag_rules_export_list(GSList *list, const char *path, char **err_msg);

/**
 * @brief Free a GSList of tag_rule_t* (e.g. one built by the model for export).
 *
 * @param list GSList of tag_rule_t* to free; each element is also freed.
 */
WS_DLL_PUBLIC void tag_rule_list_free(GSList *list);

#ifdef __cplusplus
}
#endif /* __cplusplus */

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
