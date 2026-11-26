/* profile_inherit.c
 * Inheritance of configuration file entries from parent profiles
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>
#include <string.h>

#include <wsutil/file_util.h>
#include <wsutil/filesystem.h>
#include <wsutil/profile_inherit.h>

/* The profile dialog limits the nesting to PROFILE_MAX_DEPTH; this is only a guard. */
#define PROFILE_INHERIT_MAX_DEPTH 16

const char *
profile_inherit_mode_to_str(profile_inherit_e mode)
{
    switch (mode) {
    case PROFILE_INHERIT_PROFILE_AND_PARENT:
        return "profile_and_parent";
    case PROFILE_INHERIT_PARENT_ONLY:
        return "parent_only";
    case PROFILE_INHERIT_PROFILE_ONLY:
    default:
        return "profile_only";
    }
}

profile_inherit_e
profile_inherit_mode_from_str(const char *str)
{
    if (str == NULL)
        return PROFILE_INHERIT_PROFILE_ONLY;
    if (g_ascii_strcasecmp(str, "profile_and_parent") == 0)
        return PROFILE_INHERIT_PROFILE_AND_PARENT;
    if (g_ascii_strcasecmp(str, "parent_only") == 0)
        return PROFILE_INHERIT_PARENT_ONLY;
    return PROFILE_INHERIT_PROFILE_ONLY;
}

static bool
is_default_profile_name(const char *profile_name)
{
    return profile_name == NULL || *profile_name == '\0' ||
           strcmp(profile_name, DEFAULT_PROFILE) == 0;
}

static const char *
resolve_profile_name(const char *profile_name)
{
    return profile_name ? profile_name : get_profile_name();
}

bool
profile_can_inherit(const char *profile_name)
{
    return !is_default_profile_name(resolve_profile_name(profile_name));
}

char *
profile_parent_name(const char *profile_name)
{
    profile_name = resolve_profile_name(profile_name);
    if (is_default_profile_name(profile_name))
        return NULL;

    const char *sep = strrchr(profile_name, '/');
    if (sep == NULL || sep == profile_name)
        return g_strdup(DEFAULT_PROFILE);

    return g_strndup(profile_name, sep - profile_name);
}

static char *
profile_settings_path(const char *app_env_var_prefix, const char *profile_name, bool is_global)
{
    char *profile_dir = get_profile_dir(app_env_var_prefix, profile_name, is_global);
    char *path = g_build_filename(profile_dir, PROFILE_SETTINGS_FILENAME, NULL);
    g_free(profile_dir);
    return path;
}

/*
 * Parse a "key: value" line of a profile settings file. Returns false for
 * comments, empty lines and malformed lines.
 */
static bool
parse_settings_line(char *line, char **key, char **value)
{
    char *colon;

    g_strstrip(line);
    if (*line == '\0' || *line == '#')
        return false;

    colon = strchr(line, ':');
    if (colon == NULL)
        return false;

    *colon = '\0';
    *key = g_strstrip(line);
    *value = g_strstrip(colon + 1);
    return **key != '\0';
}

char *
profile_inherit_settings_lines(const char *filename, profile_inherit_e mode)
{
    return ws_strdup_printf("\n# Where the entries of %s come from: profile_only, profile_and_parent or parent_only.\n"
                            PROFILE_INHERIT_KEY_PREFIX "%s: %s\n",
                            filename, filename, profile_inherit_mode_to_str(mode));
}

GHashTable *
profile_inherit_read_settings(const char *path, char **err_info)
{
    GHashTable *settings = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    char *contents = NULL;
    GError *error = NULL;

    if (path == NULL)
        return settings;
    if (!g_file_get_contents(path, &contents, NULL, &error)) {
        if (g_error_matches(error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
            g_error_free(error);
            return settings;
        }
        if (err_info)
            *err_info = ws_strdup_printf("Can't read profile settings file\n\"%s\": %s.", path, error->message);
        g_error_free(error);
        g_hash_table_destroy(settings);
        return NULL;
    }

    char **lines = g_strsplit(contents, "\n", -1);
    for (char **line = lines; *line; line++) {
        char *key, *value;
        if (!parse_settings_line(*line, &key, &value))
            continue;
        if (!g_str_has_prefix(key, PROFILE_INHERIT_KEY_PREFIX))
            continue;
        const char *filename = key + strlen(PROFILE_INHERIT_KEY_PREFIX);
        if (*filename == '\0')
            continue;
        g_hash_table_replace(settings, g_strdup(filename), g_strdup(value));
    }
    g_strfreev(lines);
    g_free(contents);

    return settings;
}

/*
 * The settings of the profiles read so far, by the path of the settings
 * file. Every list asks for its mode when loaded, so a file is parsed again
 * only if it changed.
 */
typedef struct {
    GHashTable *settings;
    time_t mtime;
    int64_t size;
} cached_settings_t;

static GHashTable *settings_cache;

static void
free_cached_settings(void *data)
{
    cached_settings_t *cached = (cached_settings_t *)data;

    g_hash_table_destroy(cached->settings);
    g_free(cached);
}

static void
clear_settings_cache(void)
{
    if (settings_cache)
        g_hash_table_remove_all(settings_cache);
}

/* The settings of a profile, owned by the cache; NULL if there is no file or it can't be read */
static GHashTable *
cached_profile_settings(const char *path)
{
    ws_statb64 st;

    if (ws_stat64(path, &st) != 0)
        return NULL;

    if (settings_cache == NULL)
        settings_cache = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, free_cached_settings);

    cached_settings_t *cached = (cached_settings_t *)g_hash_table_lookup(settings_cache, path);
    if (cached && cached->mtime == st.st_mtime && cached->size == (int64_t)st.st_size)
        return cached->settings;

    GHashTable *settings = profile_inherit_read_settings(path, NULL);
    if (settings == NULL)
        return NULL;

    cached = g_new(cached_settings_t, 1);
    cached->settings = settings;
    cached->mtime = st.st_mtime;
    cached->size = (int64_t)st.st_size;
    g_hash_table_replace(settings_cache, g_strdup(path), cached);
    return settings;
}

/* The inherit mode of a file in a personal or global profile */
static profile_inherit_e
get_inherit(const char *app_env_var_prefix, const char *profile_name, bool is_global, const char *filename)
{
    if (filename == NULL || is_default_profile_name(profile_name))
        return PROFILE_INHERIT_PROFILE_ONLY;

    char *path = profile_settings_path(app_env_var_prefix, profile_name, is_global);
    GHashTable *settings = cached_profile_settings(path);
    profile_inherit_e mode = settings ? profile_inherit_mode_from_str((const char *)g_hash_table_lookup(settings, filename)) :
                                        PROFILE_INHERIT_PROFILE_ONLY;
    g_free(path);

    return mode;
}

profile_inherit_e
profile_get_inherit(const char *app_env_var_prefix, const char *profile_name, const char *filename)
{
    return get_inherit(app_env_var_prefix, resolve_profile_name(profile_name), false, filename);
}

bool
profile_set_inherit(const char *app_env_var_prefix, const char *profile_name, const char *filename, profile_inherit_e mode, char **err_info)
{
    /* The file is about to change, also within the same second */
    clear_settings_cache();

    profile_name = resolve_profile_name(profile_name);
    if (filename == NULL) {
        if (err_info)
            *err_info = g_strdup("No configuration file given.");
        return false;
    }
    if (is_default_profile_name(profile_name)) {
        if (err_info)
            *err_info = g_strdup("The Default profile cannot inherit.");
        return false;
    }

    char *path = profile_settings_path(app_env_var_prefix, profile_name, false);
    char *key = g_strconcat(PROFILE_INHERIT_KEY_PREFIX, filename, NULL);
    char *contents = NULL;
    GString *out = g_string_new(NULL);
    bool found = false;

    GError *read_error = NULL;
    if (!g_file_get_contents(path, &contents, NULL, &read_error) &&
        !g_error_matches(read_error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
        /* Don't replace a file that could not be read, losing its settings */
        if (err_info)
            *err_info = ws_strdup_printf("Can't read profile settings file\n\"%s\": %s.",
                                         path, read_error->message);
        g_error_free(read_error);
        g_string_free(out, TRUE);
        g_free(key);
        g_free(path);
        return false;
    }
    g_clear_error(&read_error);

    if (contents != NULL) {
        char **lines = g_strsplit(contents, "\n", -1);
        for (char **line = lines; *line; line++) {
            char *copy = g_strdup(*line);
            char *line_key, *line_value;
            bool is_key = parse_settings_line(copy, &line_key, &line_value) &&
                          strcmp(line_key, key) == 0;
            g_free(copy);
            if (is_key) {
                /* Replace the first occurrence, drop any later ones */
                if (!found && mode != PROFILE_INHERIT_PROFILE_ONLY) {
                    g_string_append_printf(out, "%s: %s\n", key, profile_inherit_mode_to_str(mode));
                } else {
                    /* Drop the comment written with the key as well, and its blank line */
                    char *comment = ws_strdup_printf("\n# Where the entries of %s come from: profile_only, profile_and_parent or parent_only.\n", filename);
                    if (out->len >= strlen(comment) &&
                        strcmp(out->str + out->len - strlen(comment), comment) == 0)
                        g_string_truncate(out, out->len - strlen(comment));
                    g_free(comment);
                }
                found = true;
                continue;
            }
            /* g_strsplit leaves an empty last element for a trailing newline */
            if (**line == '\0' && *(line + 1) == NULL)
                continue;
            g_string_append_printf(out, "%s\n", *line);
        }
        g_strfreev(lines);
        g_free(contents);
    } else if (mode == PROFILE_INHERIT_PROFILE_ONLY) {
        /* Nothing to remove */
        g_string_free(out, TRUE);
        g_free(key);
        g_free(path);
        return true;
    }

    if (!found && mode != PROFILE_INHERIT_PROFILE_ONLY) {
        char *lines = profile_inherit_settings_lines(filename, mode);
        g_string_append(out, lines);
        g_free(lines);
    }

    char *pf_dir_path = NULL;
    if (create_persconffile_profile(app_env_var_prefix, profile_name, &pf_dir_path) == -1) {
        if (err_info)
            *err_info = ws_strdup_printf("Can't create directory\n\"%s\"\nfor profile settings file: %s.",
                                         pf_dir_path, g_strerror(errno));
        g_free(pf_dir_path);
        g_string_free(out, TRUE);
        g_free(key);
        g_free(path);
        return false;
    }
    g_free(pf_dir_path);

    GError *error = NULL;
    bool ok = g_file_set_contents(path, out->str, (gssize)out->len, &error);
    if (!ok) {
        if (err_info)
            *err_info = ws_strdup_printf("Can't write profile settings file\n\"%s\": %s.",
                                         path, error ? error->message : "unknown error");
        g_clear_error(&error);
    }

    g_string_free(out, TRUE);
    g_free(key);
    g_free(path);
    return ok;
}

static void
free_layer(void *data)
{
    profile_inherit_layer_t *layer = (profile_inherit_layer_t *)data;
    g_free(layer->profile_name);
    g_free(layer->profile_dir);
    g_free(layer->source);
    g_free(layer);
}

/* Whether there is a global profile behind the personal profile with the same name */
static bool
has_global_layer(const char *app_env_var_prefix, const char *profile_name)
{
    return !is_default_profile_name(profile_name) &&
           profile_exists(app_env_var_prefix, profile_name, true);
}

static char *
layer_source(const char *profile_name, bool is_global)
{
    return is_global ? ws_strdup_printf("%s (global)", profile_name) : g_strdup(profile_name);
}

/* Add the layer of one profile per its mode; returns whether the layers continue behind it */
static bool
add_layer(const char *app_env_var_prefix, const char *profile_name, bool is_global, const char *filename, GPtrArray *layers)
{
    bool is_default = !is_global && is_default_profile_name(profile_name);
    profile_inherit_e mode = is_default ? PROFILE_INHERIT_PROFILE_ONLY :
                             get_inherit(app_env_var_prefix, profile_name, is_global, filename);

    if (mode != PROFILE_INHERIT_PARENT_ONLY) {
        profile_inherit_layer_t *layer = g_new0(profile_inherit_layer_t, 1);
        layer->profile_name = g_strdup(is_default ? DEFAULT_PROFILE : profile_name);
        layer->profile_dir = get_profile_dir(app_env_var_prefix, is_default ? NULL : profile_name, is_global);
        layer->source = layer_source(layer->profile_name, is_global);
        layer->is_global = is_global;
        layer->mode = mode;
        g_ptr_array_add(layers, layer);
    }

    return mode != PROFILE_INHERIT_PROFILE_ONLY;
}

/*
 * Add the layers behind a personal profile: the global profile with the
 * same name, then the personal parent and the global profile with its name,
 * and so on up to the Default profile, each per its own mode.
 */
static void
add_effective_layers(const char *app_env_var_prefix, const char *profile_name, const char *filename, GPtrArray *layers)
{
    char *name = g_strdup(profile_name);
    bool personal = false;  /* The entries of the profile itself are not a layer */

    for (int depth = 0; name != NULL && depth < PROFILE_INHERIT_MAX_DEPTH; depth++) {
        if (personal && !add_layer(app_env_var_prefix, name, false, filename, layers))
            break;
        personal = true;

        if (has_global_layer(app_env_var_prefix, name) &&
            !add_layer(app_env_var_prefix, name, true, filename, layers))
            break;

        char *parent = profile_parent_name(name);
        g_free(name);
        name = parent;
    }
    g_free(name);
}

GPtrArray *
profile_inherit_layers(const char *app_env_var_prefix, const char *profile_name, const char *filename, profile_inherit_e mode)
{
    GPtrArray *layers = g_ptr_array_new_with_free_func(free_layer);

    profile_name = resolve_profile_name(profile_name);
    if (filename == NULL || mode == PROFILE_INHERIT_PROFILE_ONLY || !profile_can_inherit(profile_name))
        return layers;

    add_effective_layers(app_env_var_prefix, profile_name, filename, layers);

    return layers;
}

char *
profile_inherit_parent_source(const char *app_env_var_prefix, const char *profile_name)
{
    profile_name = resolve_profile_name(profile_name);
    if (!profile_can_inherit(profile_name))
        return NULL;

    if (has_global_layer(app_env_var_prefix, profile_name))
        return layer_source(profile_name, true);

    return profile_parent_name(profile_name);
}

struct profile_inherit_seen {
    GHashTable *seen;    /* keys of the nearer profiles */
    GHashTable *pending; /* keys of the profile being read */
};

profile_inherit_seen_t *
profile_inherit_seen_new(void)
{
    profile_inherit_seen_t *seen = g_new0(profile_inherit_seen_t, 1);
    seen->seen = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    seen->pending = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    return seen;
}

void
profile_inherit_seen_free(profile_inherit_seen_t *seen)
{
    if (seen == NULL)
        return;
    g_hash_table_destroy(seen->seen);
    g_hash_table_destroy(seen->pending);
    g_free(seen);
}

/* The two keys are kept apart, e.g. a rule named like another rule's filter */
static char *
seen_key(char kind, const char *key)
{
    return g_strdup_printf("%c%s", kind, key);
}

bool
profile_inherit_seen_check(profile_inherit_seen_t *seen, const char *key1, const char *key2)
{
    char *k1 = seen_key('1', key1 ? key1 : "");
    char *k2 = key2 ? seen_key('2', key2) : NULL;
    bool found = g_hash_table_contains(seen->seen, k1) ||
                 (k2 && g_hash_table_contains(seen->seen, k2));

    g_hash_table_add(seen->pending, k1);
    if (k2)
        g_hash_table_add(seen->pending, k2);
    return found;
}

void
profile_inherit_seen_next(profile_inherit_seen_t *seen)
{
    GHashTableIter iter;
    void *key;

    g_hash_table_iter_init(&iter, seen->pending);
    while (g_hash_table_iter_next(&iter, &key, NULL)) {
        g_hash_table_iter_steal(&iter);
        g_hash_table_add(seen->seen, key);
    }
}

/* The path of a configuration file in a parent profile */
static char *
profile_inherit_layer_path(const profile_inherit_layer_t *layer, const char *filename)
{
    return g_build_filename(layer->profile_dir, filename, NULL);
}

bool
profile_inherit_read_layers(const char *app_env_var_prefix, const char *filename,
                            const char *legacy_filename, bool global_defaults,
                            profile_inherit_e mode, profile_inherit_seen_t *seen,
                            profile_inherit_read_layer_cb read, void *user_data, char **err)
{
    GPtrArray *layers = profile_inherit_layers(app_env_var_prefix, NULL, filename, mode);
    bool ok = true;

    for (unsigned i = 0; i < layers->len; i++) {
        const profile_inherit_layer_t *layer = (const profile_inherit_layer_t *)g_ptr_array_index(layers, i);
        const char *found_name = filename;
        char *path = profile_inherit_layer_path(layer, filename);

        /* An older name of the file is read if the file isn't there */
        if (legacy_filename && !file_exists(path)) {
            g_free(path);
            found_name = legacy_filename;
            path = profile_inherit_layer_path(layer, found_name);
        }

        if (!file_exists(path)) {
            g_free(path);
            path = NULL;
            /* As when it is the current profile, a profile using its own
             * entries only falls back to the global file */
            if (global_defaults && layer->mode == PROFILE_INHERIT_PROFILE_ONLY) {
                found_name = filename;
                path = get_datafile_path(filename, app_env_var_prefix);
                if (!file_exists(path)) {
                    g_free(path);
                    path = NULL;
                }
            }
        }

        if (path != NULL) {
            char *layer_err = NULL;
            if (!read(layer, path, found_name, seen, user_data, &layer_err)) {
                if (ok && err)
                    *err = layer_err ? layer_err : ws_strdup_printf("Can't read \"%s\".", path);
                else
                    g_free(layer_err);
                ok = false;
            } else {
                g_free(layer_err);
            }
            g_free(path);
        }

        /* This profile's entries hide the same entries from its parents */
        profile_inherit_seen_next(seen);
    }

    g_ptr_array_unref(layers);
    return ok;
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
