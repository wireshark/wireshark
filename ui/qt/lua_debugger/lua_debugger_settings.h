/* lua_debugger_settings.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Persistent UI settings for the Lua debugger (lua_debugger.json).
 */

#ifndef LUA_DEBUGGER_SETTINGS_H
#define LUA_DEBUGGER_SETTINGS_H

#include <QJsonArray>
#include <QVariantMap>

/**
 * @brief In-memory Lua debugger UI settings backed by lua_debugger.json
 *        (global personal config, not per-profile).
 */
class LuaDebuggerSettingsStore
{
  public:
    /**
     * @brief Loads settings from lua_debugger.json into the internal map.
     */
    void loadFromFile();

    /**
     * @brief Persists the current settings map to lua_debugger.json.
     */
    void saveToFile() const;

    /**
     * @brief Returns a mutable reference to the underlying settings map.
     * @return Reference to the internal QVariantMap.
     */
    QVariantMap &map() { return map_; }

    /**
     * @brief Returns a read-only reference to the underlying settings map.
     * @return Const reference to the internal QVariantMap.
     */
    const QVariantMap &map() const { return map_; }

    /**
     * @brief Extracts a JSON array from a QVariantMap by key.
     *
     * QVariantMap values for JSON arrays are typically QVariantList of QVariantMap.
     *
     * @param map  The source variant map to read from.
     * @param key  The key whose value should be interpreted as a JSON array.
     * @return     A QJsonArray constructed from the value at @p key, or an empty array if absent.
     */
    static QJsonArray jsonArrayAt(const QVariantMap &map, const char *key);

  private:
    QVariantMap map_; /**< Internal storage for all settings key-value pairs. */
};

#endif
