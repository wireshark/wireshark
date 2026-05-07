/* lua_debugger_settings.cpp
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

#include "lua_debugger_settings.h"
#include "ui_lua_debugger_dialog.h"

#include <QByteArray>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonParseError>
#include <QJsonValue>
#include <QList>
#include <QString>

#include "lua_debugger_breakpoints.h"
#include "lua_debugger_dialog.h"
#include "lua_debugger_utils.h"
#include "lua_debugger_watch.h"
#include "widgets/collapsible_section.h"

/* ===== settings_store ===== */

void LuaDebuggerSettingsStore::loadFromFile()
{
    const QString path = luaDebuggerSettingsFilePath();
    QFileInfo fi(path);
    if (!fi.exists() || !fi.isFile())
    {
        return;
    }

    QFile loadFile(path);
    if (!loadFile.open(QIODevice::ReadOnly))
    {
        return;
    }

    QByteArray loadData = loadFile.readAll();
    if (loadData.startsWith("\xef\xbb\xbf"))
    {
        loadData = loadData.mid(3);
    }
    loadData = loadData.trimmed();

    QJsonParseError parseError;
    const QJsonDocument document = QJsonDocument::fromJson(loadData, &parseError);
    if (parseError.error != QJsonParseError::NoError || !document.isObject())
    {
        return;
    }
    map_ = document.object().toVariantMap();
}

void LuaDebuggerSettingsStore::saveToFile() const
{
    const QString savePath = luaDebuggerSettingsFilePath();
    QFileInfo fileInfo(savePath);

    QFile saveFile(savePath);
    if (fileInfo.exists() && !fileInfo.isFile())
    {
        return;
    }

    if (saveFile.open(QIODevice::WriteOnly))
    {
        QJsonDocument document(QJsonObject::fromVariantMap(map_));
        QByteArray saveData = document.toJson(QJsonDocument::Indented);
        saveFile.write(saveData);
    }
}

QJsonArray LuaDebuggerSettingsStore::jsonArrayAt(const QVariantMap &map, const char *key)
{
    const QVariant v = map.value(QString::fromUtf8(key));
    if (!v.isValid())
    {
        return QJsonArray();
    }
    return QJsonValue::fromVariant(v).toArray();
}

/* ===== dialog_settings (LuaDebuggerDialog members) ===== */

void LuaDebuggerDialog::saveSettingsFile()
{
    /*
     * Always merge live watch rows and engine breakpoints before writing so
     * callers that only touch theme/splitters (or watches alone) do not persist
     * stale or empty breakpoint/watch entries.
     */
    watchController_.serializeTo(settingsStore_.map());
    breakpointsController_.serializeTo(settingsStore_.map());

    settingsStore_.saveToFile();
}

void LuaDebuggerDialog::applyDialogSettings()
{
    settingsStore_.loadFromFile();

    /*
     * Load JSON into the engine and watch tree. JSON is read only here (dialog
     * construction); it is written only from closeEvent() (see saveSettingsFile).
     * Apply breakpoints first so that list is never empty before rebuild.
     */
    breakpointsController_.restoreFrom(settingsStore_.map());

    watchController_.restoreFrom(settingsStore_.map());

    // Apply theme setting
    QString themeStr = settingsStore_.map().value(LuaDebuggerSettingsKeys::Theme, "auto").toString();
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeStr == "dark")
        theme = WSLUA_DEBUGGER_THEME_DARK;
    else if (themeStr == "light")
        theme = WSLUA_DEBUGGER_THEME_LIGHT;
    currentTheme_ = theme;

    if (themeComboBox)
    {
        int idx = themeComboBox->findData(theme);
        if (idx >= 0)
            themeComboBox->setCurrentIndex(idx);
    }

    QString mainSplitterHex = settingsStore_.map().value(LuaDebuggerSettingsKeys::MainSplitter).toString();
    QString leftSplitterHex = settingsStore_.map().value(LuaDebuggerSettingsKeys::LeftSplitter).toString();
    QString evalSplitterHex = settingsStore_.map().value(LuaDebuggerSettingsKeys::EvalSplitter).toString();

    bool splittersRestored = false;
    if (!mainSplitterHex.isEmpty() && ui->mainSplitter)
    {
        ui->mainSplitter->restoreState(QByteArray::fromHex(mainSplitterHex.toLatin1()));
        splittersRestored = true;
    }
    if (!leftSplitterHex.isEmpty() && ui->leftSplitter)
    {
        ui->leftSplitter->restoreState(QByteArray::fromHex(leftSplitterHex.toLatin1()));
        splittersRestored = true;
    }
    /* The Evaluate input/output splitter is independent of the outer panel
     * splitters; restore even if the others are missing so a user who has
     * only ever collapsed an Evaluate pane keeps that preference. */
    if (!evalSplitterHex.isEmpty() && evalSplitter_)
    {
        evalSplitter_->restoreState(QByteArray::fromHex(evalSplitterHex.toLatin1()));
    }

    if (!splittersRestored && ui->mainSplitter)
    {
        ui->mainSplitter->setStretchFactor(0, 1);
        ui->mainSplitter->setStretchFactor(1, 2);
        QList<int> sizes;
        sizes << 300 << 600;
        ui->mainSplitter->setSizes(sizes);
    }

    if (variablesSection)
        variablesSection->setExpanded(
            settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionVariables, true).toBool());
    if (stackSection)
        stackSection->setExpanded(settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionStack, true).toBool());
    if (breakpointsSection)
        breakpointsSection->setExpanded(
            settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionBreakpoints, true).toBool());
    if (filesSection)
        filesSection->setExpanded(settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionFiles, false).toBool());
    if (evalSection)
        evalSection->setExpanded(settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionEval, false).toBool());
    if (settingsSection)
        settingsSection->setExpanded(
            settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionSettings, false).toBool());
    if (watchSection)
        watchSection->setExpanded(settingsStore_.map().value(LuaDebuggerSettingsKeys::SectionWatch, true).toBool());
    /* The setExpanded() calls above each fire the section's toggled signal
     * which triggers updateLeftPanelStretch(). Call once more explicitly to
     * guarantee the splitter max-height and layout stretch factors reflect
     * the final restored expansion state regardless of signal-ordering. */
    updateLeftPanelStretch();

    /* Toolbar enable preference is persisted from the user's explicit
     * intent (storeDialogSettings() saves @c !user_explicitly_disabled).
     * closeEvent() turns the core off and forces user_explicitly_disabled
     * true until we run here, so the checkbox cannot be seeded from
     * wslua_debugger_is_enabled() alone. The visible checkbox is then
     * resynced to the actual core state below by
     * ensureDebuggerEnabledForActiveBreakpoints. */
    const bool debuggerEnabledPref =
        settingsStore_.map().value(QString::fromUtf8(LuaDebuggerSettingsKeys::DebuggerEnabled), true).toBool();
    if (enabledCheckBox)
    {
        const bool blocked = enabledCheckBox->blockSignals(true);
        enabledCheckBox->setChecked(debuggerEnabledPref);
        enabledCheckBox->blockSignals(blocked);
    }
    wslua_debugger_set_user_explicitly_disabled(!debuggerEnabledPref);

    /* Match Qt enable intent to C: persist active breakpoints, then
     * enable only if the user is not in "disabled" mode. */
    ensureDebuggerEnabledForActiveBreakpoints();
}

void LuaDebuggerDialog::storeDialogSettings()
{
    /*
     * Refresh the settings map from UI only (no disk I/O). JSON is written from
     * closeEvent() via saveSettingsFile().
     */
    // Store theme from combo box (or current C-side value)
    int32_t theme = WSLUA_DEBUGGER_THEME_AUTO;
    if (themeComboBox)
    {
        theme = themeComboBox->itemData(themeComboBox->currentIndex()).toInt();
    }
    if (theme == WSLUA_DEBUGGER_THEME_DARK)
        settingsStore_.map()[LuaDebuggerSettingsKeys::Theme] = "dark";
    else if (theme == WSLUA_DEBUGGER_THEME_LIGHT)
        settingsStore_.map()[LuaDebuggerSettingsKeys::Theme] = "light";
    else
        settingsStore_.map()[LuaDebuggerSettingsKeys::Theme] = "auto";

    // Store splitter states as hex strings
    if (ui->mainSplitter)
    {
        settingsStore_.map()[LuaDebuggerSettingsKeys::MainSplitter] =
            QString::fromLatin1(ui->mainSplitter->saveState().toHex());
    }
    if (ui->leftSplitter)
    {
        settingsStore_.map()[LuaDebuggerSettingsKeys::LeftSplitter] =
            QString::fromLatin1(ui->leftSplitter->saveState().toHex());
    }
    /* Evaluate input/output splitter: preserves whether either pane is
     * collapsed (size 0) so the user's chosen layout survives close/reopen. */
    if (evalSplitter_)
    {
        settingsStore_.map()[LuaDebuggerSettingsKeys::EvalSplitter] =
            QString::fromLatin1(evalSplitter_->saveState().toHex());
    }

    // Store section expanded states
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionVariables] =
        variablesSection ? variablesSection->isExpanded() : true;
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionStack] = stackSection ? stackSection->isExpanded() : true;
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionBreakpoints] =
        breakpointsSection ? breakpointsSection->isExpanded() : true;
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionFiles] = filesSection ? filesSection->isExpanded() : false;
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionEval] = evalSection ? evalSection->isExpanded() : false;
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionSettings] =
        settingsSection ? settingsSection->isExpanded() : false;
    settingsStore_.map()[LuaDebuggerSettingsKeys::SectionWatch] = watchSection ? watchSection->isExpanded() : true;

    /* Persist the user's intent (i.e. whether they have explicitly disabled
     * the debugger), not the currently-visible checkbox state. The toolbar
     * checkbox mirrors the live core "is enabled" flag, which the new
     * ensure-down semantics auto-clear whenever no breakpoint and no
     * Break-on-Error trigger is armed. Saving that auto-cleared state would
     * promote a transient "no triggers, debugger off" snapshot into a
     * persisted explicit-disable on reopen, which then blocks the
     * "adding a breakpoint auto-enables the debugger" affordance. */
    settingsStore_.map()[QString::fromUtf8(LuaDebuggerSettingsKeys::DebuggerEnabled)] =
        !wslua_debugger_get_user_explicitly_disabled();

    watchController_.serializeTo(settingsStore_.map());
}
