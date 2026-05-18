/* lua_debugger_files.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * Files panel: scan plugin/script directories, navigate the tree.
 */

#ifndef LUA_DEBUGGER_FILES_H
#define LUA_DEBUGGER_FILES_H

#include <QIcon>
#include <QObject>
#include <QPair>
#include <QString>
#include <QVector>

class LuaDebuggerDialog;
class QModelIndex;
class QPoint;
class QStandardItem;
class QStandardItemModel;
class QTreeView;

/**
 * @brief Files panel: plugin/script indexing, hierarchical entries, open /
 *        reveal / copy gestures, and tree chrome.
 */
class LuaDebuggerFilesController : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs the controller and binds it to its host dialog.
     * @param host The owning Lua debugger dialog.
     */
    explicit LuaDebuggerFilesController(LuaDebuggerDialog *host);

    /**
     * @brief Binds the controller to the tree view and model, and loads
     *        stock icons ready for the first ensureEntry call.
     * @param tree  The tree view that displays the file hierarchy.
     * @param model The standard item model backing the tree view.
     */
    void attach(QTreeView *tree, QStandardItemModel *model);

    /** @brief Configures decorations, scrollbar, and header sizing (after widgets exist). */
    void configureTreeChrome() const;

    /**
     * @brief Rescans all known script locations and repopulates the model
     *        with up-to-date entries.
     */
    void refreshAvailableScripts();

    /**
     * @brief Recursively walks @p dir_path and calls ensureEntry for every
     *        script file found.
     * @param dir_path Absolute path of the directory to scan.
     */
    void scanScriptDirectory(const QString &dir_path);

    /**
     * @brief Ensures a leaf row exists for @p file_path, creating
     *        intermediate folder rows as needed.
     * @param file_path Absolute path of the script file.
     * @return True if a new leaf row was created; false if it already existed.
     */
    bool ensureEntry(const QString &file_path);

    /** @brief Sorts column 0 after discrete inserts from callbacks. */
    void sortModel();

public slots:
    /**
     * @brief Opens the script associated with the double-clicked item in
     *        the debugger editor.
     * @param index Model index of the activated item.
     */
    void onItemDoubleClicked(const QModelIndex &index);

    /**
     * @brief Displays a context menu offering open, reveal, and copy
     *        actions for the item under the cursor.
     * @param pos Cursor position in tree-view viewport coordinates.
     */
    void showContextMenu(const QPoint &pos);

private:
    /**
     * @brief Searches the immediate children of @p parent for an item
     *        whose stored path matches @p path.
     * @param parent The item whose children are searched.
     * @param path   Absolute path to look up.
     * @return Matching child item, or nullptr if not found.
     */
    QStandardItem *findChildItemByPath(QStandardItem *parent, const QString &path) const;

    /**
     * @brief Decomposes @p absolute_path into display-name / full-path
     *        pairs for each path component and appends them to @p components.
     * @param absolute_path Absolute path to decompose.
     * @param components    Output vector receiving (display name, full path) pairs.
     * @return True on success; false if the path could not be decomposed.
     */
    bool appendPathComponents(const QString &absolute_path, QVector<QPair<QString, QString>> &components) const;

    /** @brief The owning Lua debugger dialog. */
    LuaDebuggerDialog *host_ = nullptr;

    /** @brief The tree view that displays the file hierarchy. */
    QTreeView *tree_ = nullptr;

    /** @brief The standard item model backing the tree view. */
    QStandardItemModel *model_ = nullptr;

    /**
     * @brief Stock icons used to decorate folder / leaf rows. Loaded
     *  in @ref attach so they're ready before the first ensureEntry.
     */
    QIcon folderIcon_;

    /** @brief Stock icon used to decorate script file leaf rows. */
    QIcon fileIcon_;
};

#endif
