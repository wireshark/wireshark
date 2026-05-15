/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ABOUT_DIALOG_H
#define ABOUT_DIALOG_H

#include "config.h"

#include <ui/qt/models/astringlist_list_model.h>

#include <QDialog>
#include <QLabel>
#include <QTabWidget>
#include <QAbstractItemModel>
#include <QModelIndex>
#include <QHash>
#include <QString>
#include <QSortFilterProxyModel>

namespace Ui {
class AboutDialog;
}

/**
 * @brief List model for the Authors tab of the About dialog.
 */
class AuthorListModel : public AStringListListModel
{
    Q_OBJECT

public:
    /**
     * @brief Construct an AuthorListModel.
     * @param parent The parent object.
     */
    explicit AuthorListModel(QObject *parent = Q_NULLPTR);
    /**
     * @brief Destructor.
     */
    virtual ~AuthorListModel();

protected:
    /** @brief Return the column header labels for the authors table. */
    virtual QStringList headerColumns() const;
};

/**
 * @brief List model for the Plugins tab of the About dialog.
 */
class PluginListModel : public AStringListListModel
{
    Q_OBJECT
public:
    /**
     * @brief Construct an PluginListModel.
     * @param parent The parent object.
     */
    explicit PluginListModel(QObject *parent = Q_NULLPTR);

    /**
     * @brief Return the list of distinct plugin type name strings.
     * @return An ordered list of unique type name strings.
     */
    QStringList typeNames() const;

protected:
    /** @brief Return the column header labels for the plugins table. */
    virtual QStringList headerColumns() const;

private:
    QStringList typeNames_; /**< Cached list of distinct plugin type names. */
};

/**
 * @brief List model for the Folders tab of the About dialog.
 */
class FolderListModel : public AStringListListModel
{
    Q_OBJECT
public:
    /**
     * @brief Construct an FolderListModel.
     * @param parent The parent object.
     */
    explicit FolderListModel(QObject *parent = Q_NULLPTR);

protected:
    /** @brief Return the column header labels for the folders table. */
    virtual QStringList headerColumns() const;
};

/**
 * @brief The About Wireshark dialog.
 */
class AboutDialog : public QDialog
{
    Q_OBJECT

public:
    /**
     * @brief Construct an AboutDialog.
     * @param parent The parent widget; nullptr for a top-level dialog.
     */
    explicit AboutDialog(QWidget *parent = 0);

    /**
     * @brief Destructor.
     */
    virtual ~AboutDialog();

protected:
    /**
     * @brief Handle application-level events such as palette or font changes.
     *
     * @param event The event to process.
     * @return true if the event was recognised and consumed; false to
     *         propagate it to the base class.
     */
    virtual bool event(QEvent *event);

    /**
     * @brief Populate dynamic content the first time the dialog is shown.
     * @param event The show event.
     */
    virtual void showEvent(QShowEvent *event);

    /**
     * @brief Return the VCS (Git) revision string embedded at build time.
     *
     * @return A static string of the form @c "v4.x.y-NNN-gHHHHHHHH", or
     *         an empty string if version information was not embedded.
     */
    const char *getVCSVersion();


    // UI element accessors used by subclasses and tests.

    /** @brief Return the logo QLabel widget. */
    QLabel *labelLogo() const;

    /** @brief Return the application title QLabel widget. */
    QLabel *labelTitle() const;

    /** @brief Return the main QTabWidget containing all About tabs. */
    QTabWidget *tabWidget() const;

    /** @brief Return the "Wireshark" summary tab widget. */
    QWidget *tabWireshark() const;


private:
    /**
     * @brief Rebuild the Wireshark version and build information text block.
     */
    void updateWiresharkText();

    Ui::AboutDialog *ui;     /**< Pointer to the UI elements for this dialog. */
    QString script_pattern;  /**< Glob pattern used to identify Lua plugin files in the folder list. */
    QString clipboardInfo;   /**< Cached text prepared for the "Copy to Clipboard" button. */


private slots:
    /**
     * @brief Open a URL or reveal a path when a table row is double-clicked.
     * @param idx The model index that was double-clicked.
     */
    void urlDoubleClicked(const QModelIndex &idx);

    /**
     * @brief Show a context menu for copy and file-reveal actions.
     * @param pos The right-click position in the table's viewport coordinates.
     */
    void handleCopyMenu(QPoint pos);

    /**
     * @brief Reveal the selected path in the system file manager.
     */
    void showInFolderActionTriggered();

    /**
     * @brief Copy the selected cell or row text to the clipboard.
     * @param row If true, copy all columns of the selected row as
     *            tab-separated text; if false, copy only the active cell.
     */
    void copyActionTriggered(bool row = false);

    /**
     * @brief Copy all columns of the selected row to the clipboard.
     */
    void copyRowActionTriggered();

    /**
     * @brief Open a plugin file's containing folder when its row is
     * double-clicked in the plugins table.
     *
     * @param index The model index of the double-clicked plugins table row.
     */
    void on_tblPlugins_doubleClicked(const QModelIndex &index);

    /**
     * @brief Copy the full version and build information block to the clipboard.
     */
    void on_copyToClipboard_clicked();
};

#endif // ABOUT_DIALOG_H
