/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RESOLVED_ADDRESSES_VIEW_H
#define RESOLVED_ADDRESSES_VIEW_H

#include <ui/qt/models/resolved_addresses_models.h>

#include <QTableView>
#include <QMenu>

/**
 * @brief Table view for displaying resolved network addresses, with built-in
 *        support for copying, exporting, and saving the address table in
 *        plain-text, CSV, and JSON formats.
 */
class ResolvedAddressesView : public QTableView
{
    Q_OBJECT

public:
    /**
     * @brief Output format used when exporting or copying resolved address data.
     */
    typedef enum {
        EXPORT_TEXT, /**< Plain-text tabular format. */
        EXPORT_CSV,  /**< Comma-separated values format. */
        EXPORT_JSON  /**< JSON array format. */
    } eResolvedAddressesExport;

    /**
     * @brief Constructs a ResolvedAddressesView.
     * @param parent Optional parent widget.
     */
    ResolvedAddressesView(QWidget *parent = nullptr);

    /**
     * @brief Creates and returns a "Copy" submenu populated with format actions.
     * @param selected @c true to restrict copy actions to the current selection;
     *                 @c false to copy all rows.
     * @param parent   Optional parent widget for the menu.
     * @return Pointer to the newly created QMenu; caller takes ownership.
     */
    QMenu *createCopyMenu(bool selected = false, QWidget *parent = nullptr);

public slots:
    /**
     * @brief Opens a file-save dialog and writes the full address table to a
     *        user-chosen file in the selected export format.
     */
    void saveAs();

protected:
    /**
     * @brief Presents a context menu with copy and save options at the cursor position.
     * @param e The context menu event carrying the cursor position.
     */
    void contextMenuEvent(QContextMenuEvent *e) override;

private:
    QAction *clip_action_; /**< Action that triggers a clipboard copy in the last-used format. */

    /**
     * @brief Returns the underlying AStringListListModel powering this view.
     * @return Pointer to the model cast to AStringListListModel, or @c nullptr if not set.
     */
    AStringListListModel *dataModel() const;

    /**
     * @brief Copies the address table (or the current selection) to the system clipboard.
     * @param format   Output format to use for the clipboard text.
     * @param selected @c true to copy only selected rows; @c false to copy all rows.
     */
    void copyToClipboard(eResolvedAddressesExport format, bool selected);

private slots:
    /**
     * @brief Slot connected to @c clip_action_; copies data to the clipboard
     *        using the format encoded in the triggering action's data.
     */
    void clipboardAction();

    /**
     * @brief Serialises the address table to @p stream in the requested format.
     * @param stream   Output text stream to write to.
     * @param format   Export format to use.
     * @param selected @c true to serialise only selected rows; @c false for all rows.
     */
    void toTextStream(QTextStream &stream, eResolvedAddressesExport format, bool selected = false) const;
};

#endif // RESOLVED_ADDRESSES_VIEW_H
