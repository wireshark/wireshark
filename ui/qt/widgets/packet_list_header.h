/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_WIDGETS_PACKET_LIST_HEADER_H_
#define UI_QT_WIDGETS_PACKET_LIST_HEADER_H_

#include <epan/cfile.h>

#include <QDrag>
#include <QMenu>

#include <ui/qt/widgets/adaptive_header_view.h>

class QEvent;

/**
 * @brief Custom header view for the packet list.
 */
class PacketListHeader : public AdaptiveHeaderView
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a PacketListHeader.
     * @param orientation The orientation of the header.
     * @param parent The parent widget.
     */
    PacketListHeader(Qt::Orientation orientation, QWidget *parent = nullptr);

protected:
    /**
     * @brief Handles drop events.
     * @param event The drop event.
     */
    virtual void dropEvent(QDropEvent *event) override;

    /**
     * @brief Handles drag enter events.
     * @param event The drag enter event.
     */
    virtual void dragEnterEvent(QDragEnterEvent *event) override;

    /**
     * @brief Handles drag move events.
     * @param event The drag move event.
     */
    virtual void dragMoveEvent(QDragMoveEvent *event) override;

    /**
     * @brief Handles mouse move events.
     * @param e The mouse event.
     */
    virtual void mouseMoveEvent(QMouseEvent *e) override;

    /**
     * @brief Handles mouse press events.
     * @param e The mouse event.
     */
    virtual void mousePressEvent(QMouseEvent *e) override;

    /**
     * @brief Handles context menu events.
     * @param event The context menu event.
     */
    virtual void contextMenuEvent(QContextMenuEvent *event) override;

protected slots:
    /**
     * @brief Slot triggered to toggle column visibility.
     */
    void columnVisibilityTriggered();

    /**
     * @brief Sets the alignment of a column.
     * @param action The action specifying the alignment.
     */
    void setAlignment(QAction *action);

    /**
     * @brief Sets the display format for a column.
     * @param action The action specifying the format.
     */
    void setDisplayFormat(QAction *action);

    /**
     * @brief Shows the column preferences dialog.
     */
    void showColumnPrefs();

    /**
     * @brief Initiates editing of the selected column.
     */
    void doEditColumn();

    /**
     * @brief Resizes the column to fit its contents.
     */
    void resizeToContent();

    /**
     * @brief Removes the selected column.
     */
    void removeColumn();

    /**
     * @brief Prompts to resize the column to a specific width.
     */
    void resizeToWidth();

signals:
    /**
     * @brief Signal emitted to reset a column's width.
     * @param col The column index to reset.
     */
    void resetColumnWidth(int col);

    /**
     * @brief Signal emitted to update the packet list.
     * @param redraw True to force a redraw, false otherwise.
     */
    void updatePackets(bool redraw);

    /**
     * @brief Signal emitted to show column preferences.
     * @param pane_name The name of the preference pane to show.
     */
    void showColumnPreferences(QString pane_name);

    /**
     * @brief Signal emitted to edit a specific column.
     * @param column The column index to edit.
     */
    void editColumn(int column);

    /**
     * @brief Signal emitted when the columns configuration has changed.
     */
    void columnsChanged();

private:
    int sectionIdx; /**< The index of the section currently being interacted with. */
};

#endif
