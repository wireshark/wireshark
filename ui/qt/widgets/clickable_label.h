/** @file
 *
 * Taken from https://wiki.qt.io/Clickable_QLabel and adapted for usage
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CLICKABLE_LABEL_H_
#define CLICKABLE_LABEL_H_

#include <QLabel>

/**
 * @brief A custom QLabel that emits signals when clicked.
 */
class ClickableLabel : public QLabel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ClickableLabel.
     * @param parent The parent widget, defaults to 0.
     */
    explicit ClickableLabel(QWidget* parent=0);

signals:
    /**
     * @brief Signal emitted when the label is clicked.
     */
    void clicked();

    /**
     * @brief Signal emitted when the label is clicked, providing position and button details.
     * @param global_pos The global position of the click.
     * @param button The mouse button that was clicked.
     */
    void clickedAt(const QPoint &global_pos, Qt::MouseButton button);

protected:
    /**
     * @brief Handles the mouse release event.
     * @param event The mouse event details.
     */
    void mouseReleaseEvent(QMouseEvent* event);

    /**
     * @brief Handles the mouse press event.
     * @param event The mouse event details.
     */
    void mousePressEvent(QMouseEvent *event);

    /**
     * @brief Handles the context menu event.
     * @param event The context menu event details.
     */
    void contextMenuEvent(QContextMenuEvent *event);
};

#endif /* CLICKABLE_LABEL_H_ */
