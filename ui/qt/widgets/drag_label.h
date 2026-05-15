/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_WIDGETS_DRAG_LABEL_H_
#define UI_QT_WIDGETS_DRAG_LABEL_H_

#include <QLabel>
#include <QDrag>
#include <QMimeData>
#include <QMouseEvent>

/**
 * @brief A specialized label widget designed to support drag-and-drop operations.
 */
class DragLabel: public QLabel
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new DragLabel.
     * @param text The text to be displayed on the label.
     * @param parent The parent widget, defaults to 0.
     */
    explicit DragLabel(QString text, QWidget * parent = 0);

    /**
     * @brief Destroys the DragLabel.
     */
    virtual ~DragLabel();
};

#endif /* UI_QT_WIDGETS_DRAG_LABEL_H_ */
