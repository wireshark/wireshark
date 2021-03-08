/* drag_label.h
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

class DragLabel: public QLabel
{
    Q_OBJECT

public:
    explicit DragLabel(QString text, QWidget * parent = 0);
    virtual ~DragLabel();
};

#endif /* UI_QT_WIDGETS_DRAG_LABEL_H_ */
