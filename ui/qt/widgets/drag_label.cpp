/* drag_label.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/drag_label.h>

#include <QLayout>

DragLabel::DragLabel(QString txt, QWidget * parent)
: QLabel(txt, parent)
{
    setAutoFillBackground(true);
    setFrameShape(QFrame::Panel);
    setFrameShadow(QFrame::Raised);
    setAttribute(Qt::WA_DeleteOnClose);
    setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::MinimumExpanding);

    adjustSize();
}

DragLabel::~DragLabel() {
    // TODO Auto-generated destructor stub
}
