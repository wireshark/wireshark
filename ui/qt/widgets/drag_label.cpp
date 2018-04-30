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

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
