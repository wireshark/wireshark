/* editor_color_dialog.cpp
 *
 * Color dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include <ui/qt/widgets/editor_color_dialog.h>

#include <QColorDialog>
#include <QKeyEvent>
#include <QStyle>

EditorColorDialog::EditorColorDialog(const QModelIndex& index, const QColor& initial, QWidget* parent)
    : QLineEdit(parent)
    , color_button_(new QPushButton(this))
    , index_(index)
    , current_(initial)
{
    connect(color_button_, SIGNAL(clicked()), this, SLOT(applyColor()));
}

// QAbstractItemView installs QAbstractItemDelegate's event filter after
// we've been created. We need to install our own event filter after that
// happens so that we can steal tab keypresses.
void EditorColorDialog::focusInEvent(QFocusEvent *event)
{
    installEventFilter(this);
    QLineEdit::focusInEvent(event);
}

void EditorColorDialog::focusOutEvent(QFocusEvent *event)
{
    removeEventFilter(this);
    QLineEdit::focusOutEvent(event);
}

bool EditorColorDialog::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ( (key->key() == Qt::Key_Tab) && !color_button_->hasFocus()) {
            color_button_->setFocus();
            return true;
        }
    }
    return QLineEdit::eventFilter(obj, event);
}

void EditorColorDialog::resizeEvent(QResizeEvent *)
{
    // Move the button to the end of the line edit and set its height.
    QSize sz = color_button_->sizeHint();
    int frame_width = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    color_button_->move(rect().right() - frame_width - sz.width(),
                        contentsRect().top());
    color_button_->setMinimumHeight(contentsRect().height());
    color_button_->setMaximumHeight(contentsRect().height());
}

void EditorColorDialog::applyColor()
{
    QColorDialog color_dlg;

    color_dlg.setCurrentColor(current_);
    if (color_dlg.exec() == QDialog::Accepted) {
        current_ = color_dlg.currentColor();
        emit acceptEdit(index_);
    }

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
