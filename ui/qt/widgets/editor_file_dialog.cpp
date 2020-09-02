/* editor_file_dialog.h
 *
 * File dialog that can be used as an "inline editor" in a table
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/editor_file_dialog.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>

#include <QKeyEvent>
#include <QStyle>

#include "wsutil/utf8_entities.h"

EditorFileDialog::EditorFileDialog(const QModelIndex& index, enum FileMode mode, QWidget* parent, const QString& caption, const QString& directory, const QString& filter)
    : QLineEdit(parent)
    , file_dialog_button_(new QPushButton(this))
    , index_(index)
    , mode_(mode)
    , caption_(caption)
    , directory_(directory)
    , filter_(filter)
    , options_(QFileDialog::Options())
{
    if (mode_ == Directory)
        options_ = QFileDialog::ShowDirsOnly;

    if (!directory.isEmpty())
        setText(directory);

    file_dialog_button_->setText(UTF8_HORIZONTAL_ELLIPSIS);
    connect(file_dialog_button_, &QPushButton::clicked, this, &EditorFileDialog::applyFilename);
}

void EditorFileDialog::setOption(QFileDialog::Option option, bool on)
{
    if (on)
    {
        options_ |= option;
    }
    else
    {
        options_ &= (~option);
    }
}

// QAbstractItemView installs QAbstractItemDelegate's event filter after
// we've been created. We need to install our own event filter after that
// happens so that we can steal tab keypresses.
void EditorFileDialog::focusInEvent(QFocusEvent *event)
{
    installEventFilter(this);
    QLineEdit::focusInEvent(event);
}

void EditorFileDialog::focusOutEvent(QFocusEvent *event)
{
    removeEventFilter(this);
    QLineEdit::focusOutEvent(event);
}

bool EditorFileDialog::eventFilter(QObject *obj, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        QKeyEvent* key = static_cast<QKeyEvent*>(event);
        if ((key->key() == Qt::Key_Tab) && !file_dialog_button_->hasFocus()) {
            file_dialog_button_->setFocus();
            return true;
        }
    }
    return QLineEdit::eventFilter(obj, event);
}

void EditorFileDialog::resizeEvent(QResizeEvent *)
{
    // Move the button to the end of the line edit and set its height.
    QSize sz = file_dialog_button_->sizeHint();
    int frame_width = style()->pixelMetric(QStyle::PM_DefaultFrameWidth);
    file_dialog_button_->move(rect().right() - frame_width - sz.width(),
                      contentsRect().top());
    file_dialog_button_->setMinimumHeight(contentsRect().height());
    file_dialog_button_->setMaximumHeight(contentsRect().height());

}

void EditorFileDialog::applyFilename()
{
    QString file;

    if (mode_ == Directory)
    {
        file = WiresharkFileDialog::getExistingDirectory(this, caption_, directory_, options_);
    }
    else
    {
        file = WiresharkFileDialog::getOpenFileName(this, caption_, directory_, filter_, NULL, options_);
    }

    if (!file.isEmpty())
    {
        setText(file);
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
