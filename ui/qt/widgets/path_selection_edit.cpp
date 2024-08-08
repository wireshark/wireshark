/* path_chooser_delegate.cpp
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include "ui/util.h"

#include <ui/qt/widgets/path_selection_edit.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"
#include "ui/qt/utils/qt_ui_utils.h"

#include <QHBoxLayout>
#include <QToolButton>
#include <QWidget>
#include <QLineEdit>

PathSelectionEdit::PathSelectionEdit(QString title, QString path, bool selectFile, QWidget *parent) :
    QWidget(parent)
{
    _title = title;
    _path = path;
    _selectFile = selectFile;

    _edit = new QLineEdit(this);
    _edit->setText(_path);
    connect(_edit, &QLineEdit::textChanged, this, &PathSelectionEdit::setPath);

    _button = new QToolButton(this);
    _button->setText(tr("Browse"));
    connect(_button, &QToolButton::clicked, this, &PathSelectionEdit::browseForPath);

    setContentsMargins(0, 0, 0, 0);
    QHBoxLayout *hbox = new QHBoxLayout(this);
    hbox->setContentsMargins(0, 0, 0, 0);
    hbox->addWidget(_edit);
    hbox->addWidget(_button);
    hbox->setSizeConstraint(QLayout::SetMinimumSize);

    setLayout(hbox);

    setFocusProxy(_edit);
    setFocusPolicy(_edit->focusPolicy());
}

PathSelectionEdit::PathSelectionEdit(QWidget *parent) :
    PathSelectionEdit(tr("Select a path"), QString(), true, parent)
{}

void PathSelectionEdit::setPath(QString newPath)
{
    _path = newPath;
    if (!sender()) {
        _edit->blockSignals(true);
        _edit->setText(newPath);
        _edit->blockSignals(false);
    } else {
        emit pathChanged(newPath);
    }
}

QString PathSelectionEdit::path() const
{
    return _path;
}

void PathSelectionEdit::browseForPath()
{
    QString openDir = _path;

    if (openDir.isEmpty()) {
        openDir = openDialogInitialDir();
    }

    QString newPath;
    if ( _selectFile )
        newPath = WiresharkFileDialog::getOpenFileName(this, _title, openDir);
    else
        newPath = WiresharkFileDialog::getExistingDirectory(this, _title, openDir);

    if (!newPath.isEmpty()) {
        _edit->setText(newPath);
    }
}
