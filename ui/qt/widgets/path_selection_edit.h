/* path_chooser_delegate.cpp
 * Delegate to select a file path for a treeview entry
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PATH_SELECTOR_EDIT_H
#define PATH_SELECTOR_EDIT_H

#include <QWidget>
#include <QString>
#include <QLineEdit>
#include <QToolButton>

class PathSelectionEdit : public QWidget
{
    Q_OBJECT

public:
    PathSelectionEdit(QString title, QString path, bool selectFile, QWidget *parent = 0);
    PathSelectionEdit(QWidget *parent = 0);

    QString path() const;

public slots:
    void setPath(QString newPath = QString());

signals:
    void pathChanged(QString newPath);

protected slots:
    void browseForPath();

private:
    QString _path;

    QString _title;
    bool _selectFile;

    QLineEdit * _edit;
    QToolButton * _button;
};

#endif // PATH_SELECTOR_EDIT_H
