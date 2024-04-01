/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COPY_FROM_PROFILE_BUTTON_H
#define COPY_FROM_PROFILE_BUTTON_H

#include <config.h>

#include <QMenu>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QMetaObject>

class CopyFromProfileButton : public QPushButton
{
    Q_OBJECT

public:
    CopyFromProfileButton(QWidget * parent = Q_NULLPTR, QString profileFile = QString(), QString toolTip = QString());

    void setFilename(QString filename);

signals:
    void copyProfile(QString filename);

private:
    QString filename_;
    QMenu * buttonMenu_;

    QAction * systemDefault(QString filename);

private slots:
    void menuActionTriggered(QAction *);
};

#endif // COPY_FROM_PROFILE_BUTTON_H
