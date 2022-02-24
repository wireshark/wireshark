/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_FILTER_SYNTAX_WORKER_H
#define CAPTURE_FILTER_SYNTAX_WORKER_H

#include <QMutex>
#include <QObject>
#include <QWaitCondition>

class CaptureFilterSyntaxWorker : public QObject
{
    Q_OBJECT

public:
    CaptureFilterSyntaxWorker(QObject *parent = 0) : QObject(parent) {}

public slots:
    void checkFilter(const QString filter);

signals:
    void syntaxResult(QString filter, int state, QString err_msg);
};

#endif // CAPTURE_FILTER_SYNTAX_WORKER_H
