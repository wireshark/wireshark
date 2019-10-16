/* capture_filter_syntax_worker.h
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
    void checkFilter(const QString &filter);

public slots:
    void start();

private:
    QMutex data_mtx_;
    QWaitCondition data_cond_;
    QString filter_text_;

signals:
    void syntaxResult(QString filter, int state, QString err_msg);
};

#endif // CAPTURE_FILTER_SYNTAX_WORKER_H

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
