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

/**
 * @brief Worker class for checking capture filter syntax in the background.
 */
class CaptureFilterSyntaxWorker : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CaptureFilterSyntaxWorker.
     * @param parent The parent QObject, defaults to 0.
     */
    CaptureFilterSyntaxWorker(QObject *parent = 0) : QObject(parent) {}

public slots:
    /**
     * @brief Checks the syntax of the provided capture filter.
     * @param filter The capture filter string to check.
     */
    void checkFilter(const QString filter);

signals:
    /**
     * @brief Signal emitted with the result of a syntax check.
     * @param filter The capture filter that was checked.
     * @param state The resulting state of the syntax check.
     * @param err_msg The error message if the syntax is invalid.
     */
    void syntaxResult(QString filter, int state, QString err_msg);
};

#endif // CAPTURE_FILTER_SYNTAX_WORKER_H
