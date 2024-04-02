/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef EXTCAP_OPTIONS_DIALOG_H
#define EXTCAP_OPTIONS_DIALOG_H

#include <config.h>

#include <QWidget>
#include <QDialog>
#include <QPushButton>
#include <QList>

#include "ui/qt/extcap_argument.h"

#include <extcap.h>
#include <extcap_parser.h>

namespace Ui {
class ExtcapOptionsDialog;
}

typedef QList<ExtcapArgument *> ExtcapArgumentList;

class ExtcapOptionsDialog : public QDialog
{
    Q_OBJECT

public:
    ~ExtcapOptionsDialog();
    static ExtcapOptionsDialog * createForDevice(QString &device_name, bool startCaptureOnClose, QWidget *parent = 0);

    ExtcapValueList loadValuesFor(int argNum, QString call, QString parent = "");

private Q_SLOTS:
    void on_buttonBox_clicked(QAbstractButton *button);
    void on_buttonBox_helpRequested();
    void updateWidgets();
    void anyValueChanged();

private:
    explicit ExtcapOptionsDialog(bool startCaptureOnClose, QWidget *parent = 0);

    Ui::ExtcapOptionsDialog *ui;
    QString device_name;
    unsigned device_idx;
    QIcon defaultValueIcon_;

    ExtcapArgumentList extcapArguments;

    void loadArguments();

    bool saveOptionToCaptureInfo();
    GHashTable * getArgumentSettings(bool useCallsAsKey = false, bool includeEmptyValues = true);
    void storeValues();
    void resetValues();

};

#endif // EXTCAP_OPTIONS_DIALOG_H
