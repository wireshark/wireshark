/* extcap_argument_file.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_EXTCAP_ARGUMENT_FILE_H_
#define UI_QT_EXTCAP_ARGUMENT_FILE_H_

#include <QObject>
#include <QWidget>
#include <QLineEdit>

#include <extcap_parser.h>
#include <extcap_argument.h>

class ExtcapArgumentFileSelection : public ExtcapArgument
{
    Q_OBJECT

public:
    ExtcapArgumentFileSelection(extcap_arg * argument, QObject * parent = Q_NULLPTR);
    virtual ~ExtcapArgumentFileSelection();

    virtual QWidget * createEditor(QWidget * parent);

    virtual QString value();

    virtual bool isValid();

protected:
    QLineEdit * textBox;

private slots:
    /* opens the file dialog */
    void openFileDialog();
    /* clears previously entered filename */
    void clearFilename();
};

#endif /* UI_QT_EXTCAP_ARGUMENT_FILE_H_ */

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
