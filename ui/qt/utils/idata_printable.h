/* idata_printable.h
 *
 * Interface class for classes, which provide an interface to
 * print objects
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef IDATA_PRINTABLE_H
#define IDATA_PRINTABLE_H

#include <config.h>

#include <QtPlugin>
#include <QByteArray>
#include <QObject>

class IDataPrintable
{
public:
    virtual ~IDataPrintable() {}

    virtual const QByteArray printableData() = 0;
};

#define IDataPrintable_iid "org.wireshark.Qt.UI.IDataPrintable"

Q_DECLARE_INTERFACE(IDataPrintable, IDataPrintable_iid)

#endif // IDATA_PRINTABLE_H

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
