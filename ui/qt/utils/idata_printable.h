/** @file
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

/**
 * @brief An interface for objects that can provide a printable data representation.
 */
class IDataPrintable
{
public:
    /**
     * @brief Destroys the IDataPrintable object.
     */
    virtual ~IDataPrintable() {}

    /**
     * @brief Retrieves the printable data representation of the object.
     * @return A QByteArray containing the printable data.
     */
    virtual const QByteArray printableData() = 0;
};

/**
 * @brief The interface identifier for IDataPrintable, used by Qt's meta-object system.
 */
#define IDataPrintable_iid "org.wireshark.Qt.UI.IDataPrintable"

Q_DECLARE_INTERFACE(IDataPrintable, IDataPrintable_iid)

#endif // IDATA_PRINTABLE_H
