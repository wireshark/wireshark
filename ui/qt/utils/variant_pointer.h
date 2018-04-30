/*
 * variant_pointer.h
 * Range routines
 *
 * Roland Knall <rknall@gmail.com>
  *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_VARIANT_POINTER_H_
#define UI_QT_VARIANT_POINTER_H_

#include <QVariant>

template <typename T> class VariantPointer
{

public:
    static T* asPtr(QVariant v)
    {
        return  (T *) v.value<void *>();
    }

    static QVariant asQVariant(T* ptr)
    {
        return QVariant::fromValue((void *) ptr);
    }
};

#endif /* UI_QT_VARIANT_POINTER_H_ */
