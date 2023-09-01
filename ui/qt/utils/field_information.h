/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIELD_INFORMATION_H_
#define FIELD_INFORMATION_H_

#include <config.h>

#include <epan/proto.h>

#include <ui/qt/utils/proto_node.h>
#include "data_printer.h"

#include <QObject>

class FieldInformation : public QObject, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:

    struct HeaderInfo
    {
        QString name;
        QString description;
        QString abbreviation;
        bool isValid;
        enum ftenum type;
        int parent;
        int id;
    };

    struct Position
    {
        int start;
        int length;
    };

    explicit FieldInformation(field_info * fi, QObject * parent = Q_NULLPTR);
    explicit FieldInformation(const ProtoNode * node, QObject * parent = Q_NULLPTR);

    bool isValid() const;
    bool isLink() const ;

    field_info * fieldInfo() const;

    HeaderInfo headerInfo() const;
    Position position() const;
    Position appendix() const;

    void setParentField(field_info * fi);
    int treeType();
    FieldInformation * parentField() const;
    bool tvbContains(FieldInformation *);
    unsigned flag(unsigned mask);
    const QString moduleName();
    QString toString();
    QString url();

    const QByteArray printableData();

private:

    field_info * fi_;
    field_info * parent_fi_;
};


#endif // FIELD_INFORMATION_H_
