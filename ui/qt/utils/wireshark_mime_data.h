/* wireshark_mime_data.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UI_QT_UTILS_WIRESHARK_MIME_DATA_H_
#define UI_QT_UTILS_WIRESHARK_MIME_DATA_H_

#include <QMimeData>

class DisplayFilterMimeData: public QMimeData {
    Q_OBJECT
public:

    DisplayFilterMimeData(QString description, QString field, QString filter);

    QString description() const;
    QString field() const;
    QString filter() const;

    QString labelText() const;

private:

    QString description_;
    QString filter_;
    QString field_;

};

class ToolbarEntryMimeData: public QMimeData {
    Q_OBJECT
public:

    ToolbarEntryMimeData(QString element, int pos);

    int position() const;
    QString element() const;

    QString labelText() const;

private:

    QString element_;
    int pos_;

};

#endif /* UI_QT_UTILS_WIRESHARK_MIME_DATA_H_ */

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

