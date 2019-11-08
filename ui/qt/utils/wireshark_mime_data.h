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

class WiresharkMimeData: public QMimeData {
public:
    virtual QString labelText() const = 0;
    virtual void allowPlainText();

    static const QString ColoringRulesMimeType;
    static const QString ColumnListMimeType;
    static const QString FilterListMimeType;
    static const QString DisplayFilterMimeType;
};

class ToolbarEntryMimeData: public WiresharkMimeData {
    Q_OBJECT
public:

    ToolbarEntryMimeData(QString element, int pos);

    int position() const;
    QString element() const;
    QString filter() const;
    void setFilter(QString);

    QString labelText() const override;

private:

    QString element_;
    QString filter_;
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

