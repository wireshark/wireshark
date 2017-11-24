/* url_link.cpp
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <ui/qt/models/url_link_delegate.h>

#include <QComboBox>
#include <QEvent>
#include <QLineEdit>
#include <QPainter>
#include <QTextDocument>
#include <QRect>
#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QTextEdit>

UrlLinkDelegate::UrlLinkDelegate(QObject *parent)
 : QStyledItemDelegate(parent)
{}

void UrlLinkDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const {
    QStyleOptionViewItem options = option;
    initStyleOption(&options, index);

    QString text = options.text;
    if (text.isEmpty())
        return;

    int one_em = option.fontMetrics.height();
    QString short_dir = option.fontMetrics.elidedText(text, Qt::ElideMiddle, one_em * 10);

    painter->save();
    QFont font = option.font;
    font.setUnderline(true);
    painter->setFont(font);
    painter->setPen(option.palette.link().color());
    painter->drawText(option.rect, Qt::AlignLeft | Qt::AlignVCenter, short_dir);

    painter->restore();
}

QSize UrlLinkDelegate::sizeHint(const QStyleOptionViewItem &option, const QModelIndex &index) const {
    QStyleOptionViewItem options = option;
    initStyleOption(&options, index);

    QString text = options.text;
    if (text.isEmpty())
        return QStyledItemDelegate::sizeHint(option, index);

    int one_em = option.fontMetrics.height();
    QString short_dir = option.fontMetrics.elidedText(text, Qt::ElideMiddle, one_em * 10);

    QTextDocument doc;
    doc.setHtml(short_dir);
    doc.setTextWidth(options.rect.width());
    return QSize(doc.idealWidth(), doc.size().height());
}

/* * Editor modelines
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
