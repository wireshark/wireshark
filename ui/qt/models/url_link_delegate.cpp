/* url_link_delegate.cpp
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/models/url_link_delegate.h>

#include <QPainter>
#include <QRegExp>

#include <ui/qt/utils/color_utils.h>

UrlLinkDelegate::UrlLinkDelegate(QObject *parent)
 : QStyledItemDelegate(parent),
   re_col_(-1),
   url_re_(new QRegExp())
{}

UrlLinkDelegate::~UrlLinkDelegate()
{
    delete url_re_;
}

void UrlLinkDelegate::setColCheck(int column, QString &pattern)
{
    re_col_ = column;
    url_re_->setPattern(pattern);
}

void UrlLinkDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const {
    if (re_col_ >= 0 && url_re_) {
        QModelIndex re_idx = index.model()->index(index.row(), re_col_);
        QString col_text = index.model()->data(re_idx).toString();
        if (url_re_->indexIn(col_text) < 0) {
            QStyledItemDelegate::paint(painter, option, index);
            return;
        }
    }

    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);

    opt.font.setUnderline(true);
    opt.palette.setColor(QPalette::Text, ColorUtils::themeLinkBrush().color());

    QStyledItemDelegate::paint(painter, opt, index);
}

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
