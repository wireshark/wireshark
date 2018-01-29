/* url_link_delegate.cpp
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include <ui/qt/models/url_link_delegate.h>

#include <QPainter>

UrlLinkDelegate::UrlLinkDelegate(QObject *parent)
 : QStyledItemDelegate(parent)
{}

void UrlLinkDelegate::paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const {
    QStyleOptionViewItem opt = option;
    initStyleOption(&opt, index);

    opt.font.setUnderline(true);
    opt.palette.setColor(QPalette::Text, opt.palette.link().color());

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
