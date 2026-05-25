/** @file
 *
 * Delegates for displaying links as links, including elide model
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef URL_LINK_DELEGATE_H
#define URL_LINK_DELEGATE_H

#include <QStyledItemDelegate>
#include <QStyleOptionViewItem>
#include <QModelIndex>
#include <QRegularExpression>

/**
 * @brief A delegate that renders specific table cells as clickable URL links.
 */
class UrlLinkDelegate : public QStyledItemDelegate
{
public:
    /**
     * @brief Constructs a new UrlLinkDelegate object.
     * @param parent The parent object.
     */
    explicit UrlLinkDelegate(QObject *parent = Q_NULLPTR);

    /**
     * @brief Destroys the UrlLinkDelegate object.
     */
    ~UrlLinkDelegate();

    // If pattern matches the string in column, render as a URL.
    // Otherwise render as plain text.
    /**
     * @brief Configures a column to be checked against a regular expression pattern for URL rendering.
     * @param column The column index to check.
     * @param pattern The regular expression pattern string.
     */
    void setColCheck(int column, QString &pattern);

protected:
    /**
     * @brief Custom paint method to render the cell text as a URL if it matches the pattern.
     * @param painter The painter object.
     * @param option The style option for the item.
     * @param index The model index of the item.
     */
    virtual void paint(QPainter *painter, const QStyleOptionViewItem &option, const QModelIndex &index) const override;

private:
    /** @brief The column index designated for URL checking. */
    int re_col_;

    /** @brief The regular expression object used to validate URL strings. */
    QRegularExpression *url_re_;
};
#endif // URL_LINK_DELEGATE_H
