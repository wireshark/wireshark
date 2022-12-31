/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ELIDED_LABEL_H
#define ELIDED_LABEL_H

#include <QLabel>

class ElidedLabel : public QLabel
{
    Q_OBJECT
public:
    explicit ElidedLabel(QWidget *parent = 0);
    /**
     * @brief setUrl Set the label's URL.
     * @param url The URL to set.
     */
    void setUrl(const QString &url);
    /**
     * @brief setSmallText Specifies a small or normal text size.
     * @param small_text Show the text in a smaller font size if true, or a normal size otherwise.
     */
    void setSmallText(bool small_text = true) { small_text_ = small_text; }

protected:
    virtual bool event(QEvent *event);
    virtual void resizeEvent(QResizeEvent *);

private:
    bool small_text_;
    QString full_text_;
    QString url_;

    void updateText();

signals:

public slots:
    /**
     * @brief clear Clear the label.
     */
    void clear();
    /**
     * @brief setText Set the label's plain text.
     * @param text The text to set. HTML will be escaped.
     */
    void setText(const QString &text);
};

#endif // ELIDED_LABEL_H
