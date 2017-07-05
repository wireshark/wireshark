/* elided_label.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef ELIDED_LABEL_H
#define ELIDED_LABEL_H

#include <QLabel>

class ElidedLabel : public QLabel
{
    Q_OBJECT
public:
    explicit ElidedLabel(QWidget *parent = 0);
    void setUrl(const QString &url);
    void setSmallText(bool small_text = true) { small_text_ = small_text; }

protected:
    void resizeEvent(QResizeEvent *);

private:
    bool small_text_;
    QString full_text_;
    QString url_;

    void updateText();

signals:

public slots:
    void clear();
    void setText(const QString &text);
};

#endif // ELIDED_LABEL_H
