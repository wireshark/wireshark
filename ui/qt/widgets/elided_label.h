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

/**
 * @brief A QLabel subclass that elides text when it exceeds the widget's width, and optionally acts as a hyperlink.
 */
class ElidedLabel : public QLabel
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ElidedLabel.
     * @param parent The parent widget, defaults to 0.
     */
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
    /**
     * @brief Handles general events for the widget.
     * @param event The event to handle.
     * @return True if the event was handled, false otherwise.
     */
    virtual bool event(QEvent *event);

    /**
     * @brief Handles resize events to recalculate the elided text.
     */
    virtual void resizeEvent(QResizeEvent *);

private:
    /** Flag indicating whether the text should be displayed in a smaller font. */
    bool small_text_;

    /** The complete, un-elided text string. */
    QString full_text_;

    /** The URL string if the label acts as a hyperlink. */
    QString url_;

    /**
     * @brief Recalculates and updates the displayed text based on current width and settings.
     */
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
