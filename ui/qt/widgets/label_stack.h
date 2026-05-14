/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LABEL_STACK_H
#define LABEL_STACK_H

#include <QLabel>
#include <QStack>
#include <QElapsedTimer>
#include <QTimer>

/**
 * @brief A QLabel that manages a stack of context-tagged text messages.
 */
class LabelStack : public QLabel
{
    Q_OBJECT
public:
    /**
     * @brief Construct a LabelStack.
     * @param parent The parent widget.
     */
    explicit LabelStack(QWidget *parent = 0);

    /**
     * @brief Designate a context ID as the "temporary" context.
     * @param ctx The context ID to treat as temporary.
     */
    void setTemporaryContext(const int ctx);

    /**
     * @brief Push a text message onto the label stack.
     *
     * @param text    The message text to display.
     * @param ctx     The context ID that owns this message; used to pop it later.
     * @param tooltip Optional tooltip string shown on hover; defaults to empty.
     */
    void pushText(const QString &text, int ctx, const QString &tooltip = QString());

    /**
     * @brief Control whether the label may shrink below its preferred width.
     *
     * @param shrinkable true to allow shrinking (default); false to enforce
     *                   the full preferred width.
     */
    void setShrinkable(bool shrinkable = true);

protected:
    /**
     * @brief Forward mouse press position and button via mousePressedAt().
     * @param event The mouse press event.
     */
    void mousePressEvent(QMouseEvent *event);

    /**
     * @brief Handle mouse button release (reserved for subclass use).
     * @param event The mouse release event.
     */
    void mouseReleaseEvent(QMouseEvent *event);

    /**
     * @brief Handle double-click events (reserved for subclass use).
     * @param event The double-click event.
     */
    void mouseDoubleClickEvent(QMouseEvent *event);

    /**
     * @brief Handle mouse move events (reserved for subclass use).
     * @param event The mouse move event.
     */
    void mouseMoveEvent(QMouseEvent *event);

    /**
     * @brief Show a context menu for the label (reserved for subclass use).
     * @param event The context menu event.
     */
    void contextMenuEvent(QContextMenuEvent *event);

    /**
     * @brief Paint the label, applying elision if shrinkable and space is tight.
     * @param event The paint event.
     */
    void paintEvent(QPaintEvent *event);

private:
    /**
     * @brief A single entry in the label stack.
     */
    typedef struct _StackItem {
        QString text;    /**< The message text. */
        QString tooltip; /**< The tooltip shown on hover, or empty. */
        int     ctx;     /**< The context ID that owns this entry. */
    } StackItem;

    int temporary_ctx_;          /**< The context ID treated as temporary/flash. */
    QList<StackItem> labels_;    /**< Stack of active label entries, newest last. */
    bool shrinkable_;            /**< Whether the label may compress horizontally. */
    QElapsedTimer temporary_epoch_; /**< Measures elapsed time since the temporary message was pushed. */
    QTimer temporary_timer_;     /**< Fires when the temporary message display period expires. */

    /**
     * @brief Rebuild the visible label text and tooltip from the top stack entry.
     */
    void fillLabel();


signals:
    /**
     * @brief Emitted when the temporary flash state changes.
     * @param enable true when a temporary message is active and flashing;
     *               false when it has expired and the label has reverted.
     */
    void toggleTemporaryFlash(bool enable);

    /**
     * @brief Emitted when a mouse button is pressed on the label.
     * @param global_pos The cursor position in global screen coordinates.
     * @param button     The mouse button that was pressed.
     */
    void mousePressedAt(const QPoint &global_pos, Qt::MouseButton button);

public slots:
    /**
     * @brief Remove the stack entry associated with @p ctx.
     * @param ctx The context ID whose entry should be removed.
     */
    void popText(int ctx);

private slots:
    /**
     * @brief Handle the temporary timer tick.
     */
    void updateTemporaryStatus();
};

#endif // LABEL_STACK_H
