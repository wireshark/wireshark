/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DETACHABLE_TABWIDGET_H
#define DETACHABLE_TABWIDGET_H

#include <wireshark.h>

#include <QTabWidget>
#include <QDialog>
#include <QEvent>
#include <QCloseEvent>
#include <QTabBar>
#include <QPoint>
#include <QCursor>

/**
 * @brief A QTabWidget extension that allows tabs to be detached into separate windows.
 */
class DetachableTabWidget : public QTabWidget
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DetachableTabWidget.
     * @param parent The parent widget, defaults to nullptr.
     */
    DetachableTabWidget(QWidget * parent = nullptr);

    /**
     * @brief Retrieves the base name used when generating detached tab titles.
     * @return The base name string.
     */
    QString tabBasename() const;

protected:

    /**
     * @brief Sets the base name used when generating detached tab titles.
     * @param newName The new base name string.
     */
    void setTabBasename(QString newName);

protected slots:

    /**
     * @brief Moves a tab from one index to another.
     * @param from The original tab index.
     * @param to The new tab index.
     */
    virtual void moveTab(int from, int to);

    /**
     * @brief Detaches a tab into its own separate dialog window.
     * @param tabIdx The index of the tab to detach.
     * @param pos The position on screen to display the detached window.
     */
    virtual void detachTab(int tabIdx, QPoint pos);

    /**
     * @brief Attaches a previously detached widget back into the tab widget.
     * @param content The widget to reattach.
     * @param name The title to give the reattached tab.
     */
    virtual void attachTab(QWidget * content, QString name);

private:
    /** The base name string used for tabs. */
    QString _tabBasename;

};

/**
 * @brief A dialog wrapper for hosting a detached tab widget.
 */
class ToolDialog : public QDialog
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new ToolDialog.
     * @param _contentWidget The widget to display within the dialog.
     * @param parent The parent widget, defaults to nullptr.
     * @param f The window flags to apply.
     */
    explicit ToolDialog(QWidget * _contentWidget, QWidget * parent = nullptr, Qt::WindowFlags f = Qt::WindowFlags());

protected:

    /**
     * @brief Handles general events directed to the dialog.
     * @param event The event to process.
     * @return True if handled, false otherwise.
     */
    virtual bool event(QEvent *event) override;

    /**
     * @brief Handles the close event, emitting a signal to optionally reattach the content.
     * @param event The close event details.
     */
    virtual void closeEvent(QCloseEvent *event) override;

signals:
    /**
     * @brief Signal emitted when the dialog is closing.
     * @param contentWidget The widget that was hosted inside the dialog.
     * @param name The title of the dialog/tab.
     */
    void onCloseSignal(QWidget * contentWidget, QString name);

private:
    /** The widget currently hosted by this dialog. */
    QWidget * _contentWidget;
};

/**
 * @brief A customized QTabBar supporting drag and drop operations to reorder or detach tabs.
 */
class DragDropTabBar : public QTabBar
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new DragDropTabBar.
     * @param parent The parent widget.
     */
    explicit DragDropTabBar(QWidget * parent);

signals:
    /**
     * @brief Signal emitted to request a tab detachment.
     * @param tabIdx The index of the tab being detached.
     * @param pos The global position where the drop occurred.
     */
    void onDetachTab(int tabIdx, QPoint pos);

    /**
     * @brief Signal emitted to indicate a tab has been moved via drag and drop.
     * @param oldIdx The original index of the tab.
     * @param newIdx The new index of the tab.
     */
    void onMoveTab(int oldIdx, int newIdx);

protected:
    /**
     * @brief Handles mouse double-click events.
     * @param event The mouse event details.
     */
    virtual void mouseDoubleClickEvent(QMouseEvent *event) override;

    /**
     * @brief Handles mouse press events to initiate drag tracking.
     * @param event The mouse event details.
     */
    virtual void mousePressEvent(QMouseEvent *event) override;

    /**
     * @brief Handles mouse move events to trigger the actual drag operation.
     * @param event The mouse event details.
     */
    virtual void mouseMoveEvent(QMouseEvent *event) override;

    /**
     * @brief Handles drag enter events to accept drops.
     * @param event The drag enter event details.
     */
    virtual void dragEnterEvent(QDragEnterEvent *event) override;

    /**
     * @brief Handles drop events to finalize reordering.
     * @param event The drop event details.
     */
    virtual void dropEvent(QDropEvent *event) override;

private:
    /** The starting point of the mouse drag operation. */
    QPoint _dragStartPos;

    /** The position where the drop occurred. */
    QPoint _dragDropPos;

    /** The cursor to display during the drag operation. */
    QCursor _mouseCursor;

    /** Flag indicating whether a drag operation is currently active. */
    bool _dragInitiated;

};

#endif // DETACHABLE_TABWIDGET_H
