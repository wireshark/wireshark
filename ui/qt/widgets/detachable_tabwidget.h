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

#include <QTabWidget>
#include <QDialog>
#include <QEvent>
#include <QCloseEvent>
#include <QTabBar>
#include <QPoint>
#include <QCursor>

class DetachableTabWidget : public QTabWidget
{
    Q_OBJECT
public:
    DetachableTabWidget(QWidget * parent = nullptr);

    QString tabBasename() const;

protected:

    void setTabBasename(QString newName);

protected slots:

    virtual void moveTab(int from, int to);
    virtual void detachTab(int tabIdx, QPoint pos);
    virtual void attachTab(QWidget * content, QString name);

private:
    QString _tabBasename;

};

class ToolDialog : public QDialog
{
    Q_OBJECT
public:
    explicit ToolDialog(QWidget * _contentWidget, QWidget * parent = nullptr, Qt::WindowFlags f = Qt::WindowFlags());

protected:

    virtual bool event(QEvent *event);
    virtual void closeEvent(QCloseEvent *event);

signals:
    void onCloseSignal(QWidget * contentWidget, QString name);

private:
    QWidget * _contentWidget;
};

class DragDropTabBar : public QTabBar
{
    Q_OBJECT
public:
    explicit DragDropTabBar(QWidget * parent);

signals:
    void onDetachTab(int tabIdx, QPoint pos);
    void onMoveTab(int oldIdx, int newIdx);

protected:
    virtual void mouseDoubleClickEvent(QMouseEvent *event);
    virtual void mousePressEvent(QMouseEvent *event);
    virtual void mouseMoveEvent(QMouseEvent *event);
    virtual void dragEnterEvent(QDragEnterEvent *event);
    virtual void dropEvent(QDropEvent *event);

private:
    QPoint _dragStartPos;
    QPoint _dragDropPos;
    QCursor _mouseCursor;
    bool _dragInitiated;

};

#endif // DETACHABLE_TABWIDGET_H
