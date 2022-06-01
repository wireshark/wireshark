/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/detachable_tabwidget.h>

#include <QStackedWidget>
#include <QBoxLayout>
#include <QEvent>
#include <QCloseEvent>
#include <QMouseEvent>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QMimeData>
#include <QStringList>
#include <QApplication>
#include <QDrag>
#include <QPixmap>
#include <QPainter>

DetachableTabWidget::DetachableTabWidget(QWidget *parent) :
    QTabWidget(parent)
{
    DragDropTabBar * tabBar = new DragDropTabBar(this);
    connect(tabBar, &DragDropTabBar::onDetachTab, this, &DetachableTabWidget::detachTab);
    connect(tabBar, &DragDropTabBar::onMoveTab, this, &DetachableTabWidget::moveTab);

    setMovable(false);

    setTabBar(tabBar);
}

void DetachableTabWidget::setTabBasename(QString newName) {
    _tabBasename = newName;
}

QString DetachableTabWidget::tabBasename() const {
    return _tabBasename;
}

void DetachableTabWidget::moveTab(int from, int to)
{
    QWidget * contentWidget = widget(from);
    QString text = tabText(from);

    removeTab(from);
    insertTab(to, contentWidget, text);
    setCurrentIndex(to);
}

void DetachableTabWidget::detachTab(int tabIdx, QPoint pos)
{
    QString name = tabText(tabIdx);

    QWidget * contentWidget = widget(tabIdx);
    
    /* For the widget to properly show in the dialog, it has to be
     * removed properly and unhidden. QTabWidget uses a QStackedWidget for
     * all parents of widgets. So we remove it from it's own parent and then
     * unhide it to show the widget in the dialog */
    QStackedWidget * par = qobject_cast<QStackedWidget *>(contentWidget->parent());
    if (!par)
        return;
    QRect contentWidgetRect = par->frameGeometry();
    par->removeWidget(contentWidget);
    contentWidget->setHidden(false);

    ToolDialog * detachedTab = new ToolDialog(contentWidget, parentWidget());
    detachedTab->setWindowModality(Qt::NonModal);
    detachedTab->setWindowTitle(_tabBasename + ": " + name);
    detachedTab->setObjectName(name);
    detachedTab->setGeometry(contentWidgetRect);
    connect(detachedTab, &ToolDialog::onCloseSignal, this, &DetachableTabWidget::attachTab);
    detachedTab->move(pos);
    detachedTab->show();
}

void DetachableTabWidget::attachTab(QWidget * content, QString name)
{
    content->setParent(this);

    int index = addTab(content, name);
    if (index > -1)
        setCurrentIndex(index);
}

ToolDialog::ToolDialog(QWidget *contentWidget, QWidget *parent, Qt::WindowFlags f) :
    QDialog(parent, f)
{
    _contentWidget = contentWidget;

    _contentWidget->setParent(this);
    QVBoxLayout * layout = new QVBoxLayout(this);
    layout->addWidget(_contentWidget);
    this->setLayout(layout);
}

bool ToolDialog::event(QEvent *event)
{
    /**
     * Capture a double click event on the dialog's window frame
     */
    if (event->type() == QEvent::NonClientAreaMouseButtonDblClick) {
        event->accept();
        close();
    }

    return QDialog::event(event);
}

void ToolDialog::closeEvent(QCloseEvent * /*event*/)
{
    emit onCloseSignal(_contentWidget, objectName());
}

DragDropTabBar::DragDropTabBar(QWidget *parent) :
    QTabBar(parent)
{
    setAcceptDrops(true);
    setElideMode(Qt::ElideRight);
    setSelectionBehaviorOnRemove(QTabBar::SelectLeftTab);

    _dragStartPos = QPoint();
    _dragDropPos = QPoint();
    _mouseCursor = QCursor();
    _dragInitiated = false;
}

void DragDropTabBar::mouseDoubleClickEvent(QMouseEvent *event)
{
    event->accept();
    emit onDetachTab(tabAt(event->pos()), _mouseCursor.pos());
}

void DragDropTabBar::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
        _dragStartPos = event->pos();

    _dragDropPos = QPoint(0, 0);
    _dragInitiated = false;

    QTabBar::mousePressEvent(event);
}

void DragDropTabBar::mouseMoveEvent(QMouseEvent *event)
{
    if (!_dragStartPos.isNull() &&
            ((event->pos() - _dragStartPos).manhattanLength() > QApplication::startDragDistance()))
        _dragInitiated = true;

    if ((event->buttons() & Qt::LeftButton) && _dragInitiated) {
        QMouseEvent * finishMouseMove = new QMouseEvent(QEvent::MouseMove, event->pos(), Qt::NoButton, Qt::NoButton, Qt::NoModifier);
        QTabBar::mouseMoveEvent(finishMouseMove);

        QDrag * drag = new QDrag(this);
        QMimeData * mimeData = new QMimeData();
        mimeData->setData("action", "application/tab-detach");
        drag->setMimeData(mimeData);

        QWidget * original = parentWidget();
        if (qobject_cast<DetachableTabWidget *>(original)) {
            DetachableTabWidget * tabWidget = qobject_cast<DetachableTabWidget *>(original);
            original = tabWidget->widget(tabWidget->currentIndex());
        }
        QPixmap pixmap = original->grab();
        QPixmap targetPixmap = QPixmap(pixmap.size());
        targetPixmap.fill(Qt::transparent);

        QPainter painter(&targetPixmap);
        painter.setOpacity(0.85);
        painter.drawPixmap(0, 0, pixmap);
        painter.end();
        drag->setPixmap(targetPixmap);

        Qt::DropAction dropAction = drag->exec(Qt::MoveAction | Qt::CopyAction);
        if (dropAction == Qt::IgnoreAction) {
            event->accept();
            emit onDetachTab(tabAt(_dragStartPos), _mouseCursor.pos());
        } if (dropAction == Qt::MoveAction) {
            if (! _dragDropPos.isNull()) {
                event->accept();
                emit onMoveTab(tabAt(_dragStartPos), tabAt(_dragDropPos));
            }
        }
    } else
        QTabBar::mouseMoveEvent(event);
}

void DragDropTabBar::dragEnterEvent(QDragEnterEvent *event)
{
    const QMimeData * mimeData = event->mimeData();
    QStringList formats = mimeData->formats();

    if (formats.contains("action") && mimeData->data("action") == "application/tab-detach")
        event->acceptProposedAction();
}

void DragDropTabBar::dropEvent(QDropEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    _dragDropPos = event->position().toPoint();
#else
    _dragDropPos = event->pos();
#endif
    QTabBar::dropEvent(event);
}
