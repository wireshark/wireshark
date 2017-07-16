/* interface_frame.cpp
 * Display of interfaces, including their respective data, and the
 * capability to filter interfaces by type
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
#include "config.h"
#include <ui_interface_frame.h>

#include "caputils/capture_ifinfo.h"
#include "ui/qt/interface_frame.h"
#include "ui/qt/interface_tree_model.h"

#include "sparkline_delegate.h"
#include "wireshark_application.h"

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif

#include <QFrame>
#include <QPushButton>
#include <QHBoxLayout>
#include <QLabel>
#include <QItemSelection>

#define BTN_IFTYPE_PROPERTY "ifType"

#ifdef HAVE_LIBPCAP
const int stat_update_interval_ = 1000; // ms
#endif

InterfaceFrame::InterfaceFrame(QWidget * parent)
: AccordionFrame(parent),
  ui(new Ui::InterfaceFrame)
#ifdef HAVE_LIBPCAP
  ,stat_timer_(NULL)
#endif // HAVE_LIBPCAP
{
    ui->setupUi(this);

    setStyleSheet(QString(
                      "QFrame {"
                      "  border: 0;"
                      "}"
                      "QTreeView {"
                      "  border: 0;"
                      "}"
                    ));

#ifdef Q_OS_MAC
    ui->interfaceTree->setAttribute(Qt::WA_MacShowFocusRect, false);
#endif

    /* TODO: There must be a better way to do this */
    ifTypeDescription.insert(IF_WIRED, tr("Wired"));
    ifTypeDescription.insert(IF_AIRPCAP, tr("AirPCAP"));
    ifTypeDescription.insert(IF_PIPE, tr("Pipe"));
    ifTypeDescription.insert(IF_STDIN, tr("STDIN"));
    ifTypeDescription.insert(IF_BLUETOOTH, tr("Bluetooth"));
    ifTypeDescription.insert(IF_WIRELESS, tr("Wireless"));
    ifTypeDescription.insert(IF_DIALUP, tr("Dial-Up"));
    ifTypeDescription.insert(IF_USB, tr("USB"));
#ifdef HAVE_EXTCAP
    ifTypeDescription.insert(IF_EXTCAP, tr("External Capture"));
#endif
    ifTypeDescription.insert(IF_VIRTUAL, tr ("Virtual"));

    proxyModel = new InterfaceSortFilterModel(this);
    sourceModel = new InterfaceTreeModel(this);

    QList<InterfaceTreeColumns> columns;
#ifdef HAVE_EXTCAP
    columns.append(IFTREE_COL_EXTCAP);
#endif
    columns.append(IFTREE_COL_NAME);
    columns.append(IFTREE_COL_STATS);
    proxyModel->setColumns(columns);
    proxyModel->setStoreOnChange(true);
    proxyModel->setSourceModel(sourceModel);
    ui->interfaceTree->setModel(proxyModel);

    ui->interfaceTree->setItemDelegateForColumn(proxyModel->mapSourceToColumn(IFTREE_COL_STATS), new SparkLineDelegate(this));

    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(interfaceListChanged()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));

    connect(ui->interfaceTree->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
            this, SLOT(interfaceTreeSelectionChanged(const QItemSelection &, const QItemSelection &)));
}

InterfaceFrame::~InterfaceFrame()
{
    delete sourceModel;
    delete proxyModel;
    delete ui;
}

QMenu * InterfaceFrame::getSelectionMenu()
{
    QMenu * contextMenu = new QMenu(this);
    QList<int> typesDisplayed = proxyModel->typesDisplayed();

    QMap<int, QString>::const_iterator it = ifTypeDescription.constBegin();
    while(it != ifTypeDescription.constEnd())
    {
        int ifType = it.key();

        if ( typesDisplayed.contains(ifType) )
        {
            QAction *endp_action = new QAction(it.value(), this);
            endp_action->setData(qVariantFromValue(ifType));
            endp_action->setCheckable(true);
            endp_action->setChecked(proxyModel->isInterfaceTypeShown(ifType));
            connect(endp_action, SIGNAL(triggered()), this, SLOT(triggeredIfTypeButton()));
            contextMenu->addAction(endp_action);
        }
        ++it;
    }

#ifdef HAVE_PCAP_REMOTE
    if ( proxyModel->remoteInterfacesExist() )
    {
        QAction * toggleRemoteAction = new QAction(tr("Remote interfaces"), this);
        toggleRemoteAction->setCheckable(true);
        toggleRemoteAction->setChecked(! proxyModel->remoteDisplay());
        connect(toggleRemoteAction, SIGNAL(triggered()), this, SLOT(toggleRemoteInterfaces()));
        contextMenu->addAction(toggleRemoteAction);
    }
#endif

#if 0
    // Disabled until bug 13354 is fixed
    contextMenu->addSeparator();
    QAction * toggleHideAction = new QAction(tr("Show hidden interfaces"), this);
    toggleHideAction->setCheckable(true);
    toggleHideAction->setChecked(! proxyModel->filterHidden());
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHiddenInterfaces()));
    contextMenu->addAction(toggleHideAction);
#endif

    return contextMenu;
}

int InterfaceFrame::interfacesHidden()
{
    return proxyModel->interfacesHidden();
}

int InterfaceFrame::interfacesPresent()
{
    return sourceModel->rowCount() - proxyModel->interfacesHidden();
}

void InterfaceFrame::ensureSelectedInterface()
{
#ifdef HAVE_LIBPCAP
    if (interfacesPresent() < 1) return;

    if (sourceModel->selectedDevices().count() < 1) {
        QModelIndex first_idx = proxyModel->index(0, 0);
        ui->interfaceTree->setCurrentIndex(first_idx);
    }

    ui->interfaceTree->setFocus();
#endif
}

void InterfaceFrame::hideEvent(QHideEvent *) {
#ifdef HAVE_LIBPCAP
    if (stat_timer_)
        stat_timer_->stop();
    sourceModel->stopStatistic();
#endif // HAVE_LIBPCAP
}

void InterfaceFrame::showEvent(QShowEvent *) {

#ifdef HAVE_LIBPCAP
    if (stat_timer_)
        stat_timer_->start(stat_update_interval_);
#endif // HAVE_LIBPCAP
}

void InterfaceFrame::actionButton_toggled(bool checked)
{
    QVariant ifType = sender()->property(BTN_IFTYPE_PROPERTY);
    if ( ifType.isValid() )
    {
        proxyModel->setInterfaceTypeVisible(ifType.toInt(), checked);
    }

    resetInterfaceTreeDisplay();
}

void InterfaceFrame::triggeredIfTypeButton()
{
    QAction *sender = qobject_cast<QAction *>(QObject::sender());
    if ( sender )
    {
        int ifType = sender->data().value<int>();
        proxyModel->toggleTypeVisibility(ifType);

        resetInterfaceTreeDisplay();
        emit typeSelectionChanged();
    }
}

void InterfaceFrame::interfaceListChanged()
{
    resetInterfaceTreeDisplay();
    // Ensure that device selection is consistent with the displayed selection.
    updateSelectedInterfaces();

#ifdef HAVE_LIBPCAP
    if (!stat_timer_) {
        updateStatistics();
        stat_timer_ = new QTimer(this);
        connect(stat_timer_, SIGNAL(timeout()), this, SLOT(updateStatistics()));
        stat_timer_->start(stat_update_interval_);
    }
#endif
}

void InterfaceFrame::toggleHiddenInterfaces()
{
    proxyModel->toggleFilterHidden();

    emit typeSelectionChanged();
}

#ifdef HAVE_PCAP_REMOTE
void InterfaceFrame::toggleRemoteInterfaces()
{
    proxyModel->toggleRemoteDisplay();
    emit typeSelectionChanged();
}
#endif

void InterfaceFrame::resetInterfaceTreeDisplay()
{
    if ( proxyModel->rowCount() == 0 )
    {
        ui->interfaceTree->setHidden(true);
        ui->lblNoInterfaces->setHidden(false);

        ui->lblNoInterfaces->setText( proxyModel->interfaceError() );
    }
    else
    {
        ui->interfaceTree->setHidden(false);
        ui->lblNoInterfaces->setHidden(true);
#ifdef HAVE_EXTCAP
        ui->interfaceTree->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_EXTCAP));
#endif
        ui->interfaceTree->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_NAME));
        ui->interfaceTree->resizeColumnToContents(proxyModel->mapSourceToColumn(IFTREE_COL_STATS));
    }
}

void InterfaceFrame::updateSelectedInterfaces()
{
    if ( sourceModel->rowCount() == 0 )
        return;
#ifdef HAVE_LIBPCAP
    QItemSelection sourceSelection = sourceModel->selectedDevices();
    QItemSelection mySelection = proxyModel->mapSelectionFromSource(sourceSelection);

    ui->interfaceTree->selectionModel()->clearSelection();
    ui->interfaceTree->selectionModel()->select(mySelection, QItemSelectionModel::SelectCurrent );
#endif
}

void InterfaceFrame::interfaceTreeSelectionChanged(const QItemSelection & selected, const QItemSelection & deselected)
{
    if (selected.count() == 0 && deselected.count() == 0)
        return;
    if ( sourceModel->rowCount() == 0 )
        return;

#ifdef HAVE_LIBPCAP
    /* Take all selected interfaces, not just the newly ones */
    QItemSelection allSelected = ui->interfaceTree->selectionModel()->selection();
    QItemSelection sourceSelection = proxyModel->mapSelectionToSource(allSelected);

    if ( sourceModel->updateSelectedDevices(sourceSelection) )
        emit itemSelectionChanged();
#endif
}

void InterfaceFrame::on_interfaceTree_doubleClicked(const QModelIndex &index)
{
    QModelIndex realIndex = proxyModel->mapToSource(index);

    if ( ! realIndex.isValid() )
        return;

#if defined(HAVE_EXTCAP) && defined(HAVE_LIBPCAP)

    QString device_name = sourceModel->getColumnContent(realIndex.row(), IFTREE_COL_INTERFACE_NAME).toString();
    QString extcap_string = sourceModel->getColumnContent(realIndex.row(), IFTREE_COL_EXTCAP_PATH).toString();

    /* We trust the string here. If this interface is really extcap, the string is
     * being checked immediatly before the dialog is being generated */
    if ( extcap_string.length() > 0 )
    {
        /* this checks if configuration is required and not yet provided or saved via prefs */
        if ( extcap_has_configuration((const char *)(device_name.toStdString().c_str()), TRUE) )
        {
            emit showExtcapOptions(device_name);
            return;
        }
    }
#endif
    emit startCapture();
}

#if defined(HAVE_EXTCAP) && defined(HAVE_LIBPCAP)
void InterfaceFrame::on_interfaceTree_clicked(const QModelIndex &index)
{
    if ( index.column() == 0 )
    {
        QModelIndex realIndex = proxyModel->mapToSource(index);

        if ( ! realIndex.isValid() )
            return;

        QString device_name = sourceModel->getColumnContent(realIndex.row(), IFTREE_COL_INTERFACE_NAME).toString();
        QString extcap_string = sourceModel->getColumnContent(realIndex.row(), IFTREE_COL_EXTCAP_PATH).toString();

        /* We trust the string here. If this interface is really extcap, the string is
         * being checked immediatly before the dialog is being generated */
        if ( extcap_string.length() > 0 )
        {
            /* this checks if configuration is required and not yet provided or saved via prefs */
            if ( extcap_has_configuration((const char *)(device_name.toStdString().c_str()), FALSE) )
            {
                emit showExtcapOptions(device_name);
                return;
            }
        }
    }
}
#endif

void InterfaceFrame::updateStatistics(void)
{
    if ( sourceModel->rowCount() == 0 )
        return;

#ifdef HAVE_LIBPCAP

    for( int idx = 0; idx < proxyModel->rowCount(); idx++ )
    {
        QModelIndex selectIndex = proxyModel->mapFromSource(sourceModel->index(idx, 0));

        /* Proxy model has not masked out the interface */
        if ( selectIndex.isValid() )
            sourceModel->updateStatistic(idx);
    }

#endif
}

/* Proxy Method so we do not need to expose the source model */
void InterfaceFrame::getPoints(int idx, PointList * pts)
{
    sourceModel->getPoints(idx, pts);
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
