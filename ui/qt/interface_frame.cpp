/* interface_frame.cpp
 * Display of interfaces, including their respective data, and the
 * capability to filter interfaces by type
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"
#include <ui_interface_frame.h>

#include "caputils/capture_ifinfo.h"

#ifdef Q_OS_WIN
#include "caputils/capture-wpcap.h"
#endif

#include "ui/qt/interface_frame.h"
#include <ui/qt/simple_dialog.h>
#include <ui/qt/wireshark_application.h>

#include <ui/qt/models/interface_tree_model.h>
#include <ui/qt/models/sparkline_delegate.h>

#include <ui/qt/utils/tango_colors.h>


#include "extcap.h"

#include <ui/recent.h>
#include <wsutil/utf8_entities.h>

#include <QDesktopServices>
#include <QFrame>
#include <QHBoxLayout>
#include <QItemSelection>
#include <QLabel>
#include <QPushButton>
#include <QUrl>

#include <epan/prefs.h>

#define BTN_IFTYPE_PROPERTY "ifType"

#ifdef HAVE_LIBPCAP
const int stat_update_interval_ = 1000; // ms
#endif
const char *no_capture_link = "#no_capture";

InterfaceFrame::InterfaceFrame(QWidget * parent)
: QFrame(parent),
  ui(new Ui::InterfaceFrame)
  , proxy_model_(Q_NULLPTR)
  , source_model_(Q_NULLPTR)
  , info_model_(this)
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
                      "QLabel {"
                      "  border-radius: 0.5em;"
                      "  padding: 0.33em;"
                      "  margin-bottom: 0.25em;"
                      // We might want to transition this to normal colors this after a timeout.
                      "  color: #%1;"
                      "  background-color: #%2;"
                      "}"
                    )
                  .arg(ws_css_warn_text, 6, 16, QChar('0'))
                  .arg(ws_css_warn_background, 6, 16, QChar('0')));

    ui->warningLabel->hide();

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
    ifTypeDescription.insert(IF_EXTCAP, tr("External Capture"));
    ifTypeDescription.insert(IF_VIRTUAL, tr ("Virtual"));

    QList<InterfaceTreeColumns> columns;
    columns.append(IFTREE_COL_EXTCAP);
    columns.append(IFTREE_COL_DISPLAY_NAME);
    columns.append(IFTREE_COL_STATS);
    proxy_model_.setColumns(columns);
    proxy_model_.setStoreOnChange(true);
    proxy_model_.setSourceModel(&source_model_);

    info_model_.setSourceModel(&proxy_model_);
    info_model_.setColumn(columns.indexOf(IFTREE_COL_STATS));

    ui->interfaceTree->setModel(&info_model_);

    ui->interfaceTree->setItemDelegateForColumn(proxy_model_.mapSourceToColumn(IFTREE_COL_STATS), new SparkLineDelegate(this));

    ui->interfaceTree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(ui->interfaceTree, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showContextMenu(QPoint)));

    connect(wsApp, SIGNAL(appInitialized()), this, SLOT(interfaceListChanged()));
    connect(wsApp, SIGNAL(localInterfaceListChanged()), this, SLOT(interfaceListChanged()));

    connect(ui->interfaceTree->selectionModel(), SIGNAL(selectionChanged(const QItemSelection &, const QItemSelection &)),
            this, SLOT(interfaceTreeSelectionChanged(const QItemSelection &, const QItemSelection &)));
}

InterfaceFrame::~InterfaceFrame()
{
    delete ui;
}

QMenu * InterfaceFrame::getSelectionMenu()
{
    QMenu * contextMenu = new QMenu(this);
    QList<int> typesDisplayed = proxy_model_.typesDisplayed();

    QMap<int, QString>::const_iterator it = ifTypeDescription.constBegin();
    while (it != ifTypeDescription.constEnd())
    {
        int ifType = it.key();

        if (typesDisplayed.contains(ifType))
        {
            QAction *endp_action = new QAction(it.value(), this);
            endp_action->setData(QVariant::fromValue(ifType));
            endp_action->setCheckable(true);
            endp_action->setChecked(proxy_model_.isInterfaceTypeShown(ifType));
            connect(endp_action, SIGNAL(triggered()), this, SLOT(triggeredIfTypeButton()));
            contextMenu->addAction(endp_action);
        }
        ++it;
    }

#ifdef HAVE_PCAP_REMOTE
    if (proxy_model_.remoteInterfacesExist())
    {
        QAction * toggleRemoteAction = new QAction(tr("Remote interfaces"), this);
        toggleRemoteAction->setCheckable(true);
        toggleRemoteAction->setChecked(! proxy_model_.remoteDisplay());
        connect(toggleRemoteAction, SIGNAL(triggered()), this, SLOT(toggleRemoteInterfaces()));
        contextMenu->addAction(toggleRemoteAction);
    }
#endif

#if 0
    // Disabled until bug 13354 is fixed
    contextMenu->addSeparator();
    QAction * toggleHideAction = new QAction(tr("Show hidden interfaces"), this);
    toggleHideAction->setCheckable(true);
    toggleHideAction->setChecked(! proxy_model_->filterHidden());
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHiddenInterfaces()));
    contextMenu->addAction(toggleHideAction);
#endif

    return contextMenu;
}

int InterfaceFrame::interfacesHidden()
{
    return proxy_model_.interfacesHidden();
}

int InterfaceFrame::interfacesPresent()
{
    return source_model_.rowCount() - proxy_model_.interfacesHidden();
}

void InterfaceFrame::ensureSelectedInterface()
{
#ifdef HAVE_LIBPCAP
    if (interfacesPresent() < 1) return;

    if (source_model_.selectedDevices().count() < 1) {
        QModelIndex first_idx = info_model_.mapFromSource(proxy_model_.index(0, 0));
        ui->interfaceTree->setCurrentIndex(first_idx);
    }

    ui->interfaceTree->setFocus();
#endif
}

void InterfaceFrame::hideEvent(QHideEvent *) {
#ifdef HAVE_LIBPCAP
    if (stat_timer_)
        stat_timer_->stop();
    source_model_.stopStatistic();
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
    if (ifType.isValid())
    {
        proxy_model_.setInterfaceTypeVisible(ifType.toInt(), checked);
    }

    resetInterfaceTreeDisplay();
}

void InterfaceFrame::triggeredIfTypeButton()
{
    QAction *sender = qobject_cast<QAction *>(QObject::sender());
    if (sender)
    {
        int ifType = sender->data().value<int>();
        proxy_model_.toggleTypeVisibility(ifType);

        resetInterfaceTreeDisplay();
        emit typeSelectionChanged();
    }
}

void InterfaceFrame::interfaceListChanged()
{
    info_model_.clearInfos();
    if (prefs.capture_no_extcap)
        info_model_.appendInfo(tr("External capture interfaces disabled."));

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
    proxy_model_.toggleFilterHidden();

    emit typeSelectionChanged();
}

#ifdef HAVE_PCAP_REMOTE
void InterfaceFrame::toggleRemoteInterfaces()
{
    proxy_model_.toggleRemoteDisplay();
    emit typeSelectionChanged();
}
#endif

void InterfaceFrame::resetInterfaceTreeDisplay()
{
    ui->warningLabel->hide();
    ui->warningLabel->clear();

#ifdef HAVE_LIBPCAP
#ifdef Q_OS_WIN
    if (!has_wpcap) {
        ui->warningLabel->setText(tr(
            "<p>"
            "Local interfaces are unavailable because no packet capture driver is installed."
            "</p><p>"
            "You can fix this by installing <a href=\"https://nmap.org/npcap/\">Npcap</a>"
            " or <a href=\"https://www.winpcap.org/install/default.htm\">WinPcap</a>."
            "</p>"));
    } else if (!npf_sys_is_running()) {
        ui->warningLabel->setText(tr(
            "<p>"
            "Local interfaces are unavailable because the packet capture driver isn't loaded."
            "</p><p>"
            "You can fix this by running <pre>net start npcap</pre> if you have Npcap installed"
            " or <pre>net start npf</pre> if you have WinPcap installed."
            " Both commands must be run as Administrator."
            "</p>"));
    }
#endif

    if (!haveLocalCapturePermissions())
    {
#ifdef Q_OS_MAC
        QString install_chmodbpf_path = wsApp->applicationDirPath() + "/../Resources/Extras/Install ChmodBPF.pkg";
        ui->warningLabel->setText(tr(
            "<p>"
            "You don't have permission to capture on local interfaces."
            "</p><p>"
            "You can fix this by <a href=\"file://%1\">installing ChmodBPF</a>."
            "</p>")
            .arg(install_chmodbpf_path));
#else
        ui->warningLabel->setText(tr("You don't have permission to capture on local interfaces."));
#endif
    }

    if (proxy_model_.rowCount() == 0)
    {
        ui->warningLabel->setText(tr("No interfaces found."));
        ui->warningLabel->setText(proxy_model_.interfaceError());
        if (prefs.capture_no_interface_load) {
            ui->warningLabel->setText(tr("Interfaces not loaded (due to preference). Go to Capture " UTF8_RIGHTWARDS_ARROW " Refresh Interfaces to load."));
        }
    }

    // XXX Should we have a separate recent pref for each message?
    if (!ui->warningLabel->text().isEmpty() && recent.sys_warn_if_no_capture)
    {
        QString warning_text = ui->warningLabel->text();
        warning_text.append(QString("<p><a href=\"%1\">%2</a></p>")
                            .arg(no_capture_link)
                            .arg(SimpleDialog::dontShowThisAgain()));
        ui->warningLabel->setText(warning_text);

        ui->warningLabel->show();
    }
#endif // HAVE_LIBPCAP

    if (proxy_model_.rowCount() > 0)
    {
        ui->interfaceTree->show();
        ui->interfaceTree->resizeColumnToContents(proxy_model_.mapSourceToColumn(IFTREE_COL_EXTCAP));
        ui->interfaceTree->resizeColumnToContents(proxy_model_.mapSourceToColumn(IFTREE_COL_DISPLAY_NAME));
        ui->interfaceTree->resizeColumnToContents(proxy_model_.mapSourceToColumn(IFTREE_COL_STATS));
    }
    else
    {
        ui->interfaceTree->hide();
    }
}

// XXX Should this be in caputils/capture-pcap-util.[ch]?
bool InterfaceFrame::haveLocalCapturePermissions() const
{
#ifdef Q_OS_MAC
    QFileInfo bpf0_fi = QFileInfo("/dev/bpf0");
    return bpf0_fi.isReadable() && bpf0_fi.isWritable();
#else
    // XXX Add checks for other platforms.
    return true;
#endif
}

void InterfaceFrame::updateSelectedInterfaces()
{
    if (source_model_.rowCount() == 0)
        return;
#ifdef HAVE_LIBPCAP
    QItemSelection sourceSelection = source_model_.selectedDevices();
    QItemSelection mySelection = info_model_.mapSelectionFromSource(proxy_model_.mapSelectionFromSource(sourceSelection));

    ui->interfaceTree->selectionModel()->clearSelection();
    ui->interfaceTree->selectionModel()->select(mySelection, QItemSelectionModel::SelectCurrent);
#endif
}

void InterfaceFrame::interfaceTreeSelectionChanged(const QItemSelection & selected, const QItemSelection & deselected)
{
    if (selected.count() == 0 && deselected.count() == 0)
        return;
    if (source_model_.rowCount() == 0)
        return;

#ifdef HAVE_LIBPCAP
    /* Take all selected interfaces, not just the newly ones */
    QItemSelection allSelected = ui->interfaceTree->selectionModel()->selection();
    QItemSelection sourceSelection = proxy_model_.mapSelectionToSource(info_model_.mapSelectionToSource(allSelected));

    if (source_model_.updateSelectedDevices(sourceSelection))
        emit itemSelectionChanged();
#endif
}

void InterfaceFrame::on_interfaceTree_doubleClicked(const QModelIndex &index)
{
    QModelIndex realIndex = proxy_model_.mapToSource(info_model_.mapToSource(index));

    if (! realIndex.isValid())
        return;

#ifdef HAVE_LIBPCAP

    QString device_name = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_NAME).toString();
    QString extcap_string = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_EXTCAP_PATH).toString();

    /* We trust the string here. If this interface is really extcap, the string is
     * being checked immediatly before the dialog is being generated */
    if (extcap_string.length() > 0)
    {
        /* this checks if configuration is required and not yet provided or saved via prefs */
        if (extcap_has_configuration((const char *)(device_name.toStdString().c_str()), TRUE))
        {
            emit showExtcapOptions(device_name);
            return;
        }
    }
#endif
    emit startCapture();
}

#ifdef HAVE_LIBPCAP
void InterfaceFrame::on_interfaceTree_clicked(const QModelIndex &index)
{
    if (index.column() == 0)
    {
        QModelIndex realIndex = proxy_model_.mapToSource(info_model_.mapToSource(index));

        if (! realIndex.isValid())
            return;

        QString device_name = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_NAME).toString();
        QString extcap_string = source_model_.getColumnContent(realIndex.row(), IFTREE_COL_EXTCAP_PATH).toString();

        /* We trust the string here. If this interface is really extcap, the string is
         * being checked immediatly before the dialog is being generated */
        if (extcap_string.length() > 0)
        {
            /* this checks if configuration is required and not yet provided or saved via prefs */
            if (extcap_has_configuration((const char *)(device_name.toStdString().c_str()), FALSE))
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
    if (source_model_.rowCount() == 0)
        return;

#ifdef HAVE_LIBPCAP

    for (int idx = 0; idx < proxy_model_.rowCount(); idx++)
    {
        QModelIndex selectIndex = info_model_.mapFromSource(proxy_model_.mapFromSource(source_model_.index(idx, 0)));

        /* Proxy model has not masked out the interface */
        if (selectIndex.isValid())
            source_model_.updateStatistic(idx);
    }

#endif
}

/* Proxy Method so we do not need to expose the source model */
void InterfaceFrame::getPoints(int idx, PointList * pts)
{
    source_model_.getPoints(idx, pts);
}

void InterfaceFrame::showRunOnFile(void)
{
    ui->warningLabel->setText("Interfaces not loaded on startup (run on capture file). Go to Capture -> Refresh Interfaces to load.");
}

void InterfaceFrame::showContextMenu(QPoint pos)
{
    QMenu ctx_menu;

    ctx_menu.addAction(tr("Start capture"), this, SIGNAL(startCapture()));
    ctx_menu.exec(ui->interfaceTree->mapToGlobal(pos));
}

void InterfaceFrame::on_warningLabel_linkActivated(const QString &link)
{
    if (link.compare(no_capture_link) == 0) {
        recent.sys_warn_if_no_capture = FALSE;
        resetInterfaceTreeDisplay();
    } else {
        QDesktopServices::openUrl(QUrl(link));
    }
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
