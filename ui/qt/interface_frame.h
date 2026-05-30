/** @file
 *
 * Display of interfaces, including their respective data, and the
 * capability to filter interfaces by type
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef INTERFACE_FRAME_H
#define INTERFACE_FRAME_H

#include <config.h>

#include <ui/qt/models/info_proxy_model.h>
#include <ui/qt/models/interface_tree_model.h>
#include <ui/qt/models/interface_sort_filter_model.h>

#include <QFrame>
#include <QHBoxLayout>
#include <QAbstractButton>
#include <QTimer>
#include <QMenu>
#include <QPushButton>

namespace Ui {
class InterfaceFrame;
}

class QResizeEvent;

/**
 * @brief A frame containing the list of interfaces available for capture, along with status and controls.
 */
class InterfaceFrame : public QFrame
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new InterfaceFrame.
     * @param parent The parent widget, defaults to 0.
     */
    explicit InterfaceFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the InterfaceFrame.
     */
    ~InterfaceFrame();

    /**
     * @brief Gets the number of currently hidden interfaces.
     * @return The count of hidden interfaces.
     */
    int interfacesHidden();

    /**
     * @brief Retrieves the selection menu associated with the interface list.
     * @return A pointer to the QMenu.
     */
    QMenu * getSelectionMenu();

    /**
     * @brief Gets the total number of interfaces present.
     * @return The count of present interfaces.
     */
    int interfacesPresent();

    /**
     * @brief Ensures at least one interface is selected, if possible.
     */
    void ensureSelectedInterface();

Q_SIGNALS:
    /**
     * @brief Signal emitted to show the extended capture (extcap) options dialog for a device.
     * @param device_name The name of the device.
     * @param startCaptureOnClose True if capture should start automatically upon closing the options dialog.
     */
    void showExtcapOptions(QString device_name, bool startCaptureOnClose);

    /**
     * @brief Signal emitted to initiate a capture session.
     * @param interfaces A list of interface names to capture from.
     */
    void startCapture(QStringList interfaces);

    /**
     * @brief Signal emitted when the item selection in the interface list changes.
     */
    void itemSelectionChanged();

    /**
     * @brief Signal emitted when the selected interface type filter changes.
     */
    void typeSelectionChanged();

public slots:
#ifdef HAVE_LIBPCAP
    /**
     * @brief Scans for and populates the list of local capture interfaces.
     * @param filter_list An optional list of filters to apply during the scan.
     */
    void scanLocalInterfaces(GList *filter_list = nullptr);
#endif

    /**
     * @brief Updates the UI state based on currently selected interfaces.
     */
    void updateSelectedInterfaces();

    /**
     * @brief Handles updates when the global interface list changes.
     */
    void interfaceListChanged();

    /**
     * @brief Toggles the visibility of hidden interfaces in the list.
     */
    void toggleHiddenInterfaces();

#ifdef HAVE_PCAP_REMOTE
    /**
     * @brief Toggles the visibility of remote interfaces in the list.
     */
    void toggleRemoteInterfaces();
#endif

    /**
     * @brief Triggers the action to run wireshark/tshark on a file.
     */
    void showRunOnFile();

    /**
     * @brief Shows the context menu for the interface list.
     * @param pos The position where the context menu was requested.
     */
    void showContextMenu(QPoint pos);

protected:
    /**
     * @brief Handles hide events for the frame, stopping updates if necessary.
     * @param evt The hide event.
     */
    void hideEvent(QHideEvent *evt);

    /**
     * @brief Handles show events for the frame, resuming updates if necessary.
     * @param evt The show event.
     */
    void showEvent(QShowEvent *evt);

    /**
     * @brief Handles change events; re-fits the interface tree columns when
     *        the widget is re-polished (works around QTBUG-122109).
     * @param evt The change event.
     */
    void changeEvent(QEvent *evt);

    /**
     * @brief Handles resize events; re-fits the interface tree columns so the
     *        name column cap (and the room left for the sparkline) tracks the
     *        available width.
     * @param evt The resize event.
     */
    void resizeEvent(QResizeEvent *evt);

private:

    /**
     * @brief Resets the display parameters of the interface tree.
     */
    void resetInterfaceTreeDisplay();

    /**
     * @brief Re-fits the interface tree columns to their contents.
     */
    void resizeInterfaceColumns();

    /**
     * @brief Checks if the application currently has permissions to capture on local interfaces.
     * @return True if permissions exist, false otherwise.
     */
    bool haveLocalCapturePermissions() const;

    /** Pointer to the generated UI elements. */
    Ui::InterfaceFrame *ui;

    /** Proxy model used for sorting and filtering the interface tree. */
    InterfaceSortFilterModel proxy_model_;

    /** The source model holding the actual interface data. */
    InterfaceTreeModel source_model_;

    /** Proxy model providing specific informational views over the data. */
    InfoProxyModel info_model_;

    /** Maps interface type IDs to their descriptive string representations. */
    QMap<int, QString> ifTypeDescription;

#ifdef HAVE_LIBPCAP
    /** Timer used to periodically trigger statistics updates. */
    QTimer *stat_timer_;
#endif // HAVE_LIBPCAP

private slots:
    /**
     * @brief Slot triggered when the selection in the interface tree changes.
     * @param selected The newly selected items.
     * @param deselected The previously selected items.
     */
    void interfaceTreeSelectionChanged(const QItemSelection & selected, const QItemSelection & deselected);

    /**
     * @brief Slot triggered when an item in the interface tree is double-clicked.
     * @param index The model index of the clicked item.
     */
    void on_interfaceTree_doubleClicked(const QModelIndex &index);

#ifdef HAVE_LIBPCAP
    /**
     * @brief Slot triggered when an item in the interface tree is clicked.
     * @param index The model index of the clicked item.
     */
    void on_interfaceTree_clicked(const QModelIndex &index);
#endif

    /**
     * @brief Slot triggered periodically to update interface statistics (like sparklines).
     */
    void updateStatistics(void);

    /**
     * @brief Slot triggered when a generic action button is toggled.
     * @param checked The new checked state.
     */
    void actionButton_toggled(bool checked);

    /**
     * @brief Slot triggered when an interface type filtering button is activated.
     */
    void triggeredIfTypeButton();

    /**
     * @brief Slot triggered when a hyperlink within the warning label is activated.
     * @param link The URL of the activated link.
     */
    void on_warningLabel_linkActivated(const QString &link);
};

#endif // INTERFACE_FRAME_H
