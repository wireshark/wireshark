/********************************************************************************
** Form generated from reading UI file 'bluetooth_devices_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_BLUETOOTH_DEVICES_DIALOG_H
#define UI_BLUETOOTH_DEVICES_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QComboBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_BluetoothDevicesDialog
{
public:
    QAction *actionCopy_Cell;
    QAction *actionCopy_Rows;
    QAction *actionCopy_All;
    QAction *actionSave_as_image;
    QAction *actionMark_Unmark_Row;
    QAction *actionMark_Unmark_Cell;
    QVBoxLayout *verticalLayout;
    QTreeWidget *tableTreeWidget;
    QHBoxLayout *horizontalLayout;
    QComboBox *interfaceComboBox;
    QCheckBox *showInformationStepsCheckBox;
    QLabel *hintLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *BluetoothDevicesDialog)
    {
        if (BluetoothDevicesDialog->objectName().isEmpty())
            BluetoothDevicesDialog->setObjectName(QString::fromUtf8("BluetoothDevicesDialog"));
        BluetoothDevicesDialog->resize(880, 477);
        BluetoothDevicesDialog->setBaseSize(QSize(0, 0));
        actionCopy_Cell = new QAction(BluetoothDevicesDialog);
        actionCopy_Cell->setObjectName(QString::fromUtf8("actionCopy_Cell"));
        actionCopy_Rows = new QAction(BluetoothDevicesDialog);
        actionCopy_Rows->setObjectName(QString::fromUtf8("actionCopy_Rows"));
        actionCopy_All = new QAction(BluetoothDevicesDialog);
        actionCopy_All->setObjectName(QString::fromUtf8("actionCopy_All"));
        actionSave_as_image = new QAction(BluetoothDevicesDialog);
        actionSave_as_image->setObjectName(QString::fromUtf8("actionSave_as_image"));
        actionMark_Unmark_Row = new QAction(BluetoothDevicesDialog);
        actionMark_Unmark_Row->setObjectName(QString::fromUtf8("actionMark_Unmark_Row"));
        actionMark_Unmark_Cell = new QAction(BluetoothDevicesDialog);
        actionMark_Unmark_Cell->setObjectName(QString::fromUtf8("actionMark_Unmark_Cell"));
        verticalLayout = new QVBoxLayout(BluetoothDevicesDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        tableTreeWidget = new QTreeWidget(BluetoothDevicesDialog);
        tableTreeWidget->setObjectName(QString::fromUtf8("tableTreeWidget"));
        tableTreeWidget->setContextMenuPolicy(Qt::CustomContextMenu);
        tableTreeWidget->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tableTreeWidget->setTextElideMode(Qt::ElideMiddle);
        tableTreeWidget->setRootIsDecorated(false);
        tableTreeWidget->setItemsExpandable(false);
        tableTreeWidget->setSortingEnabled(true);
        tableTreeWidget->header()->setCascadingSectionResizes(false);
        tableTreeWidget->header()->setHighlightSections(false);
        tableTreeWidget->header()->setProperty("showSortIndicator", QVariant(true));

        verticalLayout->addWidget(tableTreeWidget);

        horizontalLayout = new QHBoxLayout();
#ifndef Q_OS_MAC
        horizontalLayout->setSpacing(-1);
#endif
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        horizontalLayout->setSizeConstraint(QLayout::SetDefaultConstraint);
        horizontalLayout->setContentsMargins(-1, -1, -1, 0);
        interfaceComboBox = new QComboBox(BluetoothDevicesDialog);
        interfaceComboBox->addItem(QString());
        interfaceComboBox->setObjectName(QString::fromUtf8("interfaceComboBox"));
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(interfaceComboBox->sizePolicy().hasHeightForWidth());
        interfaceComboBox->setSizePolicy(sizePolicy);
        interfaceComboBox->setMinimumSize(QSize(350, 0));

        horizontalLayout->addWidget(interfaceComboBox);

        showInformationStepsCheckBox = new QCheckBox(BluetoothDevicesDialog);
        showInformationStepsCheckBox->setObjectName(QString::fromUtf8("showInformationStepsCheckBox"));
        showInformationStepsCheckBox->setChecked(false);

        horizontalLayout->addWidget(showInformationStepsCheckBox);


        verticalLayout->addLayout(horizontalLayout);

        hintLabel = new QLabel(BluetoothDevicesDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));

        verticalLayout->addWidget(hintLabel);

        buttonBox = new QDialogButtonBox(BluetoothDevicesDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(BluetoothDevicesDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), BluetoothDevicesDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), BluetoothDevicesDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(BluetoothDevicesDialog);
    } // setupUi

    void retranslateUi(QDialog *BluetoothDevicesDialog)
    {
        BluetoothDevicesDialog->setWindowTitle(QApplication::translate("BluetoothDevicesDialog", "Bluetooth Devices", nullptr));
        actionCopy_Cell->setText(QApplication::translate("BluetoothDevicesDialog", "Copy Cell", nullptr));
        actionCopy_Rows->setText(QApplication::translate("BluetoothDevicesDialog", "Copy Rows", nullptr));
        actionCopy_All->setText(QApplication::translate("BluetoothDevicesDialog", "Copy All", nullptr));
        actionSave_as_image->setText(QApplication::translate("BluetoothDevicesDialog", "Save as image", nullptr));
        actionMark_Unmark_Row->setText(QApplication::translate("BluetoothDevicesDialog", "Mark/Unmark Row", nullptr));
#ifndef QT_NO_TOOLTIP
        actionMark_Unmark_Row->setToolTip(QApplication::translate("BluetoothDevicesDialog", "Mark/Unmark Row", nullptr));
#endif // QT_NO_TOOLTIP
#ifndef QT_NO_SHORTCUT
        actionMark_Unmark_Row->setShortcut(QApplication::translate("BluetoothDevicesDialog", "CtrlM", nullptr));
#endif // QT_NO_SHORTCUT
        actionMark_Unmark_Cell->setText(QApplication::translate("BluetoothDevicesDialog", "Mark/Unmark Cell", nullptr));
        QTreeWidgetItem *___qtreewidgetitem = tableTreeWidget->headerItem();
        ___qtreewidgetitem->setText(8, QApplication::translate("BluetoothDevicesDialog", "Is Local Adapter", nullptr));
        ___qtreewidgetitem->setText(7, QApplication::translate("BluetoothDevicesDialog", "HCI Revision", nullptr));
        ___qtreewidgetitem->setText(6, QApplication::translate("BluetoothDevicesDialog", "HCI Version", nullptr));
        ___qtreewidgetitem->setText(5, QApplication::translate("BluetoothDevicesDialog", "Manufacturer", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("BluetoothDevicesDialog", "LMP Subversion", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("BluetoothDevicesDialog", "LMP Version", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("BluetoothDevicesDialog", "Name", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("BluetoothDevicesDialog", "OUI", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("BluetoothDevicesDialog", "BD_ADDR", nullptr));
        interfaceComboBox->setItemText(0, QApplication::translate("BluetoothDevicesDialog", "All Interfaces", nullptr));

        showInformationStepsCheckBox->setText(QApplication::translate("BluetoothDevicesDialog", "Show information steps", nullptr));
        hintLabel->setText(QApplication::translate("BluetoothDevicesDialog", "%1 items; Right click for more option; Double click for device details", nullptr));
    } // retranslateUi

};

namespace Ui {
    class BluetoothDevicesDialog: public Ui_BluetoothDevicesDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_BLUETOOTH_DEVICES_DIALOG_H
