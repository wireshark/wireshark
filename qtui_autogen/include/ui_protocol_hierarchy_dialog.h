/********************************************************************************
** Form generated from reading UI file 'protocol_hierarchy_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_PROTOCOL_HIERARCHY_DIALOG_H
#define UI_PROTOCOL_HIERARCHY_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QAction>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHeaderView>
#include <QtWidgets/QLabel>
#include <QtWidgets/QTreeWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_ProtocolHierarchyDialog
{
public:
    QAction *actionCopyAsCsv;
    QAction *actionCopyAsYaml;
    QVBoxLayout *verticalLayout;
    QTreeWidget *hierStatsTreeWidget;
    QLabel *hintLabel;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *ProtocolHierarchyDialog)
    {
        if (ProtocolHierarchyDialog->objectName().isEmpty())
            ProtocolHierarchyDialog->setObjectName(QString::fromUtf8("ProtocolHierarchyDialog"));
        ProtocolHierarchyDialog->resize(620, 480);
        actionCopyAsCsv = new QAction(ProtocolHierarchyDialog);
        actionCopyAsCsv->setObjectName(QString::fromUtf8("actionCopyAsCsv"));
        actionCopyAsYaml = new QAction(ProtocolHierarchyDialog);
        actionCopyAsYaml->setObjectName(QString::fromUtf8("actionCopyAsYaml"));
        verticalLayout = new QVBoxLayout(ProtocolHierarchyDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        hierStatsTreeWidget = new QTreeWidget(ProtocolHierarchyDialog);
        hierStatsTreeWidget->setObjectName(QString::fromUtf8("hierStatsTreeWidget"));
        hierStatsTreeWidget->setUniformRowHeights(true);
        hierStatsTreeWidget->header()->setDefaultSectionSize(50);
        hierStatsTreeWidget->header()->setProperty("showSortIndicator", QVariant(false));

        verticalLayout->addWidget(hierStatsTreeWidget);

        hintLabel = new QLabel(ProtocolHierarchyDialog);
        hintLabel->setObjectName(QString::fromUtf8("hintLabel"));
        hintLabel->setWordWrap(true);

        verticalLayout->addWidget(hintLabel);

        buttonBox = new QDialogButtonBox(ProtocolHierarchyDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(ProtocolHierarchyDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), ProtocolHierarchyDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), ProtocolHierarchyDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(ProtocolHierarchyDialog);
    } // setupUi

    void retranslateUi(QDialog *ProtocolHierarchyDialog)
    {
        ProtocolHierarchyDialog->setWindowTitle(QApplication::translate("ProtocolHierarchyDialog", "Dialog", nullptr));
        actionCopyAsCsv->setText(QApplication::translate("ProtocolHierarchyDialog", "Copy as CSV", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsCsv->setToolTip(QApplication::translate("ProtocolHierarchyDialog", "Copy stream list as CSV.", nullptr));
#endif // QT_NO_TOOLTIP
        actionCopyAsYaml->setText(QApplication::translate("ProtocolHierarchyDialog", "Copy as YAML", nullptr));
#ifndef QT_NO_TOOLTIP
        actionCopyAsYaml->setToolTip(QApplication::translate("ProtocolHierarchyDialog", "Copy stream list as YAML.", nullptr));
#endif // QT_NO_TOOLTIP
        QTreeWidgetItem *___qtreewidgetitem = hierStatsTreeWidget->headerItem();
        ___qtreewidgetitem->setText(8, QApplication::translate("ProtocolHierarchyDialog", "End Bits/s", nullptr));
        ___qtreewidgetitem->setText(7, QApplication::translate("ProtocolHierarchyDialog", "End Bytes", nullptr));
        ___qtreewidgetitem->setText(6, QApplication::translate("ProtocolHierarchyDialog", "End Packets", nullptr));
        ___qtreewidgetitem->setText(5, QApplication::translate("ProtocolHierarchyDialog", "Bits/s", nullptr));
        ___qtreewidgetitem->setText(4, QApplication::translate("ProtocolHierarchyDialog", "Bytes", nullptr));
        ___qtreewidgetitem->setText(3, QApplication::translate("ProtocolHierarchyDialog", "Percent Bytes", nullptr));
        ___qtreewidgetitem->setText(2, QApplication::translate("ProtocolHierarchyDialog", "Packets", nullptr));
        ___qtreewidgetitem->setText(1, QApplication::translate("ProtocolHierarchyDialog", "Percent Packets", nullptr));
        ___qtreewidgetitem->setText(0, QApplication::translate("ProtocolHierarchyDialog", "Protocol", nullptr));
        hintLabel->setText(QApplication::translate("ProtocolHierarchyDialog", "<small><i>A hint.</i></small>", nullptr));
    } // retranslateUi

};

namespace Ui {
    class ProtocolHierarchyDialog: public Ui_ProtocolHierarchyDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_PROTOCOL_HIERARCHY_DIALOG_H
