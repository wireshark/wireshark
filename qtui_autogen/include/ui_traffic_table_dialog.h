/********************************************************************************
** Form generated from reading UI file 'traffic_table_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TRAFFIC_TABLE_DIALOG_H
#define UI_TRAFFIC_TABLE_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QPushButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QTabWidget>
#include <QtWidgets/QVBoxLayout>

QT_BEGIN_NAMESPACE

class Ui_TrafficTableDialog
{
public:
    QVBoxLayout *verticalLayout;
    QTabWidget *trafficTableTabWidget;
    QHBoxLayout *horizontalLayout;
    QCheckBox *nameResolutionCheckBox;
    QSpacerItem *horizontalSpacer_2;
    QCheckBox *displayFilterCheckBox;
    QSpacerItem *horizontalSpacer_3;
    QCheckBox *absoluteTimeCheckBox;
    QSpacerItem *horizontalSpacer;
    QPushButton *enabledTypesPushButton;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *TrafficTableDialog)
    {
        if (TrafficTableDialog->objectName().isEmpty())
            TrafficTableDialog->setObjectName(QString::fromUtf8("TrafficTableDialog"));
        TrafficTableDialog->resize(680, 475);
        verticalLayout = new QVBoxLayout(TrafficTableDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        trafficTableTabWidget = new QTabWidget(TrafficTableDialog);
        trafficTableTabWidget->setObjectName(QString::fromUtf8("trafficTableTabWidget"));

        verticalLayout->addWidget(trafficTableTabWidget);

        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        nameResolutionCheckBox = new QCheckBox(TrafficTableDialog);
        nameResolutionCheckBox->setObjectName(QString::fromUtf8("nameResolutionCheckBox"));

        horizontalLayout->addWidget(nameResolutionCheckBox);

        horizontalSpacer_2 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_2);

        displayFilterCheckBox = new QCheckBox(TrafficTableDialog);
        displayFilterCheckBox->setObjectName(QString::fromUtf8("displayFilterCheckBox"));

        horizontalLayout->addWidget(displayFilterCheckBox);

        horizontalSpacer_3 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_3);

        absoluteTimeCheckBox = new QCheckBox(TrafficTableDialog);
        absoluteTimeCheckBox->setObjectName(QString::fromUtf8("absoluteTimeCheckBox"));

        horizontalLayout->addWidget(absoluteTimeCheckBox);

        horizontalSpacer = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer);

        enabledTypesPushButton = new QPushButton(TrafficTableDialog);
        enabledTypesPushButton->setObjectName(QString::fromUtf8("enabledTypesPushButton"));

        horizontalLayout->addWidget(enabledTypesPushButton);

        horizontalLayout->setStretch(5, 1);

        verticalLayout->addLayout(horizontalLayout);

        buttonBox = new QDialogButtonBox(TrafficTableDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);


        retranslateUi(TrafficTableDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), TrafficTableDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), TrafficTableDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(TrafficTableDialog);
    } // setupUi

    void retranslateUi(QDialog *TrafficTableDialog)
    {
#ifndef QT_NO_TOOLTIP
        nameResolutionCheckBox->setToolTip(QApplication::translate("TrafficTableDialog", "<html><head/><body><p>Show resolved addresses and port names rather than plain values. The corresponding name resolution preference must be enabled.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        nameResolutionCheckBox->setText(QApplication::translate("TrafficTableDialog", "Name resolution", nullptr));
#ifndef QT_NO_TOOLTIP
        displayFilterCheckBox->setToolTip(QApplication::translate("TrafficTableDialog", "<html><head/><body><p>Only show conversations matching the current display filter</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        displayFilterCheckBox->setText(QApplication::translate("TrafficTableDialog", "Limit to display filter", nullptr));
#ifndef QT_NO_TOOLTIP
        absoluteTimeCheckBox->setToolTip(QApplication::translate("TrafficTableDialog", "<html><head/><body><p>Show absolute times in the start time column.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        absoluteTimeCheckBox->setText(QApplication::translate("TrafficTableDialog", "Absolute start time", nullptr));
#ifndef QT_NO_TOOLTIP
        enabledTypesPushButton->setToolTip(QApplication::translate("TrafficTableDialog", "<html><head/><body><p>Add and remove conversation types.</p></body></html>", nullptr));
#endif // QT_NO_TOOLTIP
        Q_UNUSED(TrafficTableDialog);
    } // retranslateUi

};

namespace Ui {
    class TrafficTableDialog: public Ui_TrafficTableDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TRAFFIC_TABLE_DIALOG_H
