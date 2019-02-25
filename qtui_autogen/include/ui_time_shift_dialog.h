/********************************************************************************
** Form generated from reading UI file 'time_shift_dialog.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_TIME_SHIFT_DIALOG_H
#define UI_TIME_SHIFT_DIALOG_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QCheckBox>
#include <QtWidgets/QDialog>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QRadioButton>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QVBoxLayout>
#include "widgets/syntax_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_TimeShiftDialog
{
public:
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout;
    QRadioButton *shiftAllButton;
    SyntaxLineEdit *shiftAllTimeLineEdit;
    QLabel *label_6;
    QSpacerItem *horizontalSpacer_4;
    QHBoxLayout *horizontalLayout_2;
    QRadioButton *setOneButton;
    SyntaxLineEdit *setOneFrameLineEdit;
    QLabel *label_2;
    SyntaxLineEdit *setOneTimeLineEdit;
    QHBoxLayout *horizontalLayout_3;
    QCheckBox *setTwoCheckBox;
    SyntaxLineEdit *setTwoFrameLineEdit;
    QLabel *setTwoToLabel;
    SyntaxLineEdit *setTwoTimeLineEdit;
    QSpacerItem *horizontalSpacer_3;
    QHBoxLayout *horizontalLayout_4;
    QLabel *extrapolateLabel;
    QSpacerItem *horizontalSpacer;
    QLabel *label_5;
    QRadioButton *unshiftAllButton;
    QHBoxLayout *horizontalLayout_6;
    QLabel *errorLabel;
    QSpacerItem *horizontalSpacer_5;
    QDialogButtonBox *buttonBox;

    void setupUi(QDialog *TimeShiftDialog)
    {
        if (TimeShiftDialog->objectName().isEmpty())
            TimeShiftDialog->setObjectName(QString::fromUtf8("TimeShiftDialog"));
        TimeShiftDialog->resize(549, 257);
        QSizePolicy sizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(TimeShiftDialog->sizePolicy().hasHeightForWidth());
        TimeShiftDialog->setSizePolicy(sizePolicy);
        verticalLayout = new QVBoxLayout(TimeShiftDialog);
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        shiftAllButton = new QRadioButton(TimeShiftDialog);
        shiftAllButton->setObjectName(QString::fromUtf8("shiftAllButton"));
        shiftAllButton->setChecked(true);

        horizontalLayout->addWidget(shiftAllButton);

        shiftAllTimeLineEdit = new SyntaxLineEdit(TimeShiftDialog);
        shiftAllTimeLineEdit->setObjectName(QString::fromUtf8("shiftAllTimeLineEdit"));

        horizontalLayout->addWidget(shiftAllTimeLineEdit);

        label_6 = new QLabel(TimeShiftDialog);
        label_6->setObjectName(QString::fromUtf8("label_6"));

        horizontalLayout->addWidget(label_6);

        horizontalSpacer_4 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout->addItem(horizontalSpacer_4);


        verticalLayout->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        setOneButton = new QRadioButton(TimeShiftDialog);
        setOneButton->setObjectName(QString::fromUtf8("setOneButton"));

        horizontalLayout_2->addWidget(setOneButton);

        setOneFrameLineEdit = new SyntaxLineEdit(TimeShiftDialog);
        setOneFrameLineEdit->setObjectName(QString::fromUtf8("setOneFrameLineEdit"));

        horizontalLayout_2->addWidget(setOneFrameLineEdit);

        label_2 = new QLabel(TimeShiftDialog);
        label_2->setObjectName(QString::fromUtf8("label_2"));

        horizontalLayout_2->addWidget(label_2);

        setOneTimeLineEdit = new SyntaxLineEdit(TimeShiftDialog);
        setOneTimeLineEdit->setObjectName(QString::fromUtf8("setOneTimeLineEdit"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(1);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(setOneTimeLineEdit->sizePolicy().hasHeightForWidth());
        setOneTimeLineEdit->setSizePolicy(sizePolicy1);

        horizontalLayout_2->addWidget(setOneTimeLineEdit);


        verticalLayout->addLayout(horizontalLayout_2);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        setTwoCheckBox = new QCheckBox(TimeShiftDialog);
        setTwoCheckBox->setObjectName(QString::fromUtf8("setTwoCheckBox"));
        setTwoCheckBox->setEnabled(true);

        horizontalLayout_3->addWidget(setTwoCheckBox);

        setTwoFrameLineEdit = new SyntaxLineEdit(TimeShiftDialog);
        setTwoFrameLineEdit->setObjectName(QString::fromUtf8("setTwoFrameLineEdit"));

        horizontalLayout_3->addWidget(setTwoFrameLineEdit);

        setTwoToLabel = new QLabel(TimeShiftDialog);
        setTwoToLabel->setObjectName(QString::fromUtf8("setTwoToLabel"));

        horizontalLayout_3->addWidget(setTwoToLabel);

        setTwoTimeLineEdit = new SyntaxLineEdit(TimeShiftDialog);
        setTwoTimeLineEdit->setObjectName(QString::fromUtf8("setTwoTimeLineEdit"));
        sizePolicy1.setHeightForWidth(setTwoTimeLineEdit->sizePolicy().hasHeightForWidth());
        setTwoTimeLineEdit->setSizePolicy(sizePolicy1);

        horizontalLayout_3->addWidget(setTwoTimeLineEdit);

        horizontalSpacer_3 = new QSpacerItem(28, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_3->addItem(horizontalSpacer_3);


        verticalLayout->addLayout(horizontalLayout_3);

        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        extrapolateLabel = new QLabel(TimeShiftDialog);
        extrapolateLabel->setObjectName(QString::fromUtf8("extrapolateLabel"));

        horizontalLayout_4->addWidget(extrapolateLabel);

        horizontalSpacer = new QSpacerItem(60, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_4->addItem(horizontalSpacer);

        label_5 = new QLabel(TimeShiftDialog);
        label_5->setObjectName(QString::fromUtf8("label_5"));

        horizontalLayout_4->addWidget(label_5);


        verticalLayout->addLayout(horizontalLayout_4);

        unshiftAllButton = new QRadioButton(TimeShiftDialog);
        unshiftAllButton->setObjectName(QString::fromUtf8("unshiftAllButton"));

        verticalLayout->addWidget(unshiftAllButton);

        horizontalLayout_6 = new QHBoxLayout();
        horizontalLayout_6->setObjectName(QString::fromUtf8("horizontalLayout_6"));
        errorLabel = new QLabel(TimeShiftDialog);
        errorLabel->setObjectName(QString::fromUtf8("errorLabel"));

        horizontalLayout_6->addWidget(errorLabel);

        horizontalSpacer_5 = new QSpacerItem(40, 20, QSizePolicy::Expanding, QSizePolicy::Minimum);

        horizontalLayout_6->addItem(horizontalSpacer_5);


        verticalLayout->addLayout(horizontalLayout_6);

        buttonBox = new QDialogButtonBox(TimeShiftDialog);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        buttonBox->setOrientation(Qt::Horizontal);
        buttonBox->setStandardButtons(QDialogButtonBox::Apply|QDialogButtonBox::Close|QDialogButtonBox::Help);

        verticalLayout->addWidget(buttonBox);

        buttonBox->raise();
        unshiftAllButton->raise();

        retranslateUi(TimeShiftDialog);
        QObject::connect(buttonBox, SIGNAL(accepted()), TimeShiftDialog, SLOT(accept()));
        QObject::connect(buttonBox, SIGNAL(rejected()), TimeShiftDialog, SLOT(reject()));

        QMetaObject::connectSlotsByName(TimeShiftDialog);
    } // setupUi

    void retranslateUi(QDialog *TimeShiftDialog)
    {
        shiftAllButton->setText(QApplication::translate("TimeShiftDialog", "Shift all packets by", nullptr));
        label_6->setText(QApplication::translate("TimeShiftDialog", "<html><head/><body><p><span style=\" font-size:small; font-style:italic;\">[-][[hh:]mm:]ss[.ddd] </span></p></body></html>", nullptr));
        setOneButton->setText(QApplication::translate("TimeShiftDialog", "Set the time for packet", nullptr));
        label_2->setText(QApplication::translate("TimeShiftDialog", "to", nullptr));
        setTwoCheckBox->setText(QApplication::translate("TimeShiftDialog", "\342\200\246then set packet", nullptr));
        setTwoToLabel->setText(QApplication::translate("TimeShiftDialog", "to", nullptr));
        extrapolateLabel->setText(QApplication::translate("TimeShiftDialog", "and extrapolate the time for all other packets", nullptr));
        label_5->setText(QApplication::translate("TimeShiftDialog", "<html><head/><body><p align=\"right\"><span style=\" font-size:small; font-style:italic;\">[YYYY-MM-DD] hh:mm:ss[.ddd] </span></p></body></html>", nullptr));
        unshiftAllButton->setText(QApplication::translate("TimeShiftDialog", "Undo all shifts", nullptr));
        errorLabel->setText(QString());
        Q_UNUSED(TimeShiftDialog);
    } // retranslateUi

};

namespace Ui {
    class TimeShiftDialog: public Ui_TimeShiftDialog {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_TIME_SHIFT_DIALOG_H
