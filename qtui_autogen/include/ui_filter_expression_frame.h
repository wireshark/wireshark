/********************************************************************************
** Form generated from reading UI file 'filter_expression_frame.ui'
**
** Created by: Qt User Interface Compiler version 5.12.0
**
** WARNING! All changes made in this file will be lost when recompiling UI file!
********************************************************************************/

#ifndef UI_FILTER_EXPRESSION_FRAME_H
#define UI_FILTER_EXPRESSION_FRAME_H

#include <QtCore/QVariant>
#include <QtWidgets/QApplication>
#include <QtWidgets/QDialogButtonBox>
#include <QtWidgets/QHBoxLayout>
#include <QtWidgets/QLabel>
#include <QtWidgets/QSpacerItem>
#include <QtWidgets/QToolButton>
#include <QtWidgets/QVBoxLayout>
#include "accordion_frame.h"
#include "widgets/display_filter_edit.h"
#include "widgets/syntax_line_edit.h"

QT_BEGIN_NAMESPACE

class Ui_FilterExpressionFrame
{
public:
    QHBoxLayout *horizontalLayout_5;
    QVBoxLayout *verticalLayout_2;
    QToolButton *filterExpressionPreferencesPushButton;
    QSpacerItem *verticalSpacer;
    QVBoxLayout *verticalLayout;
    QHBoxLayout *horizontalLayout_4;
    QHBoxLayout *horizontalLayout;
    QLabel *labelLabel;
    SyntaxLineEdit *labelLineEdit;
    QHBoxLayout *horizontalLayout_2;
    QLabel *filterLabel;
    DisplayFilterEdit *displayFilterLineEdit;
    QHBoxLayout *horizontalLayout_3;
    QLabel *commentLabel;
    SyntaxLineEdit *commentLineEdit;
    QDialogButtonBox *buttonBox;

    void setupUi(AccordionFrame *FilterExpressionFrame)
    {
        if (FilterExpressionFrame->objectName().isEmpty())
            FilterExpressionFrame->setObjectName(QString::fromUtf8("FilterExpressionFrame"));
        FilterExpressionFrame->resize(796, 82);
        QSizePolicy sizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy.setHorizontalStretch(0);
        sizePolicy.setVerticalStretch(0);
        sizePolicy.setHeightForWidth(FilterExpressionFrame->sizePolicy().hasHeightForWidth());
        FilterExpressionFrame->setSizePolicy(sizePolicy);
        FilterExpressionFrame->setMaximumSize(QSize(16777215, 82));
        FilterExpressionFrame->setFrameShape(QFrame::NoFrame);
        FilterExpressionFrame->setFrameShadow(QFrame::Plain);
        horizontalLayout_5 = new QHBoxLayout(FilterExpressionFrame);
        horizontalLayout_5->setObjectName(QString::fromUtf8("horizontalLayout_5"));
        verticalLayout_2 = new QVBoxLayout();
        verticalLayout_2->setObjectName(QString::fromUtf8("verticalLayout_2"));
        filterExpressionPreferencesPushButton = new QToolButton(FilterExpressionFrame);
        filterExpressionPreferencesPushButton->setObjectName(QString::fromUtf8("filterExpressionPreferencesPushButton"));

        verticalLayout_2->addWidget(filterExpressionPreferencesPushButton);

        verticalSpacer = new QSpacerItem(20, 5, QSizePolicy::Minimum, QSizePolicy::Expanding);

        verticalLayout_2->addItem(verticalSpacer);


        horizontalLayout_5->addLayout(verticalLayout_2);

        verticalLayout = new QVBoxLayout();
        verticalLayout->setObjectName(QString::fromUtf8("verticalLayout"));
        horizontalLayout_4 = new QHBoxLayout();
        horizontalLayout_4->setObjectName(QString::fromUtf8("horizontalLayout_4"));
        horizontalLayout = new QHBoxLayout();
        horizontalLayout->setObjectName(QString::fromUtf8("horizontalLayout"));
        labelLabel = new QLabel(FilterExpressionFrame);
        labelLabel->setObjectName(QString::fromUtf8("labelLabel"));

        horizontalLayout->addWidget(labelLabel);

        labelLineEdit = new SyntaxLineEdit(FilterExpressionFrame);
        labelLineEdit->setObjectName(QString::fromUtf8("labelLineEdit"));
        QSizePolicy sizePolicy1(QSizePolicy::Expanding, QSizePolicy::Fixed);
        sizePolicy1.setHorizontalStretch(1);
        sizePolicy1.setVerticalStretch(0);
        sizePolicy1.setHeightForWidth(labelLineEdit->sizePolicy().hasHeightForWidth());
        labelLineEdit->setSizePolicy(sizePolicy1);
        labelLineEdit->setMinimumSize(QSize(80, 0));

        horizontalLayout->addWidget(labelLineEdit);


        horizontalLayout_4->addLayout(horizontalLayout);

        horizontalLayout_2 = new QHBoxLayout();
        horizontalLayout_2->setObjectName(QString::fromUtf8("horizontalLayout_2"));
        filterLabel = new QLabel(FilterExpressionFrame);
        filterLabel->setObjectName(QString::fromUtf8("filterLabel"));

        horizontalLayout_2->addWidget(filterLabel);

        displayFilterLineEdit = new DisplayFilterEdit(FilterExpressionFrame);
        displayFilterLineEdit->setObjectName(QString::fromUtf8("displayFilterLineEdit"));
        sizePolicy1.setHeightForWidth(displayFilterLineEdit->sizePolicy().hasHeightForWidth());
        displayFilterLineEdit->setSizePolicy(sizePolicy1);
        displayFilterLineEdit->setMinimumSize(QSize(80, 0));

        horizontalLayout_2->addWidget(displayFilterLineEdit);


        horizontalLayout_4->addLayout(horizontalLayout_2);


        verticalLayout->addLayout(horizontalLayout_4);

        horizontalLayout_3 = new QHBoxLayout();
        horizontalLayout_3->setObjectName(QString::fromUtf8("horizontalLayout_3"));
        commentLabel = new QLabel(FilterExpressionFrame);
        commentLabel->setObjectName(QString::fromUtf8("commentLabel"));

        horizontalLayout_3->addWidget(commentLabel);

        commentLineEdit = new SyntaxLineEdit(FilterExpressionFrame);
        commentLineEdit->setObjectName(QString::fromUtf8("commentLineEdit"));
        sizePolicy1.setHeightForWidth(commentLineEdit->sizePolicy().hasHeightForWidth());
        commentLineEdit->setSizePolicy(sizePolicy1);
        commentLineEdit->setMinimumSize(QSize(80, 0));

        horizontalLayout_3->addWidget(commentLineEdit);


        verticalLayout->addLayout(horizontalLayout_3);


        horizontalLayout_5->addLayout(verticalLayout);

        buttonBox = new QDialogButtonBox(FilterExpressionFrame);
        buttonBox->setObjectName(QString::fromUtf8("buttonBox"));
        QSizePolicy sizePolicy2(QSizePolicy::Fixed, QSizePolicy::Fixed);
        sizePolicy2.setHorizontalStretch(0);
        sizePolicy2.setVerticalStretch(0);
        sizePolicy2.setHeightForWidth(buttonBox->sizePolicy().hasHeightForWidth());
        buttonBox->setSizePolicy(sizePolicy2);
        buttonBox->setStandardButtons(QDialogButtonBox::Cancel|QDialogButtonBox::Ok);

        horizontalLayout_5->addWidget(buttonBox);


        retranslateUi(FilterExpressionFrame);

        QMetaObject::connectSlotsByName(FilterExpressionFrame);
    } // setupUi

    void retranslateUi(AccordionFrame *FilterExpressionFrame)
    {
        FilterExpressionFrame->setWindowTitle(QApplication::translate("FilterExpressionFrame", "Frame", nullptr));
        filterExpressionPreferencesPushButton->setText(QApplication::translate("FilterExpressionFrame", "Filter Buttons Preferences\342\200\246", nullptr));
        labelLabel->setText(QApplication::translate("FilterExpressionFrame", "Label:", nullptr));
        labelLineEdit->setPlaceholderText(QApplication::translate("FilterExpressionFrame", "Enter a description for the filter button", nullptr));
        filterLabel->setText(QApplication::translate("FilterExpressionFrame", "Filter:", nullptr));
        displayFilterLineEdit->setPlaceholderText(QApplication::translate("FilterExpressionFrame", "Enter a filter expression to be applied", nullptr));
        commentLabel->setText(QApplication::translate("FilterExpressionFrame", "Comment:", nullptr));
        commentLineEdit->setPlaceholderText(QApplication::translate("FilterExpressionFrame", "Enter a comment for the filter button", nullptr));
    } // retranslateUi

};

namespace Ui {
    class FilterExpressionFrame: public Ui_FilterExpressionFrame {};
} // namespace Ui

QT_END_NAMESPACE

#endif // UI_FILTER_EXPRESSION_FRAME_H
