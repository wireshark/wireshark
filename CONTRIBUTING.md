# Contributing to Wireshark

<!--
To do:
- Provide an overview of project governance.
- CoC?
- Sponsorship?
- SharkFest?
-->

Thank you for your interest in contributing to Wireshark!
We wouldn’t be as successful as we are today without the help of our community.
There are many ways to contribute and help improve Wireshark.

## Help People Use Wireshark

It’s not always obvious how to capture traffic or interpret what Wireshark shows you.
We provide two primary ways to ask for help: the question and answer site at
https://ask.wireshark.org/
and a mailing list at
[wireshark-users@wireshark.org](https://www.wireshark.org/lists/).
Your constructive and respectful assistance is welcome in both places.

## Report Issues

If you run across a problem with Wireshark or have a suggestion for improvement, you’re welcome to tell us about it on our [issue tracker](https://gitlab.com/wireshark/wireshark/-/issues).
When creating an issue, please select from one of the predefined templates and fill in each section as needed.
You can increase the likelihood that a bug will be fixed by providing any materials or information required to replicate the issue.
For most issues this means uploading a capture file, but please make sure that it doesn’t contain any private or sensitive information.

The User’s Guide also has a section on [reporting problems](https://www.wireshark.org/docs/wsug_html_chunked/ChIntroHelp.html#_reporting_problems).

## Write Code And Documentation

Wireshark is primarily written in C, with the exception of the main application UI, which is written in C++.
You can find its source code at https://gitlab.com/wireshark/wireshark/-/tree/master.
You can set up a [build environment](https://www.wireshark.org/docs/wsdg_html_chunked/PartEnvironment.html) on Windows, UNIX, and UNIX-like platforms, including macOS and Linux.

If you would like to contribute changes to Wireshark’s source code, you must create a [merge request](https://gitlab.com/wireshark/wireshark/-/merge_requests).
Complete details on doing so can be found in the [Developer’s Guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSrcContribute.html) and on the [wiki](https://gitlab.com/wireshark/wireshark/-/wikis/Development/SubmittingPatches).
When you submit a merge request, a series of automated tests will be run in order to ensure that compiles across different platforms and conforms to our coding guidelines.
The change will also be manually reviewed by a core developer and will be merged when the change passes both automated and manual review.

The Wireshark User’s Guide and Developer’s Guide are maintained in the [docbook directory](https://gitlab.com/wireshark/wireshark/-/tree/master/docbook) in the main repository.
You don’t need a complete development environment to contribute to them, but you do need git and a text editor.
Documentation updates must be made via a merge request similar to source code changes.
