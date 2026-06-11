# Security Issue Reporting Guidelines

// Prior art and inspiration
// https://github.com/curl/curl/blob/master/SECURITY.md
// https://github.com/curl/curl/blob/master/docs/VULN-DISCLOSURE-POLICY.md
// https://github.com/pkgconf/pkgconf/blob/master/CONTRIBUTING.md

People use Wireshark in a variety of environments, and the Wireshark development team strives to deliver an application that our users can trust.
We use a variety of methods to ensure that our code is secure, including API safety, static analysis, dynamic analysis (fuzzing), and manual code review.
Security researchers are an important part of this effort, and we welcome reports from independent parties.

## How We Classify Security Issues

The security impact of an issue can usually be determined with the following question:

[quote]
Does this allow an attacker to ruin someone's day with little to no action on their part?

Examples of issues that *do* have a sufficient security impact include:

- A dissector bug that might cause Wireshark to crash or go into an infinite loop.
- A file parser bug that might cause Wireshark to crash or go into an infinite loop.
- A bug that might allow local or remote code execution in Wireshark, Stratoshark, or any of their accompanying utilities.

An example of an issue that *might* have a sufficient security impact is:

- An issue that meets a particular [Common Vulnerability Scoring System (CVSS)](https://nvd.nist.gov/vuln-metrics/cvss) score threshold.
  CVSS can be useful for characterizing an issue, but a score alone should not be the sole determining factor for security impact.

Examples of issues that *don't* have a sufficient security impact include:

- A crash in Wireshark that doesn't allow code execution and requires interaction on the part of the user, such as setting a specific protocol preference.
  Even though you would end up with a significant CVSS score (AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H / 4.7), unusual or specific configuration options are just that: unusual or specific, which means the issue won't affect the vast majority of our users.
- Recursion that isn't excessive. The default stack size on Linux and macOS is 8MiB, and we increase it from the default 1MiB to 8MiB on Windows.
  If you have to run `ulimit -s` to make Wireshark crash, that's your problem.
- Loops that are caught by our API.
  We check for a large number of protocol tree items and "idleness" (fetching values from a TVB without advancing its offset).
- A crash in a command line utility which doesn't lead to code execution.
  These have a low CVSS base score: AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:L / 2.5, and are usually more annoying than dangerous.

## Reporting an Application Security Issue

For Wireshark, Stratoshark, or any of their associated utilities, please open a [confidential issue](https://docs.gitlab.com/user/project/issues/confidential_issues/) at https://gitlab.com/wireshark/wireshark/-/work_items.
Alternatively you can send an email to security[AT]wireshark.org.
In that case the contents of the email will be pasted into a new confidential GitLab issue by a security team member.

In either case, we strongly recommend that you include a capture file that reproduces the issue.
This helps us identify issues and verify fixes more quickly.
Note that we also use capture files attached to issues for fuzz testing; if your file contains confidential information please make this clear.

We are happy to provide attribution for security issues.
Please provide your preferred name, and optionally, the organization that you represent in your report.

Do *not* try to request a CVE ID yourself.
We reserve the right to decide if an issue does or does not require a Wireshark security advisory and CVE ID.
We request CVE IDs as a part of our release process, which usually happens one or two days before each release.

AI-generated reports are allowed, but we require direct communication with the reporter.
Agent-submitted reports are not acceptable.
If an issue is important enough to warrant an advisory and CVE ID, it is important enough to require clear and direct communication between each party.
We recognize that AI might be required for language translation, but that should be the exception, not the rule.
From our perspective, agent-submitted reports are just another way of externalizing costs onto open source teams, which is a terrible way to begin a conversation.

## Reporting a Website Security Issue

For [www.wireshark.org](https://www.wireshark.org/), or a site hosted on a wireshark.org subdomain, please open a confidential issue at https://gitlab.com/wireshark/wireshark-web/-/work_items.
