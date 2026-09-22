# Instructions for AI coding agents

This file is for AI coding agents working in the Wireshark source tree.
The rules for human contributors apply to agents as well. They are in:

- `CONTRIBUTING.md`
- the Developer's Guide sources in `doc/wsdg_src/`, in particular
  `wsdg_sources.adoc` (contributing and commit messages) and
  `wsdg_tests.adoc` (running the tests)
- `doc/README.developer` and `doc/README.dissector` (coding style and
  dissector APIs)

What follows are the rules agents most often miss.

## Commit messages

- Disclose AI assistance with an `Assisted-by:` trailer that names the
  tool, for example `Assisted-by: Claude`. Use it instead of
  `Co-Authored-By:` or any tool-specific trailer, and do not add links
  to agent sessions. Say the same in the merge request description.
- Begin the summary line with the component the change is about, for
  example `TLS: Fix ...`. `.gitmessage` shows the format.
- `git commit -m` does not use the `.gitmessage` template, so write the
  trailer yourself. `tools/setup-dev.sh` sets up the template and the
  hooks that check commit messages and code.
- Each commit of a merge request lands on the main branch as it is.
  Revise a commit by amending it and force-pushing, not with a follow-up
  fix-up commit, and never commit only to report status: a draft or a
  reply to a reviewer goes on the merge request.

## Dissectors

Packet data is untrusted input; `doc/README.developer` section 3
("Robustness") has the rules. In short:

- Report malformed input with an expert info and stop or skip, never
  with an assertion. `DISSECTOR_ASSERT()` and `ws_assert()` are for bugs
  in the dissector, not in the packet.
- Bound any recursion over packet data, for example with
  `increment_dissection_depth()`.
- Packets are dissected again, in any order, after the first pass.
  Update state kept across packets only while
  `PINFO_FD_VISITED(pinfo)` is false, keep what a later pass needs with
  `p_add_proto_data()`, and check that `tshark -2` gives the same
  result as one pass.

## Generated files

A file whose header says "Do not modify this file" is generated and
will be overwritten. The header usually names the generator and its
inputs; change those instead. For ASN.1 dissectors, edit the `.asn`,
`.cnf` and template files under `epan/dissectors/asn1/<protocol>/`
and regenerate with the `asn1` build target.

## Before submitting

- Build, and run the tests relevant to the change as described in
  `doc/wsdg_src/wsdg_tests.adoc`.
- Run `tools/pre-commit` on staged changes, or `tools/pre-commit HEAD~`
  on the last commit, for the API and style checks the hooks run.
- CI runs more checks than the hooks. Run them on your commits too:
  - `clang-tidy` with the checks in `.clang-tidy`. CI treats them as
    errors and fails the build. Configure with
    `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`, then run
    `clang-tidy -p <build directory> <file>`.
  - `tools/check_typed_item_calls.py`, `tools/check_tfs.py`,
    `tools/check_val_to_str.py`, `tools/check_col_apis.py` and
    `tools/check_spelling.py`, each with `--commits <N>`. CI reports
    what they find to reviewers; `.gitlab-ci.yml` has the options it
    uses.
- For a dissector change, run `tools/fuzz-test.sh` on a capture that
  exercises it.

## Capture files

If a change adds a capture file, generate it or sanitize it. Never add
traffic captured from a real network or taken from the user's machine:
it can contain private data.
