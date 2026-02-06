#!/usr/bin/env python3
#
# Copyright 2022 by Moshe Kaplan
# Based on make-version.pl by Jörg Mayer
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

# See below for usage.
#
# If run with the "-r" or "--set-release" argument the VERSION macro in
# CMakeLists.txt will have the version_extra template appended to the
# version number. vcs_version.h will _not_ be generated if either argument is
# present.
#
# make-version.py is called during the build to update vcs_version.h in the build
# directory. To set a fixed version, use something like:
#
#   cmake -DVCSVERSION_OVERRIDE="Git v3.1.0 packaged as 3.1.0-1"
#

# XXX - We're pretty dumb about the "{vcsinfo}" substitution, and about having
# spaces in the package format.

import argparse
import os
import os.path
import re
import shlex
import shutil
import sys
import subprocess

from enum import Enum

Flavor = Enum('Flavor', ['Wireshark', 'Stratoshark'])

GIT_ABBREV_LENGTH = 12

# `git archive` will use an 'export-subst' entry in .gitattributes to replace
# the $Format strings with `git log --pretty=format:` placeholders.
# The output will look something like the following:
# GIT_EXPORT_SUBST_H = '51315cf37cdf6c0add1b1c99cb7941aac4489a6f'
# GIT_EXPORT_SUBST_D = 'HEAD -> master, upstream/master, upstream/HEAD'
# If the text "$Format" is still present, it means that
# git archive did not replace the $Format string, which
# means that this not a git archive.
GIT_EXPORT_SUBST_H = '$Format:%H$'
GIT_EXPORT_SUBST_D = '$Format:%D$'
IS_GIT_ARCHIVE = not GIT_EXPORT_SUBST_H.startswith('$Format')


def update_cmakelists_txt(src_dir, set_version, repo_data):
    if not set_version and repo_data['ws_package_string'] == "" and repo_data['ss_package_string'] == "":
        return

    cmake_filepath = os.path.join(src_dir, "CMakeLists.txt")

    with open(cmake_filepath, encoding='utf-8') as fh:
        cmake_contents = fh.read()

    new_cmake_contents = cmake_contents
    new_cmake_contents = re.sub(r"^set *\( *PROJECT_MAJOR_VERSION *\d+ *\)$",
                                f"set(PROJECT_MAJOR_VERSION {repo_data['ws_version_major']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(r"^set *\( *PROJECT_MINOR_VERSION *\d+ *\)$",
                                f"set(PROJECT_MINOR_VERSION {repo_data['ws_version_minor']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(r"^set *\( *PROJECT_PATCH_VERSION *\d+ *\)$",
                                f"set(PROJECT_PATCH_VERSION {repo_data['ws_version_patch']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(r"^set *\( *PROJECT_VERSION_EXTENSION .*?$",
                                f"set(PROJECT_VERSION_EXTENSION \"{repo_data['ws_package_string']}\")",
                                new_cmake_contents,
                                flags=re.MULTILINE)

    new_cmake_contents = re.sub(r"^set *\( *STRATOSHARK_MAJOR_VERSION *\d+ *\)$",
                                f"set(STRATOSHARK_MAJOR_VERSION {repo_data['ss_version_major']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(r"^set *\( *STRATOSHARK_MINOR_VERSION *\d+ *\)$",
                                f"set(STRATOSHARK_MINOR_VERSION {repo_data['ss_version_minor']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)

    with open(cmake_filepath, mode='w', encoding='utf-8') as fh:
        fh.write(new_cmake_contents)
        print(cmake_filepath + " has been updated.")


def update_debian_changelog(src_dir, repo_data):
    # Read packaging/debian/changelog, then write back out an updated version.

    deb_changelog_filepath = os.path.join(src_dir, "packaging", "debian", "changelog")
    with open(deb_changelog_filepath, encoding='utf-8') as fh:
        changelog_contents = fh.read()

    CHANGELOG_PATTERN = r"^.*"
    text_replacement = f"wireshark ({repo_data['ws_version_major']}.{repo_data['ws_version_minor']}.{repo_data['ws_version_patch']}{repo_data['ws_package_string']}) UNRELEASED; urgency=low"
    # Note: Only need to replace the first line, so we don't use re.MULTILINE or re.DOTALL
    new_changelog_contents = re.sub(CHANGELOG_PATTERN, text_replacement, changelog_contents)
    with open(deb_changelog_filepath, mode='w', encoding='utf-8') as fh:
        fh.write(new_changelog_contents)
        print(deb_changelog_filepath + " has been updated.")


def create_version_file(version_f, repo_data, flavor):
    'Write the version to the specified file handle'
    fpfx = 'ss' if flavor == Flavor.Stratoshark else 'ws'

    version_f.write(f"{repo_data[f'{fpfx}_version_major']}.{repo_data[f'{fpfx}_version_minor']}.{repo_data[f'{fpfx}_version_patch']}{repo_data[f'{fpfx}_package_string']}\n")
    print(version_f.name + " has been created.")

def update_attributes_asciidoc(src_dir, repo_data):
    # Read doc/attributes.adoc, then write it back out with an updated
    # wireshark-version replacement line.
    asiidoc_filepath = os.path.join(src_dir, "doc", "attributes.adoc")
    with open(asiidoc_filepath, encoding='utf-8') as fh:
        new_asciidoc_contents = fh.read()

    # Sample line (without quotes): ":wireshark-version: 4.3.1"
    ws_replacement = f":wireshark-version: {repo_data['ws_version_major']}.{repo_data['ws_version_minor']}.{repo_data['ws_version_patch']}"
    ss_replacement = f":stratoshark-version: {repo_data['ss_version_major']}.{repo_data['ss_version_minor']}.{repo_data['ss_version_patch']}"

    new_asciidoc_contents = re.sub(r"^:wireshark-version:.*$", ws_replacement, new_asciidoc_contents, flags=re.MULTILINE)
    new_asciidoc_contents = re.sub(r"^:stratoshark-version:.*$", ss_replacement, new_asciidoc_contents, flags=re.MULTILINE)

    with open(asiidoc_filepath, mode='w', encoding='utf-8') as fh:
        fh.write(new_asciidoc_contents)
        print(asiidoc_filepath + " has been updated.")


def update_docinfo_asciidoc(src_dir, repo_data):
    doc_paths = []
    doc_paths += [os.path.join(src_dir, 'doc', 'wsdg_src', 'developer-guide-docinfo.xml')]
    doc_paths += [os.path.join(src_dir, 'doc', 'wsug_src', 'user-guide-docinfo.xml')]

    for doc_path in doc_paths:
        with open(doc_path, encoding='utf-8') as fh:
            doc_contents = fh.read()

        # Sample line (without quotes): "<subtitle>For Wireshark 1.2</subtitle>"
        DOC_PATTERN = r"^<subtitle>For Wireshark \d+.\d+<\/subtitle>$"
        text_replacement = f"<subtitle>For Wireshark {repo_data['ws_version_major']}.{repo_data['ws_version_minor']}</subtitle>"

        new_doc_contents = re.sub(DOC_PATTERN, text_replacement, doc_contents, flags=re.MULTILINE)

        with open(doc_path, mode='w', encoding='utf-8') as fh:
            fh.write(new_doc_contents)
            print(doc_path + " has been updated.")


def update_cmake_lib_releases(src_dir, repo_data):
    # Read CMakeLists.txt for each library, then write back out an updated version.
    dir_paths = []
    dir_paths += [os.path.join(src_dir, 'epan')]
    dir_paths += [os.path.join(src_dir, 'wiretap')]

    for dir_path in dir_paths:
        cmakelists_filepath = os.path.join(dir_path, "CMakeLists.txt")
        with open(cmakelists_filepath, encoding='utf-8') as fh:
            cmakelists_contents = fh.read()

        # Sample line (without quotes; note leading tab: "    VERSION "0.0.0" SOVERSION 0")
        VERSION_PATTERN = r'^(\s*VERSION\s+"\d+\.\d+\.)\d+'
        replacement_text = f"\\g<1>{repo_data['ws_version_patch']}"
        new_cmakelists_contents = re.sub(VERSION_PATTERN,
                                         replacement_text,
                                         cmakelists_contents,
                                         flags=re.MULTILINE)

        with open(cmakelists_filepath, mode='w', encoding='utf-8') as fh:
            fh.write(new_cmakelists_contents)
            print(cmakelists_filepath + " has been updated.")


# Update distributed files that contain any version information
def update_versioned_files(src_dir, set_version, repo_data):
    update_cmakelists_txt(src_dir, set_version, repo_data)
    update_debian_changelog(src_dir, repo_data)
    if set_version:
        update_attributes_asciidoc(src_dir, repo_data)
        update_docinfo_asciidoc(src_dir, repo_data)
        update_cmake_lib_releases(src_dir, repo_data)


def generate_version_h(repo_data):
    # Generate new contents of version.h from repository data
    # XXX Is there any way we can simplify this?

    ws_vcs_line = '#define WIRESHARK_VCS_VERSION "Git Rev Unknown from unknown"'
    ws_num_commits_line = '#define WIRESHARK_VCS_NUM_COMMITS "0"'
    ws_commit_id_line = '/* #undef WIRESHARK_VCS_COMMIT_ID */'

    ss_vcs_line = '#define STRATOHARK_VCS_VERSION "Git Rev Unknown from unknown"'
    ss_num_commits_line = '#define STRATOSHARK_VCS_NUM_COMMITS "0"'
    ss_commit_id_line = '/* #undef STRATOSHARK_VCS_COMMIT_ID */'

    if repo_data.get('ws_num_commits'):
        ws_num_commits_line = f'#define WIRESHARK_VCS_NUM_COMMITS "{int(repo_data["ws_num_commits"])}"'

    if repo_data.get('ss_num_commits'):
        ss_num_commits_line = f'#define STRATOSHARK_VCS_NUM_COMMITS "{int(repo_data["ss_num_commits"])}"'

    if repo_data.get('commit_id'):
        ws_commit_id_line = f'#define WIRESHARK_VCS_COMMIT_ID "{repo_data["commit_id"]}"'
        ss_commit_id_line =  '#define STRATOSHARK_VCS_COMMIT_ID WIRESHARK_VCS_COMMIT_ID'

    if repo_data.get('enable_vcsversion'):
        if repo_data.get('ws_git_description'):
            # Do not bother adding the git branch, the git describe output
            # normally contains the base tag and commit ID which is more
            # than sufficient to determine the actual source tree.
            ws_vcs_line = f'#define WIRESHARK_VCS_VERSION "{repo_data["ws_git_description"]}"'
        elif repo_data.get('last_change') and repo_data.get('ws_num_commits'):
            version_string = f"v{repo_data['ws_version_major']}.{repo_data['ws_version_minor']}.{repo_data['ws_version_patch']}"
            ws_vcs_line = f'#define WIRESHARK_VCS_VERSION "{version_string}-Git-{repo_data["ws_num_commits"]}"'
        elif repo_data.get('commit_id'):
            ws_vcs_line = f'#define WIRESHARK_VCS_VERSION "Git commit {repo_data["commit_id"]}"'

        if repo_data.get('ss_git_description'):
            # Do not bother adding the git branch, same as above.
            ss_vcs_line = f'#define STRATOSHARK_VCS_VERSION "{repo_data["ss_git_description"]}"'
        elif repo_data.get('last_change') and repo_data.get('ss_num_commits'):
            version_string = f"v{repo_data['ss_version_major']}.{repo_data['ss_version_minor']}.{repo_data['ss_version_patch']}"
            ss_vcs_line = f'#define STRATOSHARK_VCS_VERSION "{version_string}-Git-{repo_data["ss_num_commits"]}"'
        elif repo_data.get('commit_id'):
            ss_vcs_line = f'#define STRATOSHARK_VCS_VERSION "Git commit {repo_data["commit_id"]}"'


    return f'''\
// Generated by tools/make-version.py
#pragma once
{ws_vcs_line}
{ws_num_commits_line}
{ws_commit_id_line}

{ss_vcs_line}
{ss_num_commits_line}
{ss_commit_id_line}
'''


def print_VCS_REVISION(version_file, repo_data, set_vcs):
    # Write the version control system's version to $version_file.
    # Don't change the file if it is not needed.
    #
    # XXX - We might want to add WIRESHARK_VCS_VERSION to CMakeLists.txt so that it can
    # generate vcs_version.h independently.

    new_version_h = generate_version_h(repo_data)

    needs_update = True
    if os.path.exists(version_file):
        with open(version_file, encoding='utf-8') as fh:
            current_version_h = fh.read()
        if current_version_h == new_version_h:
            needs_update = False

    if not set_vcs:
        return

    if needs_update:
        with open(version_file, mode='w', encoding='utf-8') as fh:
            fh.write(new_version_h)
            print(version_file + " has been updated.")
    elif not repo_data['enable_vcsversion']:
        print(version_file + " disabled.")
    else:
        print(version_file + " unchanged.")
    return


def get_version(cmakelists_file_data, flavor):
    # Reads major, minor, and patch
    # Sample data:
    # set(PROJECT_MAJOR_VERSION 3)
    # set(PROJECT_MINOR_VERSION 7)
    # set(PROJECT_PATCH_VERSION 2)

    fpfx = 'STRATOSHARK' if flavor == Flavor.Stratoshark else 'PROJECT'
    MAJOR_PATTERN = rf"^set *\( *{fpfx}_MAJOR_VERSION *(\d+) *\)$"
    MINOR_PATTERN = rf"^set *\( *{fpfx}_MINOR_VERSION *(\d+) *\)$"
    PATCH_PATTERN = r"^set *\( *PROJECT_PATCH_VERSION *(\d+) *\)$"

    major_match = re.search(MAJOR_PATTERN, cmakelists_file_data, re.MULTILINE)
    minor_match = re.search(MINOR_PATTERN, cmakelists_file_data, re.MULTILINE)
    patch_match = re.search(PATCH_PATTERN, cmakelists_file_data, re.MULTILINE)

    if not major_match:
        raise Exception(f"Couldn't get {flavor.name} major version")
    if not minor_match:
        raise Exception(f"Couldn't get {flavor.name} minor version")
    if not patch_match:
        raise Exception(f"Couldn't get {flavor.name} patch version")

    major_version = major_match.groups()[0]
    minor_version = minor_match.groups()[0]
    patch_version = patch_match.groups()[0]
    return major_version, minor_version, patch_version


def read_git_archive(tagged_version_extra, untagged_version_extra):
    # Reads key data from the git repo.
    # For git archives, this does not need to access the source directory because
    # `git archive` will use an 'export-subst' entry in .gitattributes to replace
    #  the value for GIT_EXPORT_SUBST_H in the script.
    # Returns a dictionary with key values from the repository

    is_tagged = False
    for git_ref in GIT_EXPORT_SUBST_D.split(r', '):
        match = re.match(r'^tag: (v[1-9].+)', git_ref)
        if match:
            is_tagged = True
            vcs_tag = match.groups()[0]

    if is_tagged:
        print(f"We are on tag {vcs_tag}.")
        ws_package_string = tagged_version_extra
    else:
        print("We are not tagged.")
        ws_package_string = untagged_version_extra

    # Always 0 commits for a git archive
    ws_num_commits = 0

    # Assume a full commit hash, abbreviate it.
    commit_id = GIT_EXPORT_SUBST_H[:GIT_ABBREV_LENGTH]
    ws_package_string = ws_package_string.replace("{vcsinfo}", str(ws_num_commits) + "-" + commit_id)

    repo_data = {}
    repo_data['commit_id'] = commit_id
    repo_data['enable_vcsversion'] = True
    repo_data['info_source'] = "git archive"
    repo_data['ws_num_commits'] = ws_num_commits
    repo_data['ws_package_string'] = ws_package_string
    # XXX Do we need a separate Stratoshark package string?
    repo_data['ss_package_string'] = ws_package_string
    return repo_data


def read_git_repo(src_dir, tagged_version_extra, untagged_version_extra):
    # Reads metadata from the git repo for generating the version string
    # Returns the data in a dict

    IS_GIT_INSTALLED = shutil.which('git') is not None
    if not IS_GIT_INSTALLED:
        print("Git unavailable. Git revision will be missing from version string.", file=sys.stderr)
        return {}

    GIT_DIR = os.path.join(src_dir, '.git')
    # Check whether to include VCS version information in vcs_version.h
    enable_vcsversion = True
    git_get_commondir_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" rev-parse --git-common-dir')
    git_commondir = subprocess.check_output(git_get_commondir_cmd, universal_newlines=True).strip()
    if git_commondir and os.path.exists(f"{git_commondir}{os.sep}wireshark-disable-versioning"):
        print("Header versioning disabled using git override.")
        enable_vcsversion = False

    git_last_changetime_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" log -1 --pretty=format:%at')
    git_last_changetime = subprocess.check_output(git_last_changetime_cmd, universal_newlines=True).strip()

    # Commits since last annotated tag.
    # Output could be something like: v3.7.2rc0-64-g84d83a8292cb
    # Or g84d83a8292cb
    git_describe_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" describe --abbrev={GIT_ABBREV_LENGTH} --long --always --match "v[1-9]*"')
    ws_git_description = subprocess.check_output(git_describe_cmd, universal_newlines=True).strip()
    parts = ws_git_description.split('-')
    if len(parts) > 1:
        ws_num_commits = int(parts[1])
    else:
        ws_num_commits = 0
    commit_id = parts[-1]

    ws_release_candidate = ''
    match = re.match(r'^v\d+\.\d+\.\d+(rc\d+)$', parts[0])
    if match:
        ws_release_candidate = match.groups()[0]

    git_describe_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" describe --abbrev={GIT_ABBREV_LENGTH} --long --always --match "ssv[0-9]*"')
    ss_git_description = subprocess.check_output(git_describe_cmd, universal_newlines=True).strip()
    parts = ss_git_description.split('-')
    if len(parts) > 1:
        ss_num_commits = int(parts[1])
    else:
        ss_num_commits = 0

    ss_release_candidate = ''
    match = re.match(r'^ssv\d+\.\d+\.\d+(rc\d+)$', parts[0])
    if match:
        ss_release_candidate = match.groups()[0]

    try:
        # This command is expected to fail if the version is not tagged
        git_vcs_tag_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" describe --exact-match --match "v[1-9]*"')
        git_vcs_tag = subprocess.check_output(git_vcs_tag_cmd, stderr=subprocess.DEVNULL, universal_newlines=True).strip()
        print(f"We are on Wireshark tag {git_vcs_tag}.")
        ws_package_string = tagged_version_extra
    except subprocess.CalledProcessError:
        print("We are not on a Wireshark tag.")
        ws_package_string = untagged_version_extra

    ws_package_string = ws_release_candidate + ws_package_string.replace("{vcsinfo}", str(ws_num_commits) + "-" + commit_id)

    try:
        # This command is expected to fail if the version is not tagged
        git_vcs_tag_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" describe --exact-match --match "ssv[0-9]*"')
        git_vcs_tag = subprocess.check_output(git_vcs_tag_cmd, stderr=subprocess.DEVNULL, universal_newlines=True).strip()
        print(f"We are on Stratoshark tag {git_vcs_tag}.")
        ss_package_string = tagged_version_extra
    except subprocess.CalledProcessError:
        print("We are not on a Stratoshark tag.")
        ss_package_string = untagged_version_extra

    ss_package_string = ss_release_candidate + ss_package_string.replace("{vcsinfo}", str(ss_num_commits) + "-" + commit_id)

    repo_data = {}
    repo_data['commit_id'] = commit_id
    repo_data['enable_vcsversion'] = enable_vcsversion
    repo_data['ws_git_description'] = ws_git_description
    repo_data['ss_git_description'] = ss_git_description
    repo_data['info_source'] = "Command line (git)"
    repo_data['last_change'] = git_last_changetime
    repo_data['ws_num_commits'] = ws_num_commits
    repo_data['ss_num_commits'] = ss_num_commits
    repo_data['ws_package_string'] = ws_package_string
    repo_data['ss_package_string'] = ss_package_string
    return repo_data


def parse_versionstring(version_arg):
    version_parts = version_arg.split('.')
    if len(version_parts) != 3:
        msg = "Version must have three numbers of the form x.y.z. You entered: " + version_arg
        raise argparse.ArgumentTypeError(msg)
    for i, version_type in enumerate(('Major', 'Minor', 'Patch')):
        try:
            int(version_parts[i])
        except ValueError:
            msg = f"{version_type} version must be a number! {version_type} version was '{version_parts[i]}'"
            raise argparse.ArgumentTypeError(msg)
    return version_parts


def read_repo_info(src_dir, tagged_version_extra, untagged_version_extra):
    if IS_GIT_ARCHIVE:
        repo_data = read_git_archive(tagged_version_extra, untagged_version_extra)
    elif os.path.exists(src_dir + os.sep + '.git') and not os.path.exists(os.path.join(src_dir, '.git', 'svn')):
        repo_data = read_git_repo(src_dir, tagged_version_extra, untagged_version_extra)
    else:
        raise Exception(src_dir + " does not appear to be a git repo or git archive!")

    return repo_data


# CMakeLists.txt calls this with no arguments to create vcs_version.h
# AppVeyor calls this with --set-release --untagged-version-extra=-{vcsinfo}-AppVeyor --tagged-version-extra=-AppVeyor
# .gitlab-ci calls this with --set-release
# Release checklist requires --set-version
def main():
    parser = argparse.ArgumentParser(description='Wireshark file and package versions')
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument('--set-wireshark-version', '-v', metavar='<x.y.z>', type=parse_versionstring, help='Set the Wireshark major, minor, and patch versions in the top-level CMakeLists.txt, doc/attributes.adoc, packaging/debian/changelog, and the CMakeLists.txt for all libraries to the provided version number')
    action_group.add_argument('--set-stratoshark-version', '-S', metavar='<x.y.z>', type=parse_versionstring, help='Set the Stratoshark major, minor, and patch versions in the top-level CMakeLists.txt and doc/attributes.adoc')
    action_group.add_argument('--set-release', '-r', action='store_true', help='Set the extra release information in the top-level CMakeLists.txt based on either default or command-line specified options.')
    setrel_group = parser.add_argument_group()
    setrel_group.add_argument('--tagged-version-extra', '-t', default="", help="Extra version information format to use when a tag is found. No format \
(an empty string) is used by default.")
    setrel_group.add_argument('--untagged-version-extra', '-u', default='-{vcsinfo}', help='Extra version information format to use when no tag is found. The format "-{vcsinfo}" (the number of commits and commit ID) is used by default.')
    parser.add_argument('--wireshark-version-file', '-f', metavar='<file>', type=argparse.FileType('w'), help='path to file containing a bare Wireshark version string')
    parser.add_argument('--stratoshark-version-file', metavar='<file>', type=argparse.FileType('w'), help='path to file containing a bare Stratoshark version string')
    parser.add_argument("src_dir", metavar='src_dir', nargs=1, help="path to source code")
    args = parser.parse_args()

    if args.wireshark_version_file and not args.set_release:
        sys.stderr.write('Error: --wireshark-version-file must be used with --set-release.\n')
        sys.exit(1)

    if args.stratoshark_version_file and not args.set_release:
        sys.stderr.write('Error: --stratoshark-version-file must be used with --set-release.\n')
        sys.exit(1)

    src_dir = args.src_dir[0]
    set_version = args.set_wireshark_version or args.set_stratoshark_version

    # Always get our version info from CMakeLists.txt
    repo_data = {'ws_package_string': '', 'ss_package_string': ''}
    cmake_path = os.path.join(src_dir, "CMakeLists.txt")
    with open(cmake_path, encoding='utf-8') as fh:
        cmakelists_file_data = fh.read()
        version_major, version_minor, version_patch = get_version(cmakelists_file_data, Flavor.Wireshark)
        repo_data['ws_version_major'] = version_major
        repo_data['ws_version_minor'] = version_minor
        repo_data['ws_version_patch'] = version_patch

        version_major, version_minor, version_patch = get_version(cmakelists_file_data, Flavor.Stratoshark)
        repo_data['ss_version_major'] = version_major
        repo_data['ss_version_minor'] = version_minor
        repo_data['ss_version_patch'] = version_patch

    if args.set_wireshark_version:
        repo_data['ws_version_major'] = args.set_wireshark_version[0]
        repo_data['ws_version_minor'] = args.set_wireshark_version[1]
        repo_data['ws_version_patch'] = args.set_wireshark_version[2]
    elif args.set_stratoshark_version:
        repo_data['ss_version_major'] = args.set_stratoshark_version[0]
        repo_data['ss_version_minor'] = args.set_stratoshark_version[1]
        repo_data['ss_version_patch'] = args.set_stratoshark_version[2]
    else:
        repo_data.update(read_repo_info(src_dir, args.tagged_version_extra, args.untagged_version_extra))

    set_vcs = not (args.set_release or set_version)
    VERSION_FILE = 'vcs_version.h'
    print_VCS_REVISION(VERSION_FILE, repo_data, set_vcs)

    if args.set_release or set_version:
        update_versioned_files(src_dir, set_version, repo_data)

    if args.wireshark_version_file:
        create_version_file(args.wireshark_version_file, repo_data, Flavor.Wireshark)

    if args.stratoshark_version_file:
        create_version_file(args.stratoshark_version_file, repo_data, Flavor.Stratoshark)


if __name__ == "__main__":
    main()
