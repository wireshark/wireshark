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
    if not set_version and repo_data['package_string'] == "":
        return

    cmake_filepath = os.path.join(src_dir, "CMakeLists.txt")

    with open(cmake_filepath, encoding='utf-8') as fh:
        cmake_contents = fh.read()

    MAJOR_PATTERN = r"^set *\( *PROJECT_MAJOR_VERSION *\d+ *\)$"
    MINOR_PATTERN = r"^set *\( *PROJECT_MINOR_VERSION *\d+ *\)$"
    PATCH_PATTERN = r"^set *\( *PROJECT_PATCH_VERSION *\d+ *\)$"
    VERSION_EXTENSION_PATTERN = r"^set *\( *PROJECT_VERSION_EXTENSION .*?$"

    new_cmake_contents = cmake_contents
    new_cmake_contents = re.sub(MAJOR_PATTERN,
                                f"set(PROJECT_MAJOR_VERSION {repo_data['version_major']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(MINOR_PATTERN,
                                f"set(PROJECT_MINOR_VERSION {repo_data['version_minor']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(PATCH_PATTERN,
                                f"set(PROJECT_PATCH_VERSION {repo_data['version_patch']})",
                                new_cmake_contents,
                                flags=re.MULTILINE)
    new_cmake_contents = re.sub(VERSION_EXTENSION_PATTERN,
                                f"set(PROJECT_VERSION_EXTENSION \"{repo_data['package_string']}\")",
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
    text_replacement = f"wireshark ({repo_data['version_major']}.{repo_data['version_minor']}.{repo_data['version_patch']}{repo_data['package_string']}) unstable; urgency=low"
    # Note: Only need to replace the first line, so we don't use re.MULTILINE or re.DOTALL
    new_changelog_contents = re.sub(CHANGELOG_PATTERN, text_replacement, changelog_contents)
    with open(deb_changelog_filepath, mode='w', encoding='utf-8') as fh:
        fh.write(new_changelog_contents)
    print(deb_changelog_filepath + " has been updated.")


def update_attributes_asciidoc(src_dir, repo_data):
    # Read docbook/attributes.adoc, then write it back out with an updated
    # wireshark-version replacement line.
    asiidoc_filepath = os.path.join(src_dir, "docbook", "attributes.adoc")
    with open(asiidoc_filepath, encoding='utf-8') as fh:
        asciidoc_contents = fh.read()

    # Sample line (without quotes): ":wireshark-version: 2.3.1"
    ASCIIDOC_PATTERN = r"^:wireshark-version:.*$"
    text_replacement = f":wireshark-version: {repo_data['version_major']}.{repo_data['version_minor']}.{repo_data['version_patch']}"

    new_asciidoc_contents = re.sub(ASCIIDOC_PATTERN, text_replacement, asciidoc_contents, flags=re.MULTILINE)

    with open(asiidoc_filepath, mode='w', encoding='utf-8') as fh:
        fh.write(new_asciidoc_contents)

    print(asiidoc_filepath + " has been updated.")


def update_docinfo_asciidoc(src_dir, repo_data):
    doc_paths = []
    doc_paths += [os.path.join(src_dir, 'docbook', 'developer-guide-docinfo.xml')]
    doc_paths += [os.path.join(src_dir, 'docbook', 'user-guide-docinfo.xml')]

    for doc_path in doc_paths:
        with open(doc_path, encoding='utf-8') as fh:
            doc_contents = fh.read()

        # Sample line (without quotes): "<subtitle>For Wireshark 1.2</subtitle>"
        DOC_PATTERN = r"^<subtitle>For Wireshark \d+.\d+<\/subtitle>$"
        text_replacement = f"<subtitle>For Wireshark {repo_data['version_major']}.{repo_data['version_minor']}</subtitle>"

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
        replacement_text = f"\\g<1>{repo_data['version_patch']}"
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

    if not repo_data.get('enable_vcsversion'):
        return "/* #undef VCSVERSION */\n"

    if repo_data.get('git_description'):
        # Do not bother adding the git branch, the git describe output
        # normally contains the base tag and commit ID which is more
        # than sufficient to determine the actual source tree.
        return f'#define VCSVERSION "{repo_data["git_description"]}"\n'

    if repo_data.get('last_change') and repo_data.get('num_commits'):
        version_string = f"v{repo_data['version_major']}.{repo_data['version_minor']}.{repo_data['version_patch']}"
        vcs_line = f'#define VCSVERSION "{version_string}-Git-{repo_data["num_commits"]}"\n'
        return vcs_line

    if repo_data.get('commit_id'):
        vcs_line = f'#define VCSVERSION "Git commit {repo_data["commit_id"]}"\n'
        return vcs_line

    vcs_line = '#define VCSVERSION "Git Rev Unknown from unknown"\n'
    return vcs_line


def print_VCS_REVISION(version_file, repo_data, set_vcs):
    # Write the version control system's version to $version_file.
    # Don't change the file if it is not needed.
    #
    # XXX - We might want to add VCSVERSION to CMakeLists.txt so that it can
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


def get_version(cmakelists_file_data):
    # Reads major, minor, and patch
    # Sample data:
    # set(PROJECT_MAJOR_VERSION 3)
    # set(PROJECT_MINOR_VERSION 7)
    # set(PROJECT_PATCH_VERSION 2)

    MAJOR_PATTERN = r"^set *\( *PROJECT_MAJOR_VERSION *(\d+) *\)$"
    MINOR_PATTERN = r"^set *\( *PROJECT_MINOR_VERSION *(\d+) *\)$"
    PATCH_PATTERN = r"^set *\( *PROJECT_PATCH_VERSION *(\d+) *\)$"

    major_match = re.search(MAJOR_PATTERN, cmakelists_file_data, re.MULTILINE)
    minor_match = re.search(MINOR_PATTERN, cmakelists_file_data, re.MULTILINE)
    patch_match = re.search(PATCH_PATTERN, cmakelists_file_data, re.MULTILINE)

    if not major_match:
        raise Exception("Couldn't get major version")
    if not minor_match:
        raise Exception("Couldn't get minor version")
    if not patch_match:
        raise Exception("Couldn't get patch version")

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
            vcs_tag = match.groups[0]

    if is_tagged:
        print(f"We are on tag {vcs_tag}.")
        package_string = tagged_version_extra
    else:
        print("We are not tagged.")
        package_string = untagged_version_extra

    # Always 0 commits for a git archive
    num_commits = 0

    # Assume a full commit hash, abbreviate it.
    commit_id = GIT_EXPORT_SUBST_H[:GIT_ABBREV_LENGTH]
    package_string = package_string.replace("{vcsinfo}", str(num_commits) + "-" + commit_id)

    repo_data = {}
    repo_data['commit_id'] = commit_id
    repo_data['enable_vcsversion'] = True
    repo_data['info_source'] = "git archive"
    repo_data['is_tagged'] = is_tagged
    repo_data['num_commits'] = num_commits
    repo_data['package_string'] = package_string
    return repo_data


def read_git_repo(src_dir, tagged_version_extra, untagged_version_extra):
    # Reads metadata from the git repo for generating the version string
    # Returns the data in a dict

    IS_GIT_INSTALLED = shutil.which('git') != ''
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
    git_last_annotated_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" describe --abbrev={GIT_ABBREV_LENGTH} --long --always --match "v[1-9]*"')
    git_last_annotated = subprocess.check_output(git_last_annotated_cmd, universal_newlines=True).strip()
    parts = git_last_annotated.split('-')
    git_description = git_last_annotated
    if len(parts) > 1:
        num_commits = int(parts[1])
    else:
        num_commits = 0
    commit_id = parts[-1]

    release_candidate = ''
    RC_PATTERN = r'^v\d+\.\d+\.\d+(rc\d+)$'
    match = re.match(RC_PATTERN, parts[0])
    if match:
        release_candidate = match.groups()[0]

    # This command is expected to fail if the version is not tagged
    try:
        git_vcs_tag_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" describe --exact-match --match "v[1-9]*"')
        git_vcs_tag = subprocess.check_output(git_vcs_tag_cmd, stderr=subprocess.DEVNULL, universal_newlines=True).strip()
        is_tagged = True
    except subprocess.CalledProcessError:
        is_tagged = False

    git_timestamp = ""
    if num_commits == 0:
        # Get the timestamp; format is similar to: 2022-06-27 23:09:20 -0400
        # Note: This doesn't appear to be used, only checked for command success
        git_timestamp_cmd = shlex.split(f'git --git-dir="{GIT_DIR}" log --format="%ad" -n 1 --date=iso')
        git_timestamp = subprocess.check_output(git_timestamp_cmd, universal_newlines=True).strip()

    if is_tagged:
        print(f"We are on tag {git_vcs_tag}.")
        package_string = tagged_version_extra
    else:
        print("We are not tagged.")
        package_string = untagged_version_extra

    package_string = release_candidate + package_string.replace("{vcsinfo}", str(num_commits) + "-" + commit_id)

    repo_data = {}
    repo_data['commit_id'] = commit_id
    repo_data['enable_vcsversion'] = enable_vcsversion
    repo_data['git_timestamp'] = git_timestamp
    repo_data['git_description'] = git_description
    repo_data['info_source'] = "Command line (git)"
    repo_data['is_tagged'] = is_tagged
    repo_data['last_change'] = git_last_changetime
    repo_data['num_commits'] = num_commits
    repo_data['package_string'] = package_string
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

    cmake_path = os.path.join(src_dir, "CMakeLists.txt")
    with open(cmake_path, encoding='utf-8') as fh:
        version_major, version_minor, version_patch = get_version(fh.read())
        repo_data['version_major'] = version_major
        repo_data['version_minor'] = version_minor
        repo_data['version_patch'] = version_patch

    return repo_data


# CMakeLists.txt calls this with no arguments to create vcs_version.h
# AppVeyor calls this with --set-release --untagged-version-extra=-{vcsinfo}-AppVeyor --tagged-version-extra=-AppVeyor
# .gitlab-ci calls this with --set-release
# Release checklist requires --set-version
def main():
    parser = argparse.ArgumentParser(description='Wireshark file and package versions')
    action_group = parser.add_mutually_exclusive_group()
    action_group.add_argument('--set-version', '-v', metavar='<x.y.z>', type=parse_versionstring, help='Set the major, minor, and patch versions in the top-level CMakeLists.txt, docbook/attributes.adoc, packaging/debian/changelog, and the CMakeLists.txt for all libraries to the provided version number')
    sr = action_group.add_argument('--set-release', '-r', action='store_true', help='Set the extra release information in the top-level CMakeLists.txt based on either default or command-line specified options.')
    setrel_group = parser.add_argument_group()
    setrel_group._group_actions.append(sr)
    setrel_group.add_argument('--tagged-version-extra', '-t', default="", help="Extra version information format to use when a tag is found. No format \
(an empty string) is used by default.")
    setrel_group.add_argument('--untagged-version-extra', '-u', default='-{vcsinfo}', help='Extra version information format to use when no tag is found. The format "-{vcsinfo}" (the number of commits and commit ID) is used by default.')
    parser.add_argument("src_dir", metavar='src_dir', nargs=1, help="path to source code")
    args = parser.parse_args()

    src_dir = args.src_dir[0]

    if args.set_version:
        repo_data = {}
        repo_data['version_major'] = args.set_version[0]
        repo_data['version_minor'] = args.set_version[1]
        repo_data['version_patch'] = args.set_version[2]
        repo_data['package_string'] = ''
    else:
        repo_data = read_repo_info(src_dir, args.tagged_version_extra, args.untagged_version_extra)

    set_vcs = not (args.set_release or args.set_version)
    VERSION_FILE = 'vcs_version.h'
    print_VCS_REVISION(VERSION_FILE, repo_data, set_vcs)

    if args.set_release or args.set_version:
        update_versioned_files(src_dir, args.set_version, repo_data)


if __name__ == "__main__":
    main()
