#!/usr/bin/env python3
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import re
import subprocess
import argparse
import signal
from collections import Counter

# Looks for spelling errors among strings found in source or documentation files.
# N.B. To run this script, you should install pyspellchecker (not spellchecker) using pip.

# TODO: check structured doxygen comments?

# For text colouring/highlighting.
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    ADDED = '\033[45m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


# Try to exit soon after Ctrl-C is pressed.
should_exit = False

def signal_handler(sig, frame):
    global should_exit
    should_exit = True
    print('You pressed Ctrl+C - exiting')

signal.signal(signal.SIGINT, signal_handler)



# Create spellchecker, and augment with some Wireshark words.
from spellchecker import SpellChecker
# Set up our dict with words from text file.
spell = SpellChecker()
spell.word_frequency.load_text_file('./tools/wireshark_words.txt')


# Track words that were not found.
missing_words = []


# Split camelCase string into separate words.
def camelCaseSplit(identifier):
    matches = re.finditer(r'.+?(?:(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])|$)', identifier)
    return [m.group(0) for m in matches]


# A File object contains all of the strings to be checked for a given file.
class File:
    def __init__(self, file):
        self.file = file
        self.values = []

        filename, extension = os.path.splitext(file)
        self.code_file = extension in {'.c', '.cpp'}


        with open(file, 'r') as f:
            contents = f.read()

            if self.code_file:
                # Remove comments so as not to trip up RE.
                contents = removeComments(contents)

            # Find protocol name and add to dict.
            # N.B. doesn't work when a variable is used instead of a literal for the protocol name...
            matches = re.finditer(r'proto_register_protocol\s*\([\n\r\s]*\"(.*)\",[\n\r\s]*\"(.*)\",[\n\r\s]*\"(.*)\"', contents)
            for m in matches:
                protocol = m.group(3)
                # Add to dict.
                spell.word_frequency.load_words([protocol])
                spell.known([protocol])
                print('Protocol is: ' + bcolors.BOLD +  protocol + bcolors.ENDC)

    # Add a string found in this file.
    def add(self, value):
        self.values.append(value)

    # Whole word is not recognised, but is it 2 words concatenated (without camelcase) ?
    def checkMultiWords(self, word):
        if len(word) < 6:
            return False

        # Don't consider if mixed cases.
        if not (word.islower() or word.isupper()):
            # But make an exception if only the fist letter is uppercase..
            if not word == (word[0].upper() + word[1:]):
                return False

        # Try splitting into 2 words recognised at various points.
        # Allow 3-letter words.
        length = len(word)
        for idx in range(3, length-3):
            word1 = word[0:idx]
            word2 = word[idx:]

            if not spell.unknown([word1, word2]):
                return True

        return self.checkMultiWordsRecursive(word)

    # If word before 'id' is recognised, accept word.
    def wordBeforeId(self, word):
        if word.lower().endswith('id'):
            if not spell.unknown([word[0:len(word)-2]]):
                return True
            else:
                return False

    def checkMultiWordsRecursive(self, word):
        length = len(word)
        #print('word=', word)
        if length < 4:
            return False

        for idx in range(4, length+1):
            w = word[0:idx]
            if not spell.unknown([w]):
                if idx == len(word):
                    return True
                else:
                    if self.checkMultiWordsRecursive(word[idx:]):
                        return True

        return False

    def numberPlusUnits(self, word):
        m = re.search(r'^([0-9]+)([a-zA-Z]+)$', word)
        if m:
            if m.group(2).lower() in { "bit", "bits", "gb", "kbps", "gig", "mb", "th", "mhz", "v", "hz", "k",
                                       "mbps", "m", "g", "ms", "nd", "nds", "rd", "kb", "kbit",
                                       "khz", "km", "ms", "usec", "sec", "gbe", "ns", "ksps", "qam", "mm" }:
                return True
        return False


    # Check the spelling of all the words we have found
    def spellCheck(self):

        num_values = len(self.values)
        for value_index,v in enumerate(self.values):
            if should_exit:
                exit(1)

            # Ignore includes.
            if v.endswith('.h'):
                continue

            # Store original (as want to include for context in error report).
            original = str(v)

            # Replace most punctuation with spaces, and eliminate common format specifiers.
            v = v.replace('.', ' ')
            v = v.replace(',', ' ')
            v = v.replace('`', ' ')
            v = v.replace(':', ' ')
            v = v.replace(';', ' ')
            v = v.replace('"', ' ')
            v = v.replace('\\', ' ')
            v = v.replace('+', ' ')
            v = v.replace('|', ' ')
            v = v.replace('(', ' ')
            v = v.replace(')', ' ')
            v = v.replace('[', ' ')
            v = v.replace(']', ' ')
            v = v.replace('{', ' ')
            v = v.replace('}', ' ')
            v = v.replace('<', ' ')
            v = v.replace('>', ' ')
            v = v.replace('_', ' ')
            v = v.replace('-', ' ')
            v = v.replace('/', ' ')
            v = v.replace('!', ' ')
            v = v.replace('?', ' ')
            v = v.replace('=', ' ')
            v = v.replace('*', ' ')
            v = v.replace('%', ' ')
            v = v.replace('#', ' ')
            v = v.replace('&', ' ')
            v = v.replace('@', ' ')
            v = v.replace('$', ' ')
            v = v.replace("'", ' ')
            v = v.replace('"', ' ')
            v = v.replace('%u', '')
            v = v.replace('%d', '')
            v = v.replace('%s', '')

            # Split into words.
            value_words = v.split()
            # Further split up any camelCase words.
            words = []
            for w in value_words:
                words +=  camelCaseSplit(w)

            # Check each word within this string in turn.
            for word in words:
                # Strip trailing digits from word.
                word = word.rstrip('1234567890')

                # Quote marks found in some of the docs...
                word = word.replace('“', '')
                word = word.replace('”', '')

                if self.numberPlusUnits(word):
                    continue

                if len(word) > 4 and spell.unknown([word]) and not self.checkMultiWords(word) and not self.wordBeforeId(word):
                    print(self.file, value_index, '/', num_values, '"' + original + '"', bcolors.FAIL + word + bcolors.ENDC,
                         ' -> ', '?')
                    # TODO: this can be interesting, but takes too long!
                    # bcolors.OKGREEN + spell.correction(word) + bcolors.ENDC
                    global missing_words
                    missing_words.append(word)

def removeWhitespaceControl(code_string):
    code_string = code_string.replace('\\n', ' ')
    code_string = code_string.replace('\\r', ' ')
    code_string = code_string.replace('\\t', ' ')
    return code_string

# Remove any contractions from the given string.
def removeContractions(code_string):
    contractions = [ "wireshark’s", "don’t", "let’s", "isn’t", "won’t", "user’s", "hasn’t", "you’re", "o’clock", "you’ll",
                     "you’d", "developer’s", "doesn’t", "what’s", "let’s", "haven’t", "can’t", "you’ve",
                     "shouldn’t", "didn’t", "wouldn’t", "aren’t", "there’s", "packet’s", "couldn’t", "world’s",
                     "needn’t", "graph’s", "table’s", "parent’s", "entity’s", "server’s", "node’s",
                     "querier’s", "sender’s", "receiver’s", "computer’s", "frame’s", "vendor’s", "system’s",
                     "we’ll", "asciidoctor’s", "protocol’s", "microsoft’s", "wasn’t" ]
    for c in contractions:
        code_string = code_string.replace(c, "")
        code_string = code_string.replace(c.capitalize(), "")
        code_string = code_string.replace(c.replace('’', "'"), "")
        code_string = code_string.replace(c.capitalize().replace('’', "'"), "")
    return code_string

def removeComments(code_string):
    code_string = re.sub(re.compile(r"/\*.*?\*/",re.DOTALL ) ,"" ,code_string) # C-style comment
    # Remove this for now as can get tripped up if see htpps://www.... within a string!
    code_string = re.sub(re.compile(r"^\s*//.*?\n" ) ,"" ,code_string)             # C++-style comment
    return code_string

def removeSingleQuotes(code_string):
    code_string = code_string.replace('\\\\', " ")        # Separate at \\
    code_string = code_string.replace('\"\\\\\"', "")
    code_string = code_string.replace("\\\"", " ")
    code_string = code_string.replace("'\"'", "")
    code_string = code_string.replace('…', ' ')
    return code_string

def removeHexSpecifiers(code_string):
    # Find all hex numbers

    looking = True
    while looking:
        m = re.search(r'(0x[0-9a-fA-F]*)', code_string)
        if m:
            code_string = code_string.replace(m.group(0), "")
        else:
            looking = False

    return code_string


# Create a File object that knows about all of the strings in the given file.
def findStrings(filename):
    with open(filename, 'r') as f:
        contents = f.read()

        # Remove comments & embedded quotes so as not to trip up RE.
        contents = removeContractions(contents)
        contents = removeWhitespaceControl(contents)
        contents = removeSingleQuotes(contents)
        contents = removeHexSpecifiers(contents)

        # Create file object.
        file = File(filename)

        # What we check depends upon file type.
        if file.code_file:
            contents = removeComments(contents)
            # Code so only checking strings.
            matches =   re.finditer(r'\"([^\"]*)\"', contents)
            for m in matches:
                file.add(m.group(1))
        else:
            # A documentation file, so examine all words.
            for w in contents.split():
                file.add(w)

        return file


# Test for whether the given file was automatically generated.
def isGeneratedFile(filename):
    if not filename.endswith('.c'):
        return False

    # This file is generated, but notice is further in than want to check for all files
    if filename.endswith('pci-ids.c'):
        return True

    # Open file
    f_read = open(os.path.join(filename), 'r')
    for line_no,line in enumerate(f_read):
        # The comment to say that its generated is near the top, so give up once
        # get a few lines down.
        if line_no > 10:
            f_read.close()
            return False
        if (line.find('Generated automatically') != -1 or
            line.find('Autogenerated from') != -1 or
            line.find('is autogenerated') != -1 or
            line.find('automatically generated by Pidl') != -1 or
            line.find('Created by: The Qt Meta Object Compiler') != -1 or
            line.find('This file was generated') != -1 or
            line.find('This filter was automatically generated') != -1 or
            line.find('This file is auto generated, do not edit!') != -1):

            f_read.close()
            return True

    # OK, looks like a hand-written file!
    f_read.close()
    return False


def isAppropriateFile(filename):
    file, extension = os.path.splitext(filename)
    if filename.find('CMake') != -1:
        return False
    return extension in { '.adoc', '.c', '.cpp', '.pod', '.nsi', '.txt'} or file.endswith('README')


def findFilesInFolder(folder, recursive=True):
    files_to_check = []

    if recursive:
        for root, subfolders, files in os.walk(folder):
            for f in files:
                if should_exit:
                    return
                f = os.path.join(root, f)
                if isAppropriateFile(f) and not isGeneratedFile(f):
                    files_to_check.append(f)
    else:
        for f in sorted(os.listdir(folder)):
            f = os.path.join(folder, f)
            if isAppropriateFile(f) and not isGeneratedFile(f):
                files_to_check.append(f)

    return files_to_check


# Check the given file.
def checkFile(filename):
    # Check file exists - e.g. may have been deleted in a recent commit.
    if not os.path.exists(filename):
        print(filename, 'does not exist!')
        return

    file = findStrings(filename)
    file.spellCheck()



#################################################################
# Main logic.

# command-line args.  Controls which files should be checked.
# If no args given, will just scan epan/dissectors folder.
parser = argparse.ArgumentParser(description='Check spellings in specified files')
parser.add_argument('--file', action='append',
                    help='specify individual file to test')
parser.add_argument('--folder', action='store', default='',
                    help='specify folder to test')
parser.add_argument('--no-recurse', action='store_true', default='',
                    help='do not recurse inside chosen folder')
parser.add_argument('--commits', action='store',
                    help='last N commits to check')
parser.add_argument('--open', action='store_true',
                    help='check open files')

args = parser.parse_args()


# Get files from wherever command-line args indicate.
files = []
if args.file:
    # Add specified file(s)
    for f in args.file:
        if not os.path.isfile(f):
            print('Chosen file', f, 'does not exist.')
            exit(1)
        else:
            files.append(f)
elif args.commits:
    # Get files affected by specified number of commits.
    command = ['git', 'diff', '--name-only', 'HEAD~' + args.commits]
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Filter files
    files = list(filter(lambda f : os.path.exists(f) and isAppropriateFile(f) and not isGeneratedFile(f), files))
elif args.open:
    # Unstaged changes.
    command = ['git', 'diff', '--name-only']
    files = [f.decode('utf-8')
             for f in subprocess.check_output(command).splitlines()]
    # Filter files.
    files = list(filter(lambda f : isAppropriateFile(f) and not isGeneratedFile(f), files))
    # Staged changes.
    command = ['git', 'diff', '--staged', '--name-only']
    files_staged = [f.decode('utf-8')
                    for f in subprocess.check_output(command).splitlines()]
    # Filter files.
    files_staged = list(filter(lambda f : isAppropriateFile(f) and not isGeneratedFile(f), files_staged))
    for f in files_staged:
        if not f in files:
            files.append(f)
else:
    # By default, scan dissectors directory
    folder = os.path.join('epan', 'dissectors')
    # But overwrite with any folder entry.
    if args.folder:
        folder = args.folder
        if not os.path.isdir(folder):
            print('Folder', folder, 'not found!')
            exit(1)

    # Find files from folder.
    print('Looking for files in', folder)
    files = findFilesInFolder(folder, not args.no_recurse)


# If scanning a subset of files, list them here.
print('Examining:')
if args.file or args.folder or args.commits or args.open:
    if files:
        print(' '.join(files), '\n')
    else:
        print('No files to check.\n')
else:
    print('All dissector modules\n')


# Now check the chosen files.
for f in files:
    # Check this file.
    checkFile(f)
    # But get out if control-C has been pressed.
    if should_exit:
        exit(1)



# Show the most commonly not-recognised words.
print('')
counter = Counter(missing_words).most_common(100)
if len(counter) > 0:
    for c in counter:
        print(c[0], ':', c[1])

# Show error count.
print('\n' + bcolors.BOLD + str(len(missing_words)) + ' issues found' + bcolors.ENDC + '\n')
