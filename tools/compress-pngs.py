#!/usr/bin/env python3
#
# compress-pngs.py - Compress PNGs
#
# By Gerald Combs <gerald@wireshark.org
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
'''Run various compression and optimization utilities on one or more PNGs'''

import argparse
import concurrent.futures
import shutil
import subprocess
import sys

PNG_FILE_ARG = '%PNG_FILE_ARG%'

def get_compressors():
    # Add *lossless* compressors here.
    compressors = {
        # https://github.com/shssoichiro/oxipng
        'oxipng': { 'args': ['--opt', 'max', '--strip', 'safe', PNG_FILE_ARG] },
        # http://optipng.sourceforge.net/
        'optipng': { 'args': ['-o3', '-quiet', PNG_FILE_ARG] },
        # https://github.com/amadvance/advancecomp
        'advpng': { 'args': ['--recompress', '--shrink-insane', PNG_FILE_ARG] },
        # https://github.com/amadvance/advancecomp
        'advdef': { 'args': ['--recompress', '--shrink-insane', PNG_FILE_ARG] },
        # https://pmt.sourceforge.io/pngcrush/
        'pngcrush': { 'args': ['-q', '-ow', '-brute', '-reduce', '-noforce', PNG_FILE_ARG, 'pngcrush.$$$$.png'] },
        # https://github.com/fhanau/Efficient-Compression-Tool
        'ect': { 'args': ['-5', '--mt-deflate', '--mt-file', '-strip', PNG_FILE_ARG]}
    }
    for compressor in compressors:
        compressor_path = shutil.which(compressor)
        if compressor_path:
            compressors[compressor]['path'] = compressor_path
    return compressors


def compress_png(png_file, compressors):
    for compressor in compressors:
        if not compressors[compressor].get('path', False):
            continue

        args = compressors[compressor]['args']
        args = [arg.replace(PNG_FILE_ARG, png_file) for arg in args]

        try:
            compress_proc = subprocess.run([compressor] + args)
        except Exception:
            print('{} returned {}:'.format(compressor, compress_proc.returncode))


def main():
    parser = argparse.ArgumentParser(description='Compress PNGs')
    parser.add_argument('--list', action='store_true',
                        help='List available compressors')
    parser.add_argument('png_files', nargs='*', metavar='png file', help='Files to compress')
    args = parser.parse_args()

    compressors = get_compressors()

    c_count = 0
    for compressor in compressors:
        if 'path' in compressors[compressor]:
            c_count += 1

    if c_count < 1:
        sys.stderr.write('No compressors found\n')
        sys.exit(1)

    if args.list:
        for compressor in compressors:
            path = compressors[compressor].get('path', 'Not found')
            print('{}: {}'.format(compressor, path))
        sys.exit(0)

    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = []
        for png_file in args.png_files:
            print('Compressing {}'.format(png_file))
            futures.append(executor.submit(compress_png, png_file, compressors))
        concurrent.futures.wait(futures)


if __name__ == '__main__':
    main()
