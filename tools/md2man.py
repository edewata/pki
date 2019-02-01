# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2019 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import argparse
import logging
import re
import subprocess
import tempfile


def process(input, output):

    pattern = re.compile(r'( *)(.*)')
    result = ''

    for line in input:

        # strip EOL but don't strip trailing spaces
        # since they are used as line breaks in Markdown
        line = line.rstrip('\n')

        # replace leading spaces with &nbsp;
        match = pattern.match(line)
        if match:
            spaces = match.group(1)
            prefix = '&nbsp;' * len(spaces)
            line = prefix + match.group(2)

        print(line, file=output)

    return result


if __name__ == '__main__':

    logging.basicConfig(format='%(levelname)s: %(message)s')

    parser = argparse.ArgumentParser(description='Convert Markdown document to Man page')
    parser.add_argument('input', help='Input file')
    parser.add_argument('output', help='Ouput file')
    parser.add_argument('-v', '--verbose', action='store_true', help='Run in verbose mode')
    parser.add_argument('--debug', action='store_true', help='Run in debug mode')

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.INFO)

    elif args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    with open(args.input) as input, tempfile.NamedTemporaryFile('w') as temp:

        logging.info('Loading Markdown document: %s', args.input)
        process(input, temp)

        logging.info('Generating Man page: %s', args.output)

        cmd = [
            'go-md2man',
            '-in', temp.name,
            '-out', args.output
        ]

        logging.debug('Command: %s', ' '.join(cmd))

        subprocess.check_call(cmd)
