#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging

import pki
import pki.client as client
import pki.encoder as encoder
import pki.profile as profile

logger = logging.getLogger(__name__)


class CAClient(object):

    def __init__(self, parent):

        self.parent = parent
