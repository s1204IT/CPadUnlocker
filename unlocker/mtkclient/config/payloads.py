#!/usr/bin/env python3

import os

class pathconfig:
    def __init__(self):
        curscript = os.path.realpath(__file__)
        self.scriptpath = os.path.dirname(curscript)

    def get_loader_path(self):
        return os.path.abspath(os.path.join(self.scriptpath,"..","Loader"))

    def get_payloads_path(self):
        return os.path.abspath(os.path.join(self.scriptpath,"..","payloads"))

