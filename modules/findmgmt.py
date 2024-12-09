#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re

addr = ''
def findmgmt(addr):
    for files in os.walk('configs/'):
        for config in files[2]:
            with open(os.path.join('configs/', config), 'r') as f:
                for line in f.readlines():
                    if re.search(rf'(ip address {addr})(\b|/)', line):
                        return config
    else:
        return addr

if __name__ == '__main__':
    findmgmt(addr)
    