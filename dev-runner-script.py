#!/usr/bin/env python3

import os
from sys import stderr
from dotenv import load_dotenv
import subprocess

load_dotenv()

SUPA_KEY = os.getenv('SUPA_SECRET')
INFURA_KEY  = os.getenv('SUPA_SECRET')
script_entry_point = '\\deno-main.ts'
if os.name == 'nt':
    depoyCtlBnloc = 'C:\\Users\\andrei0x309\\.deno\\bin\\deployctl.cmd'
    command = 'set SUPA_KEY={}; set INFURA_KEY={}; {} run addr=:4005 --libs=ns,fetchevent --no-check --watch {}'.format(SUPA_KEY,INFURA_KEY,depoyCtlBnloc,(os.getcwd() + script_entry_point ))
    print(command)
else:
    command = 'SUPA_KEY={} INFURA_KEY={} deployctl run --libs=ns,fetchevent --no-check --watch {}'.format(SUPA_KEY,INFURA_KEY,script_entry_point)

subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
