#!/usr/bin/env python
import estagio
import argparse
import os

"""
	This script imports the software vulnerability and metrics dataset into a MySQL database called 'software'.
	The MySQL server must be started before using this script.

	Usage:
		import-dataset.py 				to import the data without the timeline information (extra_time tables).
		import-dataset.py -complete 	to import the complete dataset, including the timeline information.
"""

# ----------------------------------------

complete_script = 'load-complete-db.sql'
no_timeline_script = 'load-without-timeline-db.sql'

database_config = estagio.load_database_config()
host = database_config['host']
port = database_config['port']
user = database_config['user']
password = database_config['password']

# ----------------------------------------

parser = argparse.ArgumentParser()
parser.add_argument('-complete', action='store_true')
args = parser.parse_args()

if args.complete:
	import_script = complete_script
else:
	import_script = no_timeline_script

command = f'mysql --host={host} --port={port} --user={user} --password={password} --default-character-set=utf8 --comments < {import_script}'

print(command)
os.system(command)
