#!/usr/bin/env python
import os
import sys

import estagio

"""
	This script imports the EXTRA-TIME-FILES tables from the software vulnerability and metrics dataset into a MySQL database
	called 'software'. This database must have been previously created. The MySQL server must be started before using this script.

	Usage:
		import-extra-time-files.py [Optional Dataset Root Directory Path]

		This path should point to the root dataset directory (e.g. "dumps everythink"). If it's not specified, it will default
		to the current working directory.
"""

script_name = sys.argv[0]
num_args = len(sys.argv) - 1

if num_args not in [0, 1]:
	print(f'Wrong number of arguments. Usage: {script_name} [Optional Dataset Root Directory Path]')
	sys.exit(1)

dataset_path = sys.argv[1] if num_args > 0 else ''

# ----------------------------------------

SQL_SCRIPTS_BY_PROJECT = {

	'derby': [	'EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql',
				'EXTRA-TIME-FILES1002.sql', 'EXTRA-TIME-FILES1003.sql'],

	'glibc': ['EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql'],

	'httpd': ['EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql'],

	'kernel': ['EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql'],

	'mozilla': ['EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql'],

	'tomcat': [	'EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql',
				'EXTRA-TIME-FILES1002.sql', 'EXTRA-TIME-FILES1003.sql'],

	'xen': ['EXTRA-TIME-FILES1000.sql', 'EXTRA-TIME-FILES1001.sql'],
	
}

database_config = estagio.load_database_config()
host = database_config['host']
port = database_config['port']
user = database_config['user']
password = database_config['password']
database = database_config['database']

# ----------------------------------------

for project, script_list in SQL_SCRIPTS_BY_PROJECT.items():

	for script in script_list:

		script_path = os.path.join(dataset_path, 'scripts', project, script)
		command = f'mysql --host={host} --port={port} --user={user} --password={password} --default-character-set=utf8 --comments "{database}" < "{script_path}"'

		print(f'Executing the SQL script "{script_path}"...')
		print(f'> {command}')
		print()

		os.system(command)

		print()

print('Finished running.')
