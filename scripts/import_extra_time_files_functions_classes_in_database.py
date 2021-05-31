#!/usr/bin/env python3

"""
	This script imports the EXTRA_TIME_FILES, *_FUNCTIONS, and *_CLASSES tables into the database. This is done by using the SQL scripts present in
	the dataset's directory. Note that this process takes a long time to complete.

	@TODO: Replace the test case with the real paths.
"""

import glob
import os

from modules.common import log, GLOBAL_CONFIG
from modules.database import Database
from modules.project import Project

####################################################################################################

with Database() as db:

	project_name_list = [project.database_name for project in Project.get_project_list_from_config()]

	script_pattern = os.path.join(GLOBAL_CONFIG['dataset_path'], '**', r'EXTRA-TIME-*.sql')

	for script_path in glob.iglob(script_pattern, recursive=True):

		directory_name = os.path.basename(os.path.dirname(script_path))
		if directory_name in project_name_list:

			success, output = db.execute_script('C:\\Work\\GitHub\\estagio-software-vulnerabilities-2020-2021\\scripts\\modules\\test_cases\\test.sql')

			if success:
				log.info(f'Imported the data from "{script_path}" successfully.')
			else:
				log.error(f'Failed to import the data from "{script_path}": {output}')

print('Finished running.')
