#!/usr/bin/env python3

"""
	This script modifies the ID_File, ID_Function, and ID_Class columns in the FILES_*, FUNCTIONS_*, CLASSES_*, EXTRA_TIME_FILES,
	EXTRA_TIMES_FUNCTIONS, and EXTRA_TIME_CLASS tables by changing their data type to BIGINT.

	Before running this script, the code unit tables must be merged using "merge_files_functions_classes_in_database.py".
"""

from modules.common import log
from modules.database import Database
from modules.project import Project

####################################################################################################

def alter_int_primary_keys_to_big_int_in_database() -> None:

	with Database() as db:

		project_list = Project.get_project_list_from_config()
		for project in project_list:

			for table_prefix, primary_key in [('FILES_', 'ID_File'), ('FUNCTIONS_', 'ID_Function'), ('CLASSES_', 'ID_Class')]:

				table_name = table_prefix + str(project.database_id)

				log.info(f'Modifying the primary key {primary_key} in the table "{table_name}".')
				
				success, error_code = db.execute_query(f'''
														ALTER TABLE {table_name}
														MODIFY COLUMN {primary_key} BIGINT;
														''')

				if not success:
					log.error(f'Failed to modify the primary key in the table "{table_name}" with the error code {error_code}.')
					return

		##################################################

		# Note the 's' in 'ID_Functions' and the singular form of 'CLASS'.
		for table_suffix, primary_key in [('FILES', 'ID_File'), ('FUNCTIONS', 'ID_Functions'), ('CLASS', 'ID_Class')]:

			table_name = 'EXTRA_TIME_' + table_suffix

			log.info(f'Modifying the primary key {primary_key} in the table "{table_name}".')
				
			success, error_code = db.execute_query(f'''
													ALTER TABLE {table_name}
													MODIFY COLUMN {primary_key} BIGINT;
													''')

			if not success:
				log.error(f'Failed to modify the primary key in the table "{table_name}" with the error code {error_code}.')
				return

		##################################################

		log.info('Committing changes.')
		db.commit()

alter_int_primary_keys_to_big_int_in_database()

log.info('Finished running.')
print('Finished running.')
