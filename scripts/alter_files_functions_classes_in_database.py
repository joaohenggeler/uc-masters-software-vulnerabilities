#!/usr/bin/env python3

"""
	This script changes both the primary and foreign keys of the FILES_*, FUNCTIONS_*, and CLASSES_* tables by removing the trailing
	repository ID (R_ID) digits.
"""

from modules.common import log, DATABASE_CONFIG
from modules.database import Database

####################################################################################################

def alter_files_functions_classes_in_database() -> None:

	with Database() as db:

		log.info('Changing the primary key in the CLASSES_* tables.')

		database_name = DATABASE_CONFIG['database']
		row_list = []
		
		##################################################

		success, error_code = db.execute_query(	'''
												SELECT TABLE_NAME, CONCAT('UPDATE ', TABLE_NAME, ' SET ID_File = ID_File / 100;') AS QUERY
												FROM INFORMATION_SCHEMA.TABLES
												WHERE TABLE_NAME LIKE 'FILES%'
												AND TABLE_TYPE = 'BASE TABLE'
												AND TABLE_SCHEMA = %(database_name)s
												ORDER BY TABLE_NAME;
												''',
												params={'database_name': database_name})

		if success:
			row_list.extend([row for row in db.cursor])
		else:
			log.error(f'Failed to build the queries to change the primary key in the FILES_* tables with the error code {error_code}.')
			return	

		##################################################

		success, error_code = db.execute_query(	'''
												SELECT TABLE_NAME, CONCAT('UPDATE ', TABLE_NAME, ' SET ID_Function = ID_Function / 100, ID_Class = ID_Class / 100, ID_File = ID_File / 100;') AS QUERY
												FROM INFORMATION_SCHEMA.TABLES
												WHERE TABLE_NAME LIKE 'FUNCTIONS%'
												AND TABLE_TYPE = 'BASE TABLE'
												AND TABLE_SCHEMA = %(database_name)s
												ORDER BY TABLE_NAME;
												''',
												params={'database_name': database_name})

		if success:
			row_list.extend([row for row in db.cursor])
		else:
			log.error(f'Failed to build the queries to change the primary key in the FUNCTIONS_* tables with the error code {error_code}.')
			return

		##################################################

		success, error_code = db.execute_query(	'''
												SELECT TABLE_NAME, CONCAT('UPDATE ', TABLE_NAME, ' SET ID_Class = ID_Class / 100, ID_File = ID_File / 100;') AS QUERY
												FROM INFORMATION_SCHEMA.TABLES
												WHERE TABLE_NAME LIKE 'CLASSES%'
												AND TABLE_TYPE = 'BASE TABLE'
												AND TABLE_SCHEMA = %(database_name)s
												ORDER BY TABLE_NAME;
												''',
												params={'database_name': database_name})

		if success:
			row_list.extend([row for row in db.cursor])
		else:
			log.error(f'Failed to build the queries to change the primary key in the CLASSES_* tables with the error code {error_code}.')
			return

		##################################################

		log.info(f'Changing a total of {len(row_list)} tables.')

		for row in row_list:

			table = row['TABLE_NAME']
			query = row['QUERY']

			log.info(f'Changing the primary key for the table "{table}" using the query "{query}".')

			success, error_code = db.execute_query(query)

			if not success:
				log.error(f'Failed to change the primary key for the table "{table}" with the error code {error_code}.')
				return

		##################################################

		log.info('Committing changes.')
		db.commit()

alter_files_functions_classes_in_database()

log.info('Finished running.')
print('Finished running.')
