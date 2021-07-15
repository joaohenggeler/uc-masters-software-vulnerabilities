#!/usr/bin/env python3

"""
	@TODO
"""

from collections import namedtuple

import numpy as np # type: ignore
import pandas as pd # type: ignore

from modules.common import log
from modules.database import Database
from modules.project import Project

####################################################################################################

with Database(buffered=True) as db:

	CodeUnit = namedtuple('CodeUnit', ['Kind', 'ExtraTimeTable', 'MetricsTablePrefix', 'MetricsTablePrimaryKey'])

	FILE_UNIT_INFO = 		CodeUnit('file', 		'EXTRA_TIME_FILES', 		'FILES_', 		'ID_File')
	FUNCTION_UNIT_INFO = 	CodeUnit('function', 	'EXTRA_TIME_FUNCTIONS', 	'FUNCTIONS_', 	'ID_Function')
	CLASS_UNIT_INFO = 		CodeUnit('class', 		'EXTRA_TIME_CLASS', 		'CLASSES_', 	'ID_Class')

	UNDERSTAND_TO_DATABASE_COLUMN = {
		'HenryKafura': 'HK',
		'MaxInheritanceTree': 'DIT',
		'CountClassDerived': 'NOC',
		'CountClassBase': 'CBC',
		'CountDeclMethodAll': 'RFC',
		'CountClassCoupled': 'CBO',
		'PercentLackOfCohesion': 'LCOM',
	}

	project_list = Project.get_project_list_from_config()
	for project in project_list:
		
		for unit_info in [FILE_UNIT_INFO, CLASS_UNIT_INFO, FUNCTION_UNIT_INFO]:

			is_function = (unit_info.Kind == 'function')
			is_class = (unit_info.Kind == 'class')
			unit_metrics_table = unit_info.MetricsTablePrefix + project.database_id

			success, error_code = db.execute_query(f'SELECT MAX({unit_info.MetricsTablePrimaryKey} DIV 100) + 1 AS NEXT_ID FROM {unit_metrics_table};')

			assert db.cursor.rowcount != -1, 'The database cursor must be buffered.'

			next_id = None

			if success and db.cursor.rowcount > 0:
				row = db.cursor.fetchone()
				next_id = int(row['NEXT_ID'])
				log.info(f'Found the next {unit_info.Kind} metrics ID {next_id} for the project "{project}".')
			else:
				log.error(f'Failed to find the next {unit_info.Kind} metrics ID for the project "{project}" with the error code {error_code}.')
				continue

			def get_next_unit_metrics_table_id() -> int:
				""" @TODO """
				global next_id
				result = next_id * 100 + project.database_id
				next_id += 1
				return result

			for input_csv_path in project.find_output_csv_files(f'{unit_info.Kind}-metrics', subdirectory=f'{unit_info.Kind}_metrics'):

				log.info(f'Inserting the {unit_info.Kind} metrics for the project "{project}" using the information in "{input_csv_path}".')

				metrics = pd.read_csv(input_csv_path, dtype=str)
				
				commit_hash = metrics['Commit Hash'].iloc[0]
				affected_commit = metrics['Affected'].iloc[0] == 'Yes'
				vulnerable_commit = metrics['Vulnerable'].iloc[0] == 'Yes'

				success, error_code = db.execute_query(f'''
														SELECT E.* FROM {unit_info.ExtraTimeTable} AS E
														INNER JOIN PATCHES AS P ON E.P_ID = P.P_ID
														WHERE P.R_ID = %(R_ID)s AND P.P_COMMIT = %(P_COMMIT)s
														LIMIT 1;
														''',
														params={'R_ID': project.database_id, 'P_COMMIT': commit_hash})

				if not success:
					log.error(f'Failed to find any existing {unit_info.Kind} metrics for the commit {commit_hash} ({affected_commit}, {vulnerable_commit}) in the project "{project}" with the error code {error_code}.')
					continue
				elif db.cursor.rowcount > 0:
					row = db.cursor.fetchone()
					patch_id = row['P_ID']
					log.info(f'Skipping the {unit_info.Kind} metrics for the commit {commit_hash} ({patch_id}, {affected_commit}, {vulnerable_commit}) in the project "{project}" since it already exists.')
					continue

				# Remove column name spaces for itertuples().
				metrics.columns = metrics.columns.str.replace(' ', '')

				metric_names = metrics.columns.values.tolist()
				first_metric_index = metric_names.index('File') + 1
				metric_names = metric_names[first_metric_index:]

				for row in metrics.itertuples():

					# @TODO:
					# - Set the P_ID to the correct value.
					# - Set ID_File for functions and classes.
					# - Figure out how we're going to set Patched.
					# - Handle row.VulnerableCodeUnit being NA.
					# - Build the insert query dynamically (i.e. include all metrics).

					# File: ID_File, R_ID, P_ID, FilePath, Patched, Occurrence, Affected, [METRICS]
					# Function: ID_Function, R_ID, P_ID, ID_Class, ID_File, Visibility, Complement, NameMethod, FilePath, Patched, Occurrence, Affected, [METRICS]
					# Class: ID_Class, R_ID, P_ID, ID_File, Visibility, Complement, NameClass, FilePath, Patched, Occurrence, Affected, [METRICS]

					vulnerable_code_unit = (row.VulnerableCodeUnit == 'Yes')

					# Columns in common:
					query_params = {
						unit_info.MetricsTablePrimaryKey: get_next_unit_metrics_table_id(),
						'R_ID': project.database_id,
						'FilePath': row.File,
						'Patched': 1 XXX, # If the code unit was changed.
						'Occurrence': 'before' if vulnerable_commit else 'after',
						'Affected': 1 if vulnerable_code_unit else 0, # If the code unit is vulnerable or not.
					}

					if is_function or is_class:
						query_params['Visibility'] = row.Visibility
						query_params['Complement'] = row.Complement

					if is_function:
						query_params['NameMethod'] = row.Name
						query_params[CLASS_UNIT_INFO.MetricsTablePrimaryKey] = -1
					elif is_class:
						query_params['NameClass'] = row.Name

					for name in metric_names:
						column_name = UNDERSTAND_TO_DATABASE_COLUMN.get(name, name)
						query_params[column_name] = getattr(row, name)
						

					"""
					file_id_subquery = f'''
										SELECT F.ID_File FROM {unit_metrics_table} AS F
										INNER JOIN EXTRA_TIME_FILES AS E ON F.ID_File = E.ID_File
										INNER JOIN PATCHES AS P ON E.P_ID = P.P_ID
										WHERE P.R_ID = %(R_ID)s AND P.P_COMMIT = %(P_COMMIT)s AND F.FilePath = %(FilePath)s
										LIMIT 1;
										'''
					"""






					success, error_code = db.execute_query(	'''
															INSERT INTO <FILES_>
															(
																P_ID, P_URL, R_ID, P_COMMIT,
																ERROR_SIMILARITY, SITUATION, RELEASES, DATE, Observations,

																V_ID
															)
															VALUES
															(
																%(P_ID)s, %(P_URL)s, %(R_ID)s, %(P_COMMIT)s,
																%(ERROR_SIMILARITY)s, %(SITUATION)s, %(RELEASES)s, %(DATE)s, %(Observations)s,

																(SELECT V_ID FROM VULNERABILITIES WHERE CVE = %(CVE)s LIMIT 1)
															);
															''',
															
															params={
																'P_ID': get_next_patches_table_id(),
																'P_URL': 'TBD',
																'R_ID': project.database_id,
																'P_COMMIT': commit_hash,
																'ERROR_SIMILARITY': 'TBD',
																'SITUATION': -1,
																'RELEASES': commit_tag_name,
																'DATE': commit_author_date,
																'Observations': 'TBD',
																'CVE': cve,
															}
														)

					if success:
						log.info(f'Inserted the commit {commit_hash} ({commit_tag_name}, {commit_author_date}, {cve}) for the project "{project}".')
					else:
						log.error(f'Failed to insert the commit {commit_hash} ({commit_tag_name}, {commit_author_date}, {cve}) for the project "{project}" with the error code {error_code}.')

	##################################################

	log.info('Committing changes.')
	db.commit()

log.info('Finished running.')
print('Finished running.')
