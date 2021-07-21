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
		
		file_metrics_table = FILE_UNIT_INFO.MetricsTablePrefix + project.database_id
		SELECT_FILE_ID_QUERY = f'''
							SELECT F.ID_File FROM {file_metrics_table} AS F
							INNER JOIN EXTRA_TIME_FILES AS E ON F.ID_File = E.ID_File
							INNER JOIN PATCHES AS P ON E.P_ID = P.P_ID
							WHERE P.R_ID = %(R_ID)s AND P.P_COMMIT = %(P_COMMIT)s
							AND F.FilePath = %(FilePath)s AND F.Occurrence = %(Occurrence)s;
							'''

		for unit_info in [FILE_UNIT_INFO, FUNCTION_UNIT_INFO, CLASS_UNIT_INFO]:

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
				""" Retrieves the next primary key value of the ID_File, ID_Function, or ID_Class column for the current project and code unit table. """
				global next_id
				result = next_id * 100 + project.database_id
				next_id += 1
				return result

			for input_csv_path in project.find_output_csv_files(f'{unit_info.Kind}-metrics', subdirectory=f'{unit_info.Kind}_metrics'):

				log.info(f'Inserting the {unit_info.Kind} metrics for the project "{project}" using the information in "{input_csv_path}".')

				metrics = pd.read_csv(input_csv_path, dtype=str)
				metrics = metrics.replace({np.nan: None})
				
				topological_index = metrics['Topological Index'].iloc[0]
				commit_hash = metrics['Commit Hash'].iloc[0]
				affected_commit = metrics['Affected'].iloc[0] == 'Yes'
				vulnerable_commit = metrics['Vulnerable'].iloc[0] == 'Yes'

				# @TODO: Change this query to list multiple patch IDs.
				success, error_code = db.execute_query(f'''
														SELECT
															(SELECT P_ID FROM PATCHES
														    WHERE R_ID = %(R_ID)s AND P_COMMIT = %(P_COMMIT)s
														    LIMIT 1)
														    AS P_ID,
														    
															(SELECT COUNT(*) > 0 FROM {unit_info.ExtraTimeTable} AS E
															INNER JOIN PATCHES AS P ON E.P_ID = P.P_ID
															WHERE P.R_ID = %(R_ID)s AND P.P_COMMIT = %(P_COMMIT)s
															LIMIT 1)
														    AS PATCH_METRICS_ALREADY_EXIST;
														''',
														params={'R_ID': project.database_id, 'P_COMMIT': commit_hash})

				if not success:
					log.error(f'Failed to find any existing {unit_info.Kind} metrics for the commit {commit_hash} ({topological_index}, {affected_commit}, {vulnerable_commit}) in the project "{project}" with the error code {error_code}.')
					continue

				row = db.cursor.fetchone()
				patch_id = row['P_ID']

				if patch_id is None:
					log.error(f'Could not find any patch with the commit {commit_hash} ({topological_index}, {affected_commit}, {vulnerable_commit}) in the project "{project}".')
					continue

				if row['PATCH_METRICS_ALREADY_EXIST'] == 1:
					log.info(f'Skipping the {unit_info.Kind} metrics for any patch with the commit {commit_hash} ({topological_index}, {patch_id}, {affected_commit}, {vulnerable_commit}) in the project "{project}" since they already exist.')
					continue

				# Remove column name spaces for itertuples().
				metrics.columns = metrics.columns.str.replace(' ', '')

				csv_metric_names = metrics.columns.values.tolist()
				first_metric_index = csv_metric_names.index('File') + 1
				csv_metric_names = csv_metric_names[first_metric_index:]

				# E.g. "CountInput" -> "CountInput"" or "MaxInheritanceTree" -> "DIT".
				database_metric_names = [UNDERSTAND_TO_DATABASE_COLUMN.get(name, name) for name in csv_metric_names]

				cached_file_ids = {}

				for row in metrics.itertuples():

					# @TODO:
					# - Format the patch ID list for the P_ID column if the code unit's commit is associated with more than one vulnerability.

					# File: ID_File, R_ID, P_ID, FilePath, Patched, Occurrence, Affected, [METRICS]
					# Function: ID_Function, R_ID, P_ID, ID_Class, ID_File, Visibility, Complement, NameMethod, FilePath, Patched, Occurrence, Affected, [METRICS]
					# Class: ID_Class, R_ID, P_ID, ID_File, Visibility, Complement, NameClass, FilePath, Patched, Occurrence, Affected, [METRICS]

					vulnerable_code_unit = (row.VulnerableCodeUnit == 'Yes')
					unit_id = get_next_unit_metrics_table_id()

					if row.PatchedCodeUnit == 'Yes':
						patched = 1
					elif row.PatchedCodeUnit == 'No':
						patched = 0
					else:
						patched = 2

					# Columns in common:
					query_params = {
						unit_info.MetricsTablePrimaryKey: unit_id,
						'R_ID': project.database_id,
						'P_ID': patch_id if affected_commit else None,
						'FilePath': row.File,
						'Patched': patched, # If the code unit was changed.
						'Occurrence': 'before' if vulnerable_commit else 'after', # Whether or not this code unit exists before (vulnerable) or after (neutral) the patch.
						'Affected': 1 if vulnerable_code_unit else 0, # If the code unit is vulnerable or not.
					}

					if is_function or is_class:
						query_params['Visibility'] = row.Visibility
						query_params['Complement'] = row.Complement

						file_id = cached_file_ids.get(row.File, -1)
						if file_id == -1:

							success, error_code = db.execute_query(SELECT_FILE_ID_QUERY, params={
																	'R_ID': query_params['R_ID'],
																	'P_COMMIT': commit_hash,
																	'FilePath': query_params['FilePath'],
																	'Occurrence': query_params['Occurrence']
																	})

							if success:
								row = db.cursor.fetchone()
								file_id = row[FILE_UNIT_INFO.MetricsTablePrimaryKey]
							else:
								file_id = None
								log.warning(f'Failed to find the ID for the file "{row.File}" when inserting the {unit_info.Kind} metrics for the unit "{row.Name}" in the commit {commit_hash} ({topological_index}, {patch_id}, {affected_commit}, {vulnerable_commit}).')

							cached_file_ids[row.File] = file_id

						query_params[FILE_UNIT_INFO.MetricsTablePrimaryKey] = file_id

					if is_function:
						query_params['NameMethod'] = row.Name
						query_params[CLASS_UNIT_INFO.MetricsTablePrimaryKey] = -1
					elif is_class:
						query_params['NameClass'] = row.Name

					for database_name, csv_name in zip(database_metric_names, csv_metric_names):
						query_params[database_name] = getattr(row, csv_name)
						
					query = f'INSERT INTO {unit_metrics_table} ( '

					for name in query_params:
						query += f'{name},'

					query = query.rstrip(',')
					query += ') VALUES ( '

					for name in query_params:
						query += f'%({name})s,'

					query = query.rstrip(',')
					query += ');'

					success, error_code = db.execute_query(query, params=query_params)

					if success:
					
						success, error_code = db.execute_query(f'''
																INSERT INTO {unit_info.ExtraTimeTable}
																(
																	P_ID, {unit_info.MetricsTablePrimaryKey}
																)
																VALUES
																(
																	%(P_ID)s, %({unit_info.MetricsTablePrimaryKey})s
																);
																''',
																
																params={
																	'P_ID': patch_id,
																	unit_info.MetricsTablePrimaryKey: unit_id
																}
															)

						if not success:
							log.error(f'Failed to insert the {unit_info.Kind} metrics ID in the {unit_info.ExtraTimeTable} table for the unit "{row.Name}" ({unit_id}) in the file "{row.File}" and commit {commit_hash} ({topological_index}, {patch_id}, {affected_commit}, {vulnerable_commit}) with the error code {error_code}.')

					else:
						log.error(f'Failed to insert the {unit_info.Kind} metrics for the unit "{row.Name}" ({unit_id}) in the file "{row.File}" and commit {commit_hash} ({topological_index}, {patch_id}, {affected_commit}, {vulnerable_commit}) with the error code {error_code}.')

		##################################################

		log.info(f'Committing changes for the project "{project}".')
		db.commit()

log.info('Finished running.')
print('Finished running.')
