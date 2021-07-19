#!/usr/bin/env python3

"""
	@TODO
"""

import numpy as np # type: ignore
import pandas as pd # type: ignore

from modules.common import log, deserialize_json_container
from modules.database import Database
from modules.project import Project

####################################################################################################

with Database(buffered=True) as db:

	project_list = Project.get_project_list_from_config()
	for project in project_list:
		
		success, error_code = db.execute_query(	'''
												SELECT
													(SELECT MAX(REGEXP_SUBSTR(P_ID, '[0-9]+') + 0) + 1 FROM PATCHES WHERE R_ID = %(R_ID)s) AS NEXT_ID,
													(SELECT REGEXP_REPLACE(P_ID, '[0-9]+', '<ID>') FROM PATCHES WHERE R_ID = %(R_ID)s LIMIT 1) AS ID_TEMPLATE;
												''',
												params={'R_ID': project.database_id})

		assert db.cursor.rowcount != -1, 'The database cursor must be buffered.'

		next_id = None
		id_template = None

		if success and db.cursor.rowcount > 0:
			row = db.cursor.fetchone()
			next_id = int(row['NEXT_ID'])
			id_template = row['ID_TEMPLATE']
			log.info(f'Found the next commit ID {next_id} with the template "{id_template}" for the project "{project}".')
		else:
			log.error(f'Failed to find the next commit ID for the project "{project}" with the error code {error_code}.')
			continue

		def get_next_patches_table_id() -> str:
			""" Retrieves the next primary key value of the P_ID column for the current project. """
			global next_id, id_template
			result = id_template.replace('<ID>', str(next_id))
			next_id += 1
			return result

		for input_csv_path in project.find_output_csv_files('file-timeline'):

			log.info(f'Inserting the commits for the project "{project}" using the information in "{input_csv_path}".')

			commits = pd.read_csv(input_csv_path, usecols=['Affected', 'Commit Hash', 'Tag Name', 'Author Date', 'CVEs'], dtype=str)
			commits.drop_duplicates(subset=['Commit Hash'], inplace=True)
			is_affected_commit = commits['Affected'] == 'Yes'
			commits = commits[is_affected_commit]
			commits = commits.replace({np.nan: None})

			for _, row in commits.iterrows():

				commit_hash = row['Commit Hash']

				success, error_code = db.execute_query('SELECT * FROM PATCHES WHERE P_COMMIT = %(P_COMMIT)s LIMIT 1;', params={'P_COMMIT': commit_hash})

				if db.cursor.rowcount > 0:
					log.info(f'Skipping the commit {commit_hash} for the project "{project}" since it already exists.')
					continue

				commit_tag_name = row['Tag Name']
				commit_author_date = row['Author Date']
				cve_list = deserialize_json_container(row['CVEs'], [None])

				# @TODO: Does this have to insert NxM times, where N are the CVEs and M the various V_IDs associated with each one?
				for cve in cve_list:

					success, error_code = db.execute_query(	'''
															INSERT INTO PATCHES
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
