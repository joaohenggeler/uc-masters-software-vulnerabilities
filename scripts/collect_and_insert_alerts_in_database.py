#!/usr/bin/env python3

"""
	@TODO
"""

import os
import tempfile
from base64 import b64decode
from collections import namedtuple
from zipfile import ZipFile

import numpy as np # type: ignore
import pandas as pd # type: ignore
from github import Github, GithubException

from modules.common import log, GLOBAL_CONFIG, delete_file
from modules.database import Database
from modules.project import Project
from modules.sats import Sat, CppcheckSat

####################################################################################################

github = Github(GLOBAL_CONFIG['github_token'])
data_repository = github.get_repo(GLOBAL_CONFIG['github_data_repository'])

sat_list = Sat.get_sat_info_from_config()

CommitType = namedtuple('CommitType', ['Vulnerable', 'GithubDataName'])
commit_type_list = [CommitType(True, 'previous_commit'), CommitType(False, 'current_commit')]

with Database(buffered=True) as db:

	project_list = Project.get_project_list_from_config()
	for project in project_list:

		cppcheck = CppcheckSat(project)

		with tempfile.TemporaryDirectory() as temporary_directory_path:

			for sat in sat_list:

				for commit_type in commit_type_list:

					# E.g. "mozilla/cppcheck/complete_scan/current_commit/part1/cppcheck-195-305babb41123e575e6fd6bf4ea4dab2716ce1ecc.csv.zip"
					base_directory = f'{project.github_data_name}/{sat.github_data_name}/complete_scan/{commit_type.GithubDataName}'
					
					try:
						file_list = data_repository.get_contents(base_directory)
					except GithubException as error:
						file_list = []
						log.warning(f'Could not find the directory "{base_directory}" in the repository with the error: {repr(error)}')

					# Traverse the repository and find every file recursively.
					while file_list:

						file = file_list.pop()

						if file.type == 'dir':
							directory_files = data_repository.get_contents(file.path)
							file_list.extend(directory_files)
						else:

							log.info(f'Collecting and inserting the alerts from "{file.path}".')
							
							# E.g. "cppcheck-195-305babb41123e575e6fd6bf4ea4dab2716ce1ecc.csv.zip"
							_, _, commit_hash = file.name.split('-', 2)
							commit_hash, _, _ = commit_hash.rsplit('.', 2)

							# @TODO: Check if we already have one or more alerts with this commit hash.

							success, error_code = db.execute_query('SELECT COUNT(*) > 0 AS ALERTS_ALREADY_EXIST FROM ALERT WHERE R_ID = %(R_ID)s AND P_COMMIT = %(P_COMMIT)s;',
																	params={'R_ID': project.database_id, 'P_COMMIT': commit_hash})

							if not success:
								log.error(f'Failed to query any existing alerts for the commit {commit_hash} ("{file.name}") in the project "{project}" with the error code {error_code}.')
								continue

							row = db.cursor.fetchone()

							if row['ALERTS_ALREADY_EXIST'] == 1:
								log.info(f'Skipping the alerts for the commit {commit_hash} ("{file.name}") in the project "{project}" since they already exist.')
								continue

							zip_file_path = os.path.join(temporary_directory_path, file.name)

							with open(zip_file_path, 'wb') as zip_file:
								zip_data = b64decode(file.content)
								zip_file.write(zip_data)

							with ZipFile(zip_file_path, 'r') as zip_file:
								filenames_in_zip = zip_file.namelist()
								zip_file.extractall(temporary_directory_path)

							csv_file_path = os.path.join(temporary_directory_path, filenames_in_zip[0])

							if sat.database_name == 'Cppcheck':
								alerts = cppcheck.read_and_convert_output_csv_in_default_format(csv_file_path)
							else:
								alerts = pd.read_csv(csv_file_path, dtype=str)

							alerts = alerts.replace({np.nan: None})

							# @TODO

							delete_file(zip_file_path)
							delete_file(csv_file_path)

		##################################################

		log.info(f'Committing changes for the project "{project}".')
		db.commit()

log.info('Finished running.')
print('Finished running.')