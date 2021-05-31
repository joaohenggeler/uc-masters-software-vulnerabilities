#!/usr/bin/env python3

"""
	This script creates a timeline of files starting at each project's first commit and going through every commit that was affected
	by a vulnerability.

	This script uses the CSV files generated after running "find_affected_files.py" to creates its own CSVs.
"""

from collections import namedtuple

import pandas as pd # type: ignore

from modules.common import log, GLOBAL_CONFIG, replace_in_filename, serialize_json_container
from modules.project import Project

####################################################################################################

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

CSV_WRITE_FREQUENCY = 1 # GLOBAL_CONFIG['affected_files_csv_write_frequency']

for project in project_list:

	for input_csv_path in project.find_output_csv_files('affected-files'):

		log.info(f'Creating the file timeline for the project "{project}" using the information in "{input_csv_path}".')

		affected_files = pd.read_csv(input_csv_path, dtype=str)

		vulnerable_commit_list = affected_files['Vulnerable Commit Hash'].drop_duplicates().tolist()
		neutral_commit_list = affected_files['Neutral Commit Hash'].drop_duplicates().tolist()

		assert len(vulnerable_commit_list) == len(neutral_commit_list), 'The number of vulnerable and neutral commits must be the same.'

		Commit = namedtuple('Commit', ['TopologicalIndex', 'Vulnerable', 'CommitHash', 'TagName', 'AuthorDate'])
		topological_index = 0

		def create_commit_tuple(commit_hash: str, vulnerable: bool) -> Commit:

			tag_name = project.find_tag_name_from_git_commit_hash(commit_hash)
			author_date = project.find_author_date_from_git_commit_hash(commit_hash)

			global topological_index
			commit = Commit(topological_index, vulnerable, commit_hash, tag_name, author_date)
			topological_index += 1

			return commit

		first_commit = project.find_first_git_commit_hash()
		commit_list = [create_commit_tuple(first_commit, False)]

		for vulnerable_commit, neutral_commit in zip(vulnerable_commit_list, neutral_commit_list):

			commit_list.append(create_commit_tuple(vulnerable_commit, True))
			commit_list.append(create_commit_tuple(neutral_commit, False))

		timeline = pd.DataFrame(columns=[	'File Path', 'Topological Index',
											'Affected', 'Vulnerable', 'Commit Hash',
											'Tag Name', 'Author Date',
											'Changed Lines', 'Affected Functions', 'Affected Classes', 'CVEs'])
		
		output_csv_path = replace_in_filename(input_csv_path, 'affected-files', 'file-timeline')

		for index, (from_commit, to_commit) in enumerate(zip(commit_list, commit_list[1:])):

			assert (from_commit.Vulnerable and not to_commit.Vulnerable) or (not from_commit.Vulnerable and to_commit.Vulnerable)

			for file_path, from_changed_lines, to_changed_lines in project.find_changed_source_files_and_lines_between_git_commits(from_commit.CommitHash, to_commit.CommitHash):

				if to_commit.Vulnerable:

					is_affected_file = (affected_files['File Path'] == file_path) & (affected_files['Vulnerable Commit Hash'] == to_commit.CommitHash)

					if is_affected_file.any():
						continue

				first_row = {
					'File Path': file_path,
					'Topological Index': from_commit.TopologicalIndex,
					'Affected': 'Yes' if from_commit.Vulnerable else 'No',
					'Vulnerable': 'Yes' if from_commit.Vulnerable else 'No',
					'Commit Hash': from_commit.CommitHash,
					'Tag Name': from_commit.TagName,
					'Author Date': from_commit.AuthorDate,
					'Changed Lines': serialize_json_container(from_changed_lines),
				}

				second_row = None

				if from_commit.Vulnerable:

					is_affected_file = (affected_files['File Path'] == file_path) & (affected_files['Vulnerable Commit Hash'] == from_commit.CommitHash)
					file = affected_files[is_affected_file].iloc[0]

					first_row['Affected Functions'] = file['Vulnerable File Functions']
					first_row['Affected Classes'] = file['Vulnerable File Classes']
					first_row['CVEs'] = file['CVEs']

					second_row = {
						'File Path': file_path,
						'Topological Index': to_commit.TopologicalIndex,
						'Affected': 'Yes',
						'Vulnerable': 'No',
						'Commit Hash': to_commit.CommitHash,
						'Tag Name': to_commit.TagName,
						'Author Date': to_commit.AuthorDate,
						'Changed Lines': serialize_json_container(to_changed_lines),
						'Affected Functions': file['Neutral File Functions'],
						'Affected Classes': file['Neutral File Classes'],
						'CVEs': file['CVEs'],
					}
					
				timeline = timeline.append(first_row, ignore_index=True)
				if second_row is not None:
					timeline = timeline.append(second_row, ignore_index=True)

			if index % CSV_WRITE_FREQUENCY == 0:
				log.info(f'Updating the results with basic commit information for the index {index}...')
				timeline.to_csv(output_csv_path, index=False)

		timeline.drop_duplicates(subset=['File Path', 'Topological Index', 'Affected'], inplace=True)
		timeline.to_csv(output_csv_path, index=False)
		
	log.info(f'Finished running for the project "{project}".')

print('Finished running.')
