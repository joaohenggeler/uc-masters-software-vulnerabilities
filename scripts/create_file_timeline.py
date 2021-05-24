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

CSV_WRITE_FREQUENCY = GLOBAL_CONFIG['affected_files_csv_write_frequency']

for project in project_list:

	for input_csv_path in project.find_output_csv_files('affected-files'):

		log.info(f'Creating the file timeline for the project "{project}" using the information in "{input_csv_path}".')

		affected_files = pd.read_csv(input_csv_path, dtype=str)

		vulnerable_commit_list = affected_files['Vulnerable Commit Hash'].drop_duplicates().tolist()
		neutral_commit_list = affected_files['Neutral Commit Hash'].drop_duplicates().tolist()

		assert len(vulnerable_commit_list) == len(neutral_commit_list), 'The number of vulnerable and neutral commits must be the same.'

		Commit = namedtuple('Commit', ['TopologicalIndex', 'Affected', 'Vulnerable', 'CommitHash'])
		topological_index = 0

		first_commit = project.find_first_git_commit_hash()
		commit_list = [Commit(topological_index, False, False, first_commit)]
		topological_index += 1

		for vulnerable_commit, neutral_commit in zip(vulnerable_commit_list, neutral_commit_list):

			commit_list.append(Commit(topological_index, True, True, vulnerable_commit))
			topological_index += 1

			commit_list.append(Commit(topological_index, True, False, neutral_commit))
			topological_index += 1

		timeline = pd.DataFrame(columns=['File Path', 'Changed Lines', 'Topological Index', 'Vulnerable', 'Commit Hash'])
		output_csv_path = replace_in_filename(input_csv_path, 'affected-files', 'file-timeline')

		for index, (from_commit, to_commit) in enumerate(zip(commit_list, commit_list[1:])):

			for file_path, from_changed_lines, to_changed_lines in project.find_changed_source_files_and_lines_between_git_commits(from_commit.CommitHash, to_commit.CommitHash):

				row = {
					'File Path': file_path,
					'Changed Lines': serialize_json_container(from_changed_lines),
					'Topological Index': from_commit.TopologicalIndex,
					'Vulnerable': 'Yes' if from_commit.Vulnerable else 'No',
					'Commit Hash': from_commit.CommitHash
				}

				timeline = timeline.append(row, ignore_index=True)

				if from_commit.Vulnerable:

					row = {
						'File Path': file_path,
						'Changed Lines': serialize_json_container(to_changed_lines),
						'Topological Index': to_commit.TopologicalIndex,
						'Vulnerable': 'Yes' if to_commit.Vulnerable else 'No',
						'Commit Hash': to_commit.CommitHash
					}

					timeline = timeline.append(row, ignore_index=True)

			if index % CSV_WRITE_FREQUENCY == 0:
				log.info(f'Updating the results with basic commit information for the index {index}...')
				timeline.to_csv(output_csv_path, index=False)

		timeline.to_csv(output_csv_path, index=False)
		
	log.info(f'Finished running for the project "{project}".')

print('Finished running.')
