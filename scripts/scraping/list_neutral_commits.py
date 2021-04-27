#!/usr/bin/env python3

"""
	This script lists any neutral commits affected by vulnerabilities associated with the five C/C++ projects.
	
	This script uses the CSV files generated after running "find_affected_files.py" to creates its own CSVs.
"""

from common_scraping import Project

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:
	project.list_and_save_neutral_commits_to_csv_file()
	
print('Finished running')
