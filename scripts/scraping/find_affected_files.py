#!/usr/bin/env python3

"""
	@TODO
"""

from common_scraping import DEBUG_ENABLED, Project

project_list = Project.get_project_list_from_config()

if not DEBUG_ENABLED:
	Project.ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:

	print(project)
	project.collect_and_save_affected_files_to_csv_file()

	print()
	print()
		
print('Finished running')
