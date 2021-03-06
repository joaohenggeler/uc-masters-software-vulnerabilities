#!/usr/bin/env python3

"""
	This script collects any vulnerabilities associated with the five C/C++ projects by scraping the CVE Details website.
	
	This information includes the CVE identifier, publish date, CVSS score, various impacts, vulnerability types, the CWE ID, and
	the URLs to other relevant websites like a project's Bugzilla or Security Advisory platforms.

	For each project, this information is saved to a CSV file.
"""

from common_scraping import Project

project_list = Project.get_project_list_from_config()

Project.debug_ensure_all_project_repositories_were_loaded(project_list)

for project in project_list:
	project.collect_and_save_vulnerabilities_to_csv_file()

print('Finished running')
