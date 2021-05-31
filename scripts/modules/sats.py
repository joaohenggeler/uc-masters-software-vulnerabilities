#!/usr/bin/env python3

"""
	This module defines a class that represents any third-party tool used to perform static analysis on a project's source files.
"""

import os
import re
import subprocess
from typing import Optional, Tuple, Union

import bs4 # type: ignore
import pandas as pd # type: ignore

from .common import log, GLOBAL_CONFIG, delete_directory, delete_file, get_path_in_data_directory
from .project import Project

####################################################################################################

class Sat():
	""" Represents a third-party static analysis tool (SAT) and allows the execution of its commands. """

	config: dict

	name: str
	executable_path: str
	version: Optional[str]

	project: Project

	def __init__(self, name: str, project: Project):

		self.config = GLOBAL_CONFIG['sats'][name]
		self.name = name
		self.executable_path = self.config['executable_path']
		self.version = None
		self.project = project

	def __str__(self):
		return self.name

	def get_version(self) -> str:
		""" Gets the tool's version number. """
		return self.version or 'Unknown'

	def run(self, *args) -> Tuple[bool, str]:
		""" Runs the tool with a series of command line arguments. """

		arguments = [self.executable_path] + [arg for arg in args]
		result = subprocess.run(arguments, capture_output=True, text=True)
		success = result.returncode == 0

		if not success:
			command_line_arguments = ' '.join(arguments)
			error_message = result.stderr or result.stdout
			log.error(f'Failed to run the command "{command_line_arguments}" with the error code {result.returncode} and the error message "{error_message}".')

		return (success, result.stdout)

####################################################################################################

class UnderstandSat(Sat):
	""" Represents the Understand tool, which is used to generate software metrics given a project's source files. """

	use_new_database_format: bool
	database_extension: str

	def __init__(self, project: Project):
		super().__init__('Understand', project)
		
		version_success, build_number = self.run('version')
		if version_success:
			
			build_number = re.findall(r'\d+', build_number)[0]
			self.version = build_number
			
			self.use_new_database_format = int(build_number) >= 1039 # Understand 6.0 or later.
			self.database_extension = '.und' if self.use_new_database_format else '.udb'

	def generate_project_metrics(self, file_path_list: Union[list, bool], output_csv_path: str) -> bool:
		""" Generates the project's metrics using the files and any other options defined in the database directory. """
	
		"""
			Understand Metrics Settings:
			- WriteColumnTitles				on/off (default on)
			- ShowFunctionParameterTypes	on/off (default off)
			- ShowDeclaredInFile			on/off (default off)
			- FileNameDisplayMode			NoPath/FullPath/RelativePath (default NoPath)
			- DeclaredInFileDisplayMode		NoPath/FullPath/RelativePath (default NoPath)
			- OutputFile					<CSV File Path> (default "<Database Name>.csv")
			
			These were listed using the command: und list -all settings <Database Name>
		"""

		database_path = os.path.join(self.project.output_directory_path, self.project.short_name + self.database_extension)

		if isinstance(file_path_list, bool):
			file_path_list = [self.project.repository_path]

		success, _ = self.run	(
									'-quiet', '-db', database_path,
									'create', '-languages', 'c++', # This value cannot be self.project.language since only "c++" is accepted.
									'settings', '-metrics', 'all',
												'-metricsWriteColumnTitles', 'on',
												'-metricsShowFunctionParameterTypes', 'on',
												'-metricsShowDeclaredInFile', 'on',
												'-metricsFileNameDisplayMode', 'NoPath',
												'-metricsDeclaredInFileDisplayMode', 'FullPath', # See below.
												'-metricsOutputFile', output_csv_path,

									'add', *file_path_list,
									'analyze',
									'metrics'
								)

		if success:
			
			metrics = pd.read_csv(output_csv_path, dtype=str)

			# Ideally, we'd just set the "DeclaredInFileDisplayMode" option to "RelativePath" and skip this step. However, doing that would
			# lead to a few cases where the relative path to the file in the repository was incorrect.
			metrics['File'] = metrics['File'].map(lambda x: self.project.get_relative_path_in_repository(x) if pd.notna(x) else x)

			metrics.to_csv(output_csv_path, index=False)

		if self.use_new_database_format:
			delete_directory(database_path)
		else:
			delete_file(database_path)

		return success

####################################################################################################

class CppcheckSat(Sat):
	""" Represents the Cppcheck tool, which is used to generate security alerts given a project's source files. """

	RULE_TO_CWE: dict = {}
	mapped_rules_to_cwes: bool = False

	def __init__(self, project: Project):
		super().__init__('Cppcheck', project)

		version_success, version_number = self.run('--version')
		if version_success:
			version_number = re.findall(r'\d+\.\d+', version_number)[0]
			self.version = version_number

		if not CppcheckSat.mapped_rules_to_cwes:
			CppcheckSat.mapped_rules_to_cwes = True

			error_list_file_path = get_path_in_data_directory('cppcheck_error_list.xml')

			with open(error_list_file_path) as xml_file:
				error_soup = bs4.BeautifulSoup(xml_file, 'xml')

			if error_soup is not None:
				error_list = error_soup.find_all('error', id=True, cwe=True)				
				CppcheckSat.RULE_TO_CWE = {error['id']: error['cwe'] for error in error_list}
			else:
				log.error(f'Failed to map a list of SAT rules in "{error_list_file_path}" to their CWE values.')

	def generate_project_alerts(self, file_path_list: Union[list, bool], output_csv_path: str) -> bool:
		""" Generates the project's alerts given list of files. """

		if self.project.include_directory_path is not None:
			include_arguments = ['-I', self.project.include_directory_path]
		else:
			include_arguments = ['--suppress=missingInclude']

		if isinstance(file_path_list, bool):
			file_path_list = [self.project.repository_path]

		# The argument "--enable=error" is not necessary since it's enabled by default.
		# @Future: Should "--force" be used? If so, remove "--suppress=toomanyconfigs".
		success, _ = self.run	(
									'--quiet',
									'--enable=warning,portability', '--inconclusive',
									f'--language={self.project.language}', *include_arguments,
									'--suppress=toomanyconfigs', '--suppress=unknownMacro', '--suppress=unmatchedSuppression',
									
									'--template="{file}","{line}","{column}","{severity}","{id}","{cwe}","{message}"',
									f'--output-file={output_csv_path}',
									*file_path_list
								)

		if success:
			alerts = pd.read_csv(output_csv_path, header=None, names=['File', 'Line', 'Column', 'Severity', 'Rule', 'CWE', 'Message'], dtype=str)

			alerts['File'] = alerts['File'].map(lambda x: None if x == 'nofile' else self.project.get_relative_path_in_repository(x))
			alerts['Line'] = alerts['Line'].replace({'0': None})
			alerts['Column'] = alerts['Column'].replace({'0': None})
			alerts['CWE'] = alerts['CWE'].replace({'0': None})

			alerts.to_csv(output_csv_path, index=False)

		return success

	def read_and_convert_output_csv_in_default_format(self, csv_file_path: str) -> pd.DataFrame:
		""" Reads a CSV file generated using Cppcheck's default output parameters and converts it to a more convenient format. """

		# The default CSV files generated by Cppcheck don't quote values with commas correctly.
		# This means that pd.read_csv() would fail because some lines have more columns than others.
		# We'll read each line ourselves and interpret anything after the fourth column as being part
		# of the "Message" column.
		dictionary_list = []
		with open(csv_file_path, 'r') as csv_file:
			
			for line in csv_file:
				filepath_and_line, severity, rule, message = line.split(',', 3)
				file_path, line = filepath_and_line.rsplit(':', 1)
				message = message.rstrip()

				dictionary_list.append({'File': file_path, 'Line': line, 'Severity': severity, 'Rule': rule, 'Message': message})

		alerts = pd.DataFrame.from_dict(dictionary_list, dtype=str)

		alerts['File'] = alerts['File'].map(lambda x: None if x == 'nofile' else self.project.get_relative_path_in_repository(x))
		alerts['CWE'] = alerts['Rule'].map(lambda x: CppcheckSat.RULE_TO_CWE.get(x, ''))
		
		return alerts

if __name__ == '__main__':
	pass