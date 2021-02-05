#!/usr/bin/env python
import glob
import os
import sys

import mysql.connector
import numpy as np
import pandas as pd

from estagio import load_database_config

"""
	This script adds the contents of any files that were generated by Understand (using the script generate-metrics-results.py) to
	the software vulnerabilities database. These are currently added to a test table called 'FILES_0_netscape'. Only software metrics
	related to files are currently handled.

	The MySQL server must be started before using this script.

	Requirements:

	pip install mysql-connector-python
	pip install numpy
	pip install pandas
"""

DEBUG_MODE = True
if DEBUG_MODE:
	print('[DEBUG MODE IS ENABLED]')
	print()

database_config = load_database_config()

try:
	print('Connecting to the database...')
	connection = mysql.connector.connect(**database_config)
	cursor = connection.cursor(prepared=True)
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to connect to the database with the error: {error_string}')
	sys.exit(1)

# --------------------------------------------------

if DEBUG_MODE:

	try:
		print('Dropping all the test metrics tables...')
		cursor.execute(	'''
							DROP TABLE IF EXISTS FILES_0_netscape;
						''')

		connection.commit()
	except mysql.connector.Error as error:
		error_string = repr(error)
		print(f'Failed to drop all the test metrics tables with the error: {error_string}')
		sys.exit(1)

# --------------------------------------------------

try:
	print('Creating the files table...')
	cursor.execute(	'''
						CREATE TABLE IF NOT EXISTS FILES_0_netscape LIKE FILES_1_mozilla;
					''')

	# For testing purposes: automatically assign the IDs.
	cursor.execute(	'''
						ALTER TABLE FILES_0_netscape MODIFY ID_File INT AUTO_INCREMENT;
					''')

	connection.commit()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to create the files table with the error: {error_string}')
	sys.exit(1)

# --------------------------------------------------
print()

METRICS_RESULTS_PATH = os.path.join('..', 'metrics', '*.csv')
metrics_results_file_list = glob.glob(METRICS_RESULTS_PATH)

for i, results_file_path in enumerate(metrics_results_file_list):
	
	results = pd.read_csv(results_file_path)

	# Replace any N/A values with None.
	results = results.replace({np.nan: None})

	# For testing purposes: only insert some metrics.
	if DEBUG_MODE:
		results = results[::1]

	print(f'Adding the {len(results)} metrics from the file {i+1} of {len(metrics_results_file_list)}: "{results_file_path}"...')

	if DEBUG_MODE:
		print('Unique values in the "Kind" column:')
		print(results['Kind'].unique())
		print()

	for index, row in results.iterrows():

		kind = row['Kind']
		name = row['Name']
		original_file_path = row['File']

		if original_file_path is not None:
			file_path = original_file_path.replace('\\', '/')

		if kind == 'File':

			if DEBUG_MODE:
				print(f'- Inserting metrics for file {index+1}: "{file_path}"...')

			try:
				cursor.execute(	'''
									INSERT INTO FILES_0_netscape
									(
										ID_File, P_ID, FilePath,
										Patched, Occurrence, R_ID, Affected,

										AltAvgLineBlank, AltAvgLineCode, AltAvgLineComment,
										AltCountLineBlank, AltCountLineCode, AltCountLineComment,
										AvgCyclomatic, AvgCyclomaticModified, AvgCyclomaticStrict,
										AvgEssential, AvgLine, AvgLineBlank, AvgLineCode, AvgLineComment, 
										CountDeclClass, CountDeclFunction, CountLine, CountLineBlank,
										CountLineCode, CountLineCodeDecl, CountLineCodeExe, CountLineComment,
										CountLineInactive, CountLinePreprocessor, CountSemicolon, CountStmt,
										CountStmtDecl, CountStmtEmpty, CountStmtExe,
										MaxCyclomatic, MaxCyclomaticModified, MaxCyclomaticStrict,
										MaxEssential, MaxNesting, RatioCommentToCode,
										SumCyclomatic, SumCyclomaticModified, SumCyclomaticStrict, SumEssential,

										CountPath,
										FanIn, FanOut,
										AvgFanIn, AvgFanOut,
										MaxFanIn, MaxFanOut,
										AvgMaxNesting, SumMaxNesting, MaxMaxNesting,
										HK,

										DIT, NOC, CBC,
										RFC, CBO, LCOM
									)
									VALUES
									(
										NULL, NULL, %s,
										NULL, NULL, 0, NULL,

										%s, %s, %s,
										%s, %s, %s,
										%s, %s, %s,
										%s, %s, %s, %s, %s, 
										%s, %s, %s, %s,
										%s, %s, %s, %s,
										%s, %s, %s, %s,
										%s, %s, %s,
										%s, %s, %s,
										%s, %s, %s,
										%s, %s, %s, %s,
										
										%s,
										%s, %s,
										%s, %s,
										%s, %s,
										%s, %s, %s,
										%s,

										%s, %s, %s,
										%s, %s, %s
									);
								''',
								(
									file_path,

									row['AltAvgLineBlank'], row['AltAvgLineCode'], row['AltAvgLineComment'],
									row['AltCountLineBlank'], row['AltCountLineCode'], row['AltCountLineComment'],
									row['AvgCyclomatic'], row['AvgCyclomaticModified'], row['AvgCyclomaticStrict'],
									row['AvgEssential'], row['AvgLine'], row['AvgLineBlank'], row['AvgLineCode'], row['AvgLineComment'], 
									row['CountDeclClass'], row['CountDeclFunction'], row['CountLine'], row['CountLineBlank'],
									row['CountLineCode'], row['CountLineCodeDecl'], row['CountLineCodeExe'], row['CountLineComment'],
									row['CountLineInactive'], row['CountLinePreprocessor'], row['CountSemicolon'], row['CountStmt'],
									row['CountStmtDecl'], row['CountStmtEmpty'], row['CountStmtExe'],
									row['MaxCyclomatic'], row['MaxCyclomaticModified'], row['MaxCyclomaticStrict'],
									row['MaxEssential'], row['MaxNesting'], row['RatioCommentToCode'],
									row['SumCyclomatic'], row['SumCyclomaticModified'], row['SumCyclomaticStrict'], row['SumEssential'],
									
									row['SumCountPath'],
									row['SumCountInput'], row['SumCountOutput'],
									row['AvgCountInput'], row['AvgCountOutput'],
									row['MaxCountInput'], row['MaxCountOutput'],
									row['AvgMaxNesting'], row['SumMaxNesting'], row['MaxMaxNesting'],
									row['HenryKafura'],

									row['MaxInheritanceTree'], row['CountClassDerived'], row['CountClassBase'],
									row['CountDeclMethodAll'], row['CountClassCoupled'], row['PercentLackOfCohesion']
								)
								)

				connection.commit()
			except mysql.connector.Error as error:
				error_string = repr(error)
				print(f'-> Failed to insert the result "{name}" with the error: {error_string}')

		elif 'Function' in kind:
			# To be implemented.
			pass
		elif 'Class' in kind or 'Struct' in kind or 'Union' in kind:
			# To be implemented.
			pass
		else:
			print(f'-> Skipping the unhandled record type "{kind}".')

	print()
	print()

try:
	cursor.close()
	connection.close()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to close the connection to the database with the error: {error_string}')

print('Finished running.')
