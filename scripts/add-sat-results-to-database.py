#!/usr/bin/env python
import estagio
import sys
import mysql.connector
import glob
import pandas as pd

"""
	@TODO

	Requirements:

	pip install mysql-connector-python
	pip install pandas
	pip install xlrd
"""

database_config = estagio.load_database_config()

try:
	print('Connecting to the database...')
	connection = mysql.connector.connect(**database_config)
	cursor = connection.cursor(prepared=True)
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to connect to the database with the error: {error_string}')
	sys.exit(1)

# --------------------------------------------------

try:
	print('Creating the SAT table...')
	cursor.execute(	'''
						CREATE TABLE IF NOT EXISTS sat
						(
							SAT_ID INTEGER AUTO_INCREMENT PRIMARY KEY,
							SAT_NAME VARCHAR(50) NOT NULL UNIQUE
						);
					''')

	connection.commit()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to create the SAT table with the error: {error_string}')
	sys.exit(1)

# --------------------------------------------------

try:
	print('Creating the Rules table...')
	cursor.execute(	'''
						CREATE TABLE IF NOT EXISTS rule
						(
							RULE_ID INTEGER AUTO_INCREMENT PRIMARY KEY,
							RULE_NAME VARCHAR(100) NOT NULL UNIQUE,
							RULE_CATEGORY VARCHAR(50) NOT NULL,

							SAT_ID INTEGER NOT NULL,
							V_CWE INTEGER,
							
							FOREIGN KEY (SAT_ID) REFERENCES sat(SAT_ID) ON DELETE RESTRICT ON UPDATE RESTRICT
						);
					''')
	# FOREIGN KEY (V_CWE) REFERENCES cwe_info(V_CWE) ON DELETE RESTRICT ON UPDATE RESTRICT

	connection.commit()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to create the Rules table with the error: {error_string}')
	sys.exit(1)

# --------------------------------------------------

try:
	print('Creating the Alerts table...')
	cursor.execute(	'''
						CREATE TABLE IF NOT EXISTS alert
						(
							ALERT_ID INTEGER AUTO_INCREMENT PRIMARY KEY,
							ALERT_SEVERITY_LEVEL INTEGER,
							ALERT_LINE INTEGER NOT NULL,
							ALERT_MESSAGE VARCHAR(1000),

							RULE_ID INTEGER NOT NULL,
							ID_File INTEGER NOT NULL,
							
							FOREIGN KEY (RULE_ID) REFERENCES rule(RULE_ID) ON DELETE RESTRICT ON UPDATE RESTRICT
						);
					''')

	connection.commit()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to create the Alerts table with the error: {error_string}')
	sys.exit(1)

# --------------------------------------------------
print()

SAT_RESULTS_DIRCTORY = 'sat-results'
SAT_NAMES = ['Cppcheck', 'Flawfinder']

try:
	print('Inserting the following SATs in the SAT table:')
	print(SAT_NAMES)
	
	name_list = [(name,) for name in SAT_NAMES]
	cursor.executemany(	'''
							INSERT IGNORE INTO sat (SAT_NAME)
							VALUES (%s);
						''',
						name_list)

	connection.commit()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to insert the SATs with the error: {error_string}')
	sys.exit(1)

print()
print(f'---> Adding SAT results to the database:')
print()

cppcheck_results = glob.iglob(fr'{SAT_RESULTS_DIRCTORY}\cppcheck*')
INSERT_FREQUENCY = 4000

for results_path in cppcheck_results:
	
	# For now, we'll assume it's an Excel .xlsx file.
	results = pd.read_excel(results_path, sheet_name='All Alerts', na_values=['None', 'CWE not found'])

	print(f'Adding the {len(results)} Cppcheck results from "{results_path}"...')

	for index, row in results.iterrows():

		if index % INSERT_FREQUENCY == 0:

			commit = row['commit']
			filename_loc = row['filename-loc']
			category = row['severity']
			rule_name = row['id']
			message = row['message']
			cwe = row['cwe']

			file_path, line = filename_loc.split(':', 1)

			try:
				cursor.execute(	'''
									INSERT IGNORE INTO rule (RULE_NAME, RULE_CATEGORY, SAT_ID, V_CWE)
									VALUES
									(
										%s,
										%s,
										(SELECT SAT_ID FROM sat WHERE SAT_NAME = 'Cppcheck' LIMIT 1),
										%s
									);
								''',
								(rule_name, category, cwe))

				connection.commit()
			except mysql.connector.Error as error:
				error_string = repr(error)
				print(f'Failed to insert the rule "{rule_name}" with the error: {error_string}')

			try:
				print(f'- Inserting alert #{index} in the file "{file_path}"...')

				cursor.execute(	'''
									INSERT INTO alert (ALERT_LINE, ALERT_MESSAGE, RULE_ID, ID_File)
									VALUES
									(
										%s,
										%s,
										(SELECT RULE_ID FROM rule WHERE RULE_NAME = %s LIMIT 1),
										(
											SELECT ID_File FROM
											(
												SELECT * FROM files_1_dom
												UNION ALL
												SELECT * FROM files_1_javascript
												UNION ALL
												SELECT * FROM files_1_javascript_extras
												UNION ALL
												SELECT * FROM files_1_javascript_xpconnect
												UNION ALL
												SELECT * FROM files_1_layout_rendering
												UNION ALL
												SELECT * FROM files_1_libraries
												UNION ALL
												SELECT * FROM files_1_mozilla
												UNION ALL
												SELECT * FROM files_1_network
												UNION ALL
												SELECT * FROM files_1_toolkit
												UNION ALL
												SELECT * FROM files_1_webpage_structure
												UNION ALL
												SELECT * FROM files_1_widget
											) all_files
											WHERE FilePath = %s
											LIMIT 1
										)
									);
								''',
								(line, message, rule_name, file_path))

				connection.commit()
			except mysql.connector.Error as error:
				error_string = repr(error)
				print(f'Failed to insert the alert #{index} with the error: {error_string}')

print()

print('Finished running.')
