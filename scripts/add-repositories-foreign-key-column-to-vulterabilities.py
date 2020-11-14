#!/usr/bin/env python
import estagio
import sys
import mysql.connector
from mysql.connector import errorcode as MySqlErrorCodes

"""
	This script adds a new column to the 'VULNERABILITIES' table that represents the foreign key for the 'REPOSITORIES_SAMPLE'
	table (the R_ID column). This value is assigned based on the V_ID prefix in the 'VULNERABILITIES' table. For example, a
	vulnerability with the V_ID 'vuln123' (prefix 'vuln') maps to the Mozilla row in the 'REPOSITORIES_SAMPLE' table.

	Requirements:

	pip install mysql-connector-python
"""

database_config = estagio.load_database_config()

try:
	print('Connecting to the database...')
	connection = mysql.connector.connect(**database_config)
	cursor = connection.cursor()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to connect to the database with the error: {error_string}')
	sys.exit(1)

try:	
	cursor.execute(	'''
						SELECT DISTINCT REGEXP_SUBSTR(V_ID, '[a-z]+') FROM VULNERABILITIES;
					''')

	print('Unique vulnerability prefixes:')
	for i, result_set in enumerate(cursor):
		prefix = result_set[0]
		print(f'{i+1}: "{prefix}"')
	print()

except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to query the unique vulnerability prefixes with the error: {error_string}')

repository_info = {
	'derby': 	{'project': 'Derby', 		'r_id': None},
	'glibc': 	{'project': 'Glibc', 		'r_id': None},
	'httpd': 	{'project': 'Apache', 		'r_id': None},
	'ker': 		{'project': 'Kernel Linux', 'r_id': None},
	'tomcat': 	{'project': 'Tomcat', 		'r_id': None},
	'vuln': 	{'project': 'Mozilla', 		'r_id': None},
	'xen': 		{'project': 'Xen', 			'r_id': None}
}

try:
	print('Mapping the R_ID values in the repositories sample table to the prefixes...')
	cursor.execute(	'''
						SELECT R_ID, PROJECT FROM REPOSITORIES_SAMPLE;
					''')

	for result_set in cursor:
		r_id = result_set[0]
		project = result_set[1]

		for info in repository_info.values():
			if info['project'] == project:
				info['r_id'] = r_id

except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to query the R_ID values from the repositories sample table with the error: {error_string}')

try:
	print('Adding the R_ID foreign key column to the vulnerabilities table...')
	cursor.execute(	'''
						ALTER TABLE VULNERABILITIES
						ADD COLUMN R_ID TINYINT NOT NULL AFTER V_ID;
					''')

	cursor.execute(	'''
						ALTER TABLE VULNERABILITIES
						ADD CONSTRAINT FK_R_ID_REPOSITORY
						FOREIGN KEY (R_ID) REFERENCES REPOSITORIES_SAMPLE (R_ID)
						ON DELETE RESTRICT ON UPDATE RESTRICT;
					''')

	connection.commit()
except mysql.connector.Error as error:

	if error.errno == MySqlErrorCodes.ER_DUP_FIELDNAME:
		print('The R_ID foreign key column already exists.')
	else:
		error_string = repr(error)
		print(f'Failed to add the R_ID foreign key column in the vulnerabilities table with the error: {error_string}')
		sys.exit(1)

print('Updating the R_ID foreign key column in the vulnerabilities table...')
for prefix, info in repository_info.items():

	try:
		r_id = info['r_id']

		cursor.execute(	'''
							UPDATE VULNERABILITIES
							SET R_ID = %s
							WHERE REGEXP_SUBSTR(V_ID, '[a-z]+') = %s;
						''',
						(r_id, prefix))

		connection.commit()
	except mysql.connector.Error as error:
		error_string = repr(error)
		print(f'Failed to update the R_ID foreign key column in the vulnerabilities table with the error: {error_string}')

try:
	cursor.close()
	connection.close()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to close the connection to the database with the error: {error_string}')

print('Finished running.')
