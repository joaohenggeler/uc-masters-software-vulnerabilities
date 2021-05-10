#!/usr/bin/env python3

"""
	This script makes the following structural changes to the VULNERABILITIES table in the database:
	- Adds columns that represent each vulnerability's CWE (V_CWE) and project (R_ID.
	- Sets the values of the R_ID column and adds a foreign key relationship that references the project's in the REPOSITORIES_SAMPLE table.
"""

from mysql.connector.errorcode import ER_DUP_FIELDNAME # type: ignore

from modules.common import log
from modules.database import Database

####################################################################################################

with Database() as db:

	log.info('Adding the CWE column to the VULNERABILITIES table.')

	success, error_code = db.execute_query(	'''
											ALTER TABLE VULNERABILITIES
											ADD COLUMN V_CWE INTEGER AFTER CVE;
											''')

	if not success and error_code != ER_DUP_FIELDNAME:
		log.error(f'Failed to add the CWE column with the error code {error_code}.')

	##################################################

	log.info('Adding the repository ID column to the VULNERABILITIES table.')

	success, error_code = db.execute_query(	'''
											ALTER TABLE VULNERABILITIES
											ADD COLUMN R_ID TINYINT NOT NULL AFTER V_ID;
											''')

	if not success and error_code != ER_DUP_FIELDNAME:
		log.error(f'Failed to add the repository ID column with the error code {error_code}.')

	##################################################

	log.info('Adding the repository ID foreign key to the VULNERABILITIES table.')

	success, error_code = db.execute_query(	'''
											ALTER TABLE VULNERABILITIES
											ADD CONSTRAINT FK_R_ID_REPOSITORY
											FOREIGN KEY (R_ID) REFERENCES REPOSITORIES_SAMPLE (R_ID)
											ON DELETE RESTRICT ON UPDATE RESTRICT;
											''')

	if not success and error_code != ER_DUP_FIELDNAME:
			log.error(f'Failed to add the repository ID foreign key with the error code {error_code}.')

	##################################################

	log.info('Setting the repository ID values based on the vulnerability IDs in the VULNERABILITIES table.')

	PREFIX_TO_ID = {'vuln': 1, 'ker': 2, 'xen': 3, 'httpd': 4, 'glibc': 5, 'tomcat': 6, 'derby': 7}

	for prefix, id in PREFIX_TO_ID.items():

		success, error_code = db.execute_query(	'''
												UPDATE VULNERABILITIES
												SET R_ID = %(id)s
												WHERE REGEXP_SUBSTR(V_ID, '^[a-z]+') = %(prefix)s;
												''',
												params={'id': id, 'prefix': prefix})

		if not success:
			log.error(f'Failed to set the repository ID for the prefix "{prefix}" ({id}) with the error code {error_code}.')

	db.commit()

log.info('Finished running.')
print('Finished running.')
