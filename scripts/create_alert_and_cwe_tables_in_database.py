#!/usr/bin/env python3

"""
	@TODO
"""

from modules.common import log, GLOBAL_CONFIG
from modules.database import Database
from modules.project import Project
from modules.sats import Sat

####################################################################################################

def create_alert_and_cwe_tables_in_database() -> None:

	with Database() as db:
		
		log.info('Creating the VULNERABILITY_CATEGORIES table.')

		success, error_code = db.execute_query(	'''
												CREATE TABLE IF NOT EXISTS VULNERABILITY_CATEGORIES
												(
													ID_CATEGORY INTEGER AUTO_INCREMENT PRIMARY KEY,
													NAME VARCHAR(50) NOT NULL UNIQUE
												);
												''')

		if not success:
			log.error(f'Failed to create the VULNERABILITY_CATEGORIES table with the error code {error_code}.')
			return

		##################################################

		log.info('Creating the CWE_INFO table.')

		success, error_code = db.execute_query(	'''
												CREATE TABLE IF NOT EXISTS CWE_INFO
												(
													V_CWE VARCHAR(10) PRIMARY KEY,
													DESCRIPTION VARCHAR(1000),
													ID_CATEGORY INTEGER,

													FOREIGN KEY (ID_CATEGORY) REFERENCES VULNERABILITY_CATEGORIES(ID_CATEGORY) ON DELETE RESTRICT ON UPDATE RESTRICT
												);
												''')

		if not success:
			log.error(f'Failed to create the CWE_INFO table with the error code {error_code}.')
			return

		log.info('Changing the V_CWE foreign key in the VULNERABILITIES table.')

		success, error_code = db.execute_query(	'''
												ALTER TABLE VULNERABILITIES
												ADD CONSTRAINT FK_CWE_INFO_VULNERABILITIES
												FOREIGN KEY (V_CWE) REFERENCES CWE_INFO (V_CWE);
												''')

		if not success:
			log.error(f'Failed to change the V_CWE foreign key in the VULNERABILITIES table with the error code {error_code}.')
			return

		##################################################

		log.info('Inserting the default values in the VULNERABILITY_CATEGORIES and CWE_INFO tables.')

		for category, cwe_list in GLOBAL_CONFIG['vulnerability_categories'].items():
							
			success, error_code = db.execute_query(	'INSERT INTO VULNERABILITY_CATEGORIES (NAME) VALUES (%(NAME)s);',
													params={'NAME': category})

			if not success:
				log.error(f'Failed to insert the vulnerability category "{category}" with the error code {error_code}.')
				return

			category_id = db.cursor.lastrowid

			for cwe in cwe_list:

				success, error_code = db.execute_query(	'INSERT INTO CWE_INFO (V_CWE, ID_CATEGORY) VALUES (%(V_CWE)s, %(ID_CATEGORY)s);',
														params={'V_CWE': cwe, 'ID_CATEGORY': category_id})

				if not success:
					log.error(f'Failed to insert the CWE {cwe} for the category "{category}" ({category_id}) with the error code {error_code}.')
					return

		##################################################

		log.info('Creating the SAT table.')

		success, error_code = db.execute_query(	'''
												CREATE TABLE IF NOT EXISTS SAT
												(
													SAT_ID INTEGER AUTO_INCREMENT PRIMARY KEY,
													SAT_NAME VARCHAR(50) NOT NULL UNIQUE
												);
												''')

		if not success:
			log.error(f'Failed to create the SAT table with the error code {error_code}.')
			return

		log.info('Inserting the default values in the SAT table.')

		sat_list = Sat.get_sat_info_from_config()

		for sat in sat_list:

			success, error_code = db.execute_query(	'INSERT INTO SAT (SAT_NAME) VALUES (%(SAT_NAME)s);',
													params={'SAT_NAME': sat.database_name})

			if not success:
				log.error(f'Failed to insert the SAT "{sat.database_name}" with the error code {error_code}.')
				return

		##################################################

		log.info('Creating the RULE table.')

		success, error_code = db.execute_query(	'''
												CREATE TABLE IF NOT EXISTS RULE
												(
													RULE_ID INTEGER AUTO_INCREMENT PRIMARY KEY,
													RULE_NAME VARCHAR(100) NOT NULL,
													RULE_CATEGORY VARCHAR(50) NOT NULL,

													SAT_ID INTEGER NOT NULL,

													UNIQUE KEY (RULE_NAME, SAT_ID),
													
													FOREIGN KEY (SAT_ID) REFERENCES SAT(SAT_ID) ON DELETE RESTRICT ON UPDATE RESTRICT
												);
												''')

		if not success:
			log.error(f'Failed to create the RULE table with the error code {error_code}.')
			return

		##################################################

		log.info('Creating the RULE_CWE_INFO table.')

		success, error_code = db.execute_query(	'''
												CREATE TABLE IF NOT EXISTS RULE_CWE_INFO
												(
													RULE_ID INTEGER,
													V_CWE INTEGER,
													
													PRIMARY KEY (RULE_ID, V_CWE),

													FOREIGN KEY (RULE_ID) REFERENCES RULE(RULE_ID) ON DELETE RESTRICT ON UPDATE RESTRICT,
													FOREIGN KEY (V_CWE) REFERENCES CWE_INFO(V_CWE) ON DELETE RESTRICT ON UPDATE RESTRICT
												);
												''')

		if not success:
			log.error(f'Failed to create the RULE_CWE_INFO table with the error code {error_code}.')
			return

		##################################################

		project_list = Project.get_project_list_from_config()
		foreign_key_template = ''
		
		for project in project_list:
			foreign_key_template += f'FOREIGN KEY (<UNIT_ID>) REFERENCES <UNIT_TABLE>_{project.database_id}(<UNIT_ID>) ON DELETE RESTRICT ON UPDATE RESTRICT,'
		
		foreign_key_template = foreign_key_template.rstrip(',')

		##################################################

		log.info('Creating the ALERT table.')

		file_foreign_key = foreign_key_template.replace('<UNIT_ID>', 'ID_File').replace('<UNIT_TABLE>', 'FILES')

		success, error_code = db.execute_query(f'''
												CREATE TABLE IF NOT EXISTS ALERT
												(
													ALERT_ID INTEGER AUTO_INCREMENT PRIMARY KEY,
													ALERT_SEVERITY_LEVEL INTEGER,
													ALERT_LINE INTEGER NOT NULL,
													ALERT_MESSAGE VARCHAR(1000),

													R_ID INTEGER NOT NULL,
													P_COMMIT VARCHAR(200) NOT NULL,

													RULE_ID INTEGER NOT NULL,
													ID_File INTEGER NOT NULL,
													
													FOREIGN KEY (RULE_ID) REFERENCES RULE(RULE_ID) ON DELETE RESTRICT ON UPDATE RESTRICT,
													{file_foreign_key}
												);
												''')

		if not success:
			log.error(f'Failed to create the ALERT table with the error code {error_code}.')
			return

		##################################################

		# @TODO: Two junction tables that associate the ALERT to multiple functions and classes (ALERT_ID <-> ID_Function, ALERT_ID <-> ID_Class).

		log.info('Creating the ALERT_FUNCTION table.')

		function_foreign_key = foreign_key_template.replace('<UNIT_ID>', 'ID_Function').replace('<UNIT_TABLE>', 'FUNCTIONS')

		success, error_code = db.execute_query(f'''
												CREATE TABLE IF NOT EXISTS ALERT_FUNCTION
												(
													ALERT_ID INTEGER,
													ID_Function INTEGER,
													
													PRIMARY KEY (ALERT_ID, ID_Function),

													FOREIGN KEY (ALERT_ID) REFERENCES ALERT(ALERT_ID) ON DELETE RESTRICT ON UPDATE RESTRICT,
													{function_foreign_key}
												);
												''')

		if not success:
			log.error(f'Failed to create the ALERT_FUNCTION table with the error code {error_code}.')
			return

		##################################################

		log.info('Creating the ALERT_CLASS table.')

		class_foreign_key = foreign_key_template.replace('<UNIT_ID>', 'ID_Class').replace('<UNIT_TABLE>', 'CLASSES')

		success, error_code = db.execute_query(f'''
												CREATE TABLE IF NOT EXISTS ALERT_CLASS
												(
													ALERT_ID INTEGER,
													ID_Class INTEGER,
													
													PRIMARY KEY (ALERT_ID, ID_Class),

													FOREIGN KEY (ALERT_ID) REFERENCES ALERT(ALERT_ID) ON DELETE RESTRICT ON UPDATE RESTRICT,
													{class_foreign_key}
												);
												''')

		if not success:
			log.error(f'Failed to create the ALERT_CLASS table with the error code {error_code}.')
			return

		##################################################

		log.info('Committing changes.')
		db.commit()

create_alert_and_cwe_tables_in_database()

log.info('Finished running.')
print('Finished running.')
