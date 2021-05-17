#!/usr/bin/env python3

"""
	This module defines a class that represents a MySQL database connection and that contains methods for querying its information.
"""

import os
import sys
from typing import Iterator, Optional, Tuple, Union

from mysql.connector import MySQLConnection, Error as MySQLError # type: ignore
from mysql.connector.cursor import MySQLCursor # type: ignore

from .common import log, GLOBAL_CONFIG, DATABASE_CONFIG

class Database:
	""" Represents a connection to the software vulnerability MySQL database. """

	connection: MySQLConnection
	cursor: MySQLCursor

	input_directory_path: str

	def __init__(self, config: dict = DATABASE_CONFIG, **kwargs):

		try:
			log.info(f'Connecting to the database with the following configurations: {config}')
			self.connection = MySQLConnection(**config)
			self.cursor = self.connection.cursor(dictionary=True, **kwargs)

			log.info(f'Autocommit is {self.connection.autocommit}.')

			self.input_directory_path = os.path.abspath(GLOBAL_CONFIG['output_directory_path'])

		except MySQLError as error:
			log.error(f'Failed to connect to the database with the error: {repr(error)}')
			sys.exit(1)

	def __enter__(self):
		return self

	def __exit__(self, exception_type, exception_value, traceback):

		try:
			self.cursor.close()
			self.connection.close()
		except MySQLError as error:
			log.error(f'Failed to close the connection to the database with the error: {repr(error)}')

	def execute_query(self, query: str, commit: bool = False, **kwargs) -> Tuple[bool, Optional[int]]:
		""" Executes a given SQL query and optionally commits the results. """

		try:
			self.cursor.execute(query, **kwargs)
			if commit:
				self.connection.commit()
			
			success = True
			error_code = None
		
		except MySQLError as error:
			success = False
			error_code = error.errno
			log.warning(f'Failed to execute the query "{query}" with the error: {repr(error)}')

		return (success, error_code)

	def commit(self) -> bool:
		""" Commits the current transaction. """

		try:
			self.connection.commit()
			success = True
		except MySQLError as error:
			success = False
			log.error(f'Failed to perform the commit with the error: {repr(error)}')

		return success

	'''
	def load_csv_file_into_table(self, csv_file_path: str, table: str) -> bool:
		""" @TODO """

		self.execute_query(r"""
								LOAD DATA INFILE %s
								IGNORE
								INTO TABLE %s 
								FIELDS TERMINATED BY ',' 
								OPTIONALLY ENCLOSED BY '"'
								LINES TERMINATED BY '\n'
								IGNORE 1 LINES
								(V_ID, CVE, ID_ADVISORIES, V_CLASSIFICATION, V_IMPACT, VULNERABILITY_URL, PRODUCTS, Affects)
							""",
							(csv_file_path, table))
	'''
