#!/usr/bin/env python3
import estagio
import sys
import mysql.connector
from mysql.connector import errorcode as MySqlErrorCodes
import requests
from bs4 import BeautifulSoup, NavigableString

"""
	This script queries the software vulnerability database for any CVE record that is missing its respective CWE value.
	This value is then scraped from the CVE Details website and added to the 'V_CWE' column in the 'VULNERABILITIES' table.

	Requirements:

	pip install mysql-connector-python
	pip install requests
	pip install beautifulsoup4
"""

database_config = estagio.load_database_config()

try:
	print('Connecting to the database...')
	connection = mysql.connector.connect(**database_config)
	query_cursor = connection.cursor(buffered=True)
	update_cursor = connection.cursor(buffered=True)
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to connect to the database with the error: {error_string}')
	sys.exit(1)

try:
	print('Adding the V_CWE column to the vulnerabilities table...')
	query_cursor.execute(	'''
								ALTER TABLE VULNERABILITIES
								ADD COLUMN V_CWE INTEGER AFTER CVE;
							''')
	connection.commit()
except mysql.connector.Error as error:

	if error.errno == MySqlErrorCodes.ER_DUP_FIELDNAME:
		print('The V_CWE column already exists.')
	else:
		error_string = repr(error)
		print(f'Failed to add the V_CWE column with the error: {error_string}')
		sys.exit(1)

try:
	print('Finding any CVEs without an associated CWE...')
	query_cursor.execute(	'''
								SELECT CVE
								FROM VULNERABILITIES
								WHERE CVE IS NOT NULL AND V_CWE IS NULL;
							''')
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to query CVEs without an associated CWE with the error: {error_string}')
	sys.exit(1)

HTTP_HEADERS = {
	'Accept-Language': 'en-US',
	'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
}

i = 0
total_rows = query_cursor.rowcount
progress_update_every = 150

if total_rows > 0:
	print(f'Fetching {total_rows} CWE values from the CVE Details website (progress marker every {progress_update_every} values)...')
else:
	print('No new values to fetch since every CVE has a corresponding CWE entry.')

for result_set in query_cursor:

	i += 1
	if i == 1 or i % progress_update_every == 0:
		percentage = i / total_rows * 100
		print(f'- Fetching progress at {i} of {total_rows} ({percentage:.2f}%)...')

	cve = result_set[0]

	try:
		url = f'https://www.cvedetails.com/cve/{cve}'
		response = requests.get(url, headers=HTTP_HEADERS)
		response.raise_for_status()
	except Exception as error:
		error_string = repr(error)
		print(f'Failed to download the CVE page for {cve} with the error: {error_string}')
		continue

	cwe = None
	soup = BeautifulSoup(response.text, 'html.parser')

	"""
	<table id="cvssscorestable" class="details">
		<tbody>
			<tr>
				[...]
			</tr>

			[If it exists]
			<tr>
				<th>CWE ID</th>
				<td><a href="//www.cvedetails.com/cwe-details/200/cwe.html" title="CWE-200 - CWE definition">200</a></td>
			</tr>
			
			[If it doesn't]
			<tr>
				<th>CWE ID</th>
				<td>CWE id is not defined for this vulnerability</td>
			</tr>
		</tbody>
	</table>
	"""

	scores_table = soup.find('table', id='cvssscorestable')
	if scores_table is not None:
		
		for scores in scores_table:

			# Skip any text between the HTML tags.
			if isinstance(scores, NavigableString):
				continue

			score_name = scores.find('th')
			if score_name is not None and score_name.get_text(strip=True) == 'CWE ID':
					
				score_value = scores.find('a')
				if score_value is not None:

					cwe = score_value.get_text(strip=True)

	if cwe is None:
		cwe = -1

	try:
		update_cursor.execute(	'''
									UPDATE VULNERABILITIES
									SET V_CWE = %s
									WHERE CVE = %s;
								''',
								(cwe, cve))

		connection.commit()
	except mysql.connector.Error as error:
		error_string = repr(error)
		print(f'Failed to update {cve} with the CWE value {cwe} in the database with the error: {error_string}')

try:
	query_cursor.close()
	update_cursor.close()
	connection.close()
except mysql.connector.Error as error:
	error_string = repr(error)
	print(f'Failed to close the connection to the database with the error: {error_string}')

print('Finished running.')
