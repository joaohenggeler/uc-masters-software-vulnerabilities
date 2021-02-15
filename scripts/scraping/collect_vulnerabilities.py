#!/usr/bin/env python3

"""
	This script collects any vulnerabilities associated with the five C/C++ projects by scraping the CVE Details website.
	
	This information includes the CVE identifier, publish date, CVSS score, various impacts, vulnerability types, the CWE ID, and
	the URLs to other relevant websites like a project's Bugzilla or Security Advisory platforms.

	For each project, this information is saved to a CSV file.

	Requirements:

	pip install beautifulsoup4
	pip install GitPython
	pip install requests
"""

import csv
import json
import random
import re
import sys
from typing import Callable, Optional, Union
from urllib.parse import urlsplit, parse_qsl

import bs4 # type: ignore
import git # type: ignore

from estagio_scraping import load_scraping_config, download_page, get_current_timestamp, change_datetime_string_format

####################################################################################################

PAGE_TITLE_REGEX = re.compile(r'Go to page \d+', re.IGNORECASE)
CVE_REGEX = re.compile(r'(CVE-\d+-\d+)', re.IGNORECASE)

# BUG TRACKERS
BUGZILLA_URL_REGEX = re.compile(r'https?://.*bugzilla.*', re.IGNORECASE)

"""
Examples:
- Mozilla: https://bugzilla.mozilla.org/show_bug.cgi?id=1580506
- Apache: https://bz.apache.org/bugzilla/show_bug.cgi?id=57531
- Glibc: https://sourceware.org/bugzilla/show_bug.cgi?id=24114
"""

# SECURITY ADVISORIES
MFSA_URL_REGEX = re.compile(r'https?://.*mozilla.*security.*mfsa.*', re.IGNORECASE)
MFSA_ID_REGEX = re.compile(r'(mfsa\d+-\d+)', re.IGNORECASE)

XSA_URL_REGEX = re.compile(r'https?://.*xen.*xsa.*advisory.*', re.IGNORECASE)
XSA_ID_REGEX = re.compile(r'advisory-(\d+)', re.IGNORECASE)

APACHE_SECURITY_URL_REGEX = re.compile(r'https?://.*apache.*security.*vulnerabilities.*', re.IGNORECASE)
APACHE_SECURITY_ID_REGEX = re.compile(r'vulnerabilities_(\d+)', re.IGNORECASE)

"""
Examples:
- Mozilla: https://www.mozilla.org/security/advisories/mfsa2019-31/
- Mozilla: http://www.mozilla.org/security/announce/mfsa2005-58.html 
- Xen: https://xenbits.xen.org/xsa/advisory-300.html
- Apache: https://httpd.apache.org/security/vulnerabilities_24.html
"""

# VERSION CONTROL
GIT_URL_REGEX = re.compile(r'https?://.*git.*commit.*', re.IGNORECASE)
GITHUB_URL_REGEX = re.compile(r'https?://.*github\.com.*commit.*', re.IGNORECASE)
SVN_URL_REGEX = re.compile(r'https?://.*svn.*rev.*', re.IGNORECASE)

GIT_COMMIT_HASH_LENGTH = 40
GIT_COMMIT_HASH_REGEX = re.compile(r'([A-Fa-f0-9]{40})', re.IGNORECASE)
SVN_REVISION_NUMBER_REGEX = re.compile(r'(\d+)', re.IGNORECASE)

"""
Examples:
- Linux: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eff73de2b1600ad8230692f00bc0ab49b166512a
- Glibc: https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9

- Linux: https://github.com/torvalds/linux/commit/6ef36ab967c71690ebe7e5ef997a8be4da3bc844
- Apache: https://github.com/apache/httpd/commit/e427c41257957b57036d5a549b260b6185d1dd73 

- Apache: http://svn.apache.org/viewcvs?rev=292949&view=rev
"""

####################################################################################################

scraping_config = load_scraping_config()
if scraping_config is None:
	print('The program will terminate as the configuration file could not be read correctly.')
	sys.exit(1)

DEBUG_MODE = scraping_config['debug']
if DEBUG_MODE:
	print('[DEBUG MODE IS ENABLED]')
	print()

####################################################################################################

class Cve:

	id: str
	url: str
	project: 'Project'

	publish_date: Optional[str]
	last_update_date: Optional[str]

	cvss_score: 				Optional[str]
	confidentiality_impact: 	Optional[str]
	integrity_impact: 			Optional[str]
	availability_impact: 		Optional[str]
	access_complexity: 			Optional[str]
	authentication: 			Optional[str]
	gained_access: 				Optional[str]
	vulnerability_types: 		Optional[list]
	cwe: 						Optional[str]

	affected_products: dict

	bugzilla_urls: list
	bugzilla_ids: list
	advisory_urls: list
	advisory_ids: list

	advisory_info: dict

	git_urls: list
	git_commit_hashes: list
	svn_urls: list
	svn_revision_numbers: list

	def __init__(self, id: str, project: 'Project'):
		self.id = id
		self.url = f'https://www.cvedetails.com/cve/{self.id}'
		self.project = project

		self.cve_details_soup = None

		self.publish_date = None
		self.last_update_date = None

		self.cvss_score = None
		self.confidentiality_impact = None
		self.integrity_impact = None
		self.availability_impact = None
		self.access_complexity = None
		self.authentication = None
		self.gained_access = None
		self.vulnerability_types = None
		self.cwe = None

		self.affected_products = {}

		self.bugzilla_urls = []
		self.bugzilla_ids = []
		self.advisory_urls = []
		self.advisory_ids = []

		self.advisory_info = {}

		self.git_urls = []
		self.git_commit_hashes = []
		self.svn_urls = []
		self.svn_revision_numbers = []

	def __str__(self):
		return self.id

	def download_cve_details_page(self) -> bool:
		response = download_page(self.url)
		if response is not None:
			self.cve_details_soup = bs4.BeautifulSoup(response.text, 'html.parser')
		
		return response is not None

	def scrape_dates_from_page(self):

		"""
		<div class="cvedetailssummary">
			Memory safety bugs were reported in Firefox 57 and Firefox ESR 52.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Thunderbird &lt; 52.6, Firefox ESR &lt; 52.6, and Firefox &lt; 58.	<br>
			<span class="datenote">Publish Date : 2018-06-11	Last Update Date : 2018-08-03</span>
		</div>
		
		"""

		dates_span = self.cve_details_soup.find('span', class_='datenote')
		if dates_span is None:
			print(f'--> No dates span found for {self}.')

		dates_text = dates_span.get_text(strip=True)
		
		cve_dates = {}
		for date in re.split(r'\t+', dates_text):
			key, value = date.split(' : ')
			cve_dates[key] = value

		self.publish_date = cve_dates.get('Publish Date')
		self.last_update_date = cve_dates.get('Last Update Date')

	def scrape_basic_attributes_from_page(self):

		"""
		<table id="cvssscorestable" class="details">
			<tbody>
				<tr>
					<th>CVSS Score</th>
					<td><div class="cvssbox" style="background-color:#ff9c20">7.5</div></td>
				</tr>
				<tr>
					<th>Confidentiality Impact</th>
					<td><span style="color:orange">Partial</span>
					<span class="cvssdesc">(There is considerable informational disclosure.)</span></td>
				</tr>
				<tr>
					<th>Access Complexity</th>
					<td><span style="color:red">Low</span>
					<span class="cvssdesc">(Specialized access conditions or extenuating circumstances do not exist. Very little knowledge or skill is required to exploit. )</span></td>
				</tr>
				<tr>
					<th>Authentication</th>
					<td><span style="color:red">Not required</span>
					<span class="cvssdesc">(Authentication is not required to exploit the vulnerability.)</span></td>
				</tr>
				<tr>
					<th>Gained Access</th>
					<td><span style="color:green;">None</span></td>
				</tr>
				<tr>
					<th>Vulnerability Type(s)</th>
					<td><span class="vt_overflow">Overflow</span><span class="vt_memc">Memory corruption</span></td>
				</tr>
				<tr>
					<th>CWE ID</th>
					<td><a href="//www.cvedetails.com/cwe-details/119/cwe.html" title="CWE-119 - CWE definition">119</a></td>
				</tr>
			</tbody>
		</table>
		"""

		scores_table = self.cve_details_soup.find('table', id='cvssscorestable')
		if scores_table is None:
			print(f'--> No scores table found for {self}.')
			return

		scores_th_list = scores_table.find_all('th')
		scores_td_list = scores_table.find_all('td')

		cve_attributes = {}
		for th, td in zip(scores_th_list, scores_td_list):

			key = th.get_text(strip=True)
			value = None

			if key == 'Vulnerability Type(s)':
				value = [span.get_text(strip=True) for span in td.find_all('span')]
			else:
				span = td.find('span')
				if span is not None:
					value = span.get_text(strip=True)
				else:
					value = td.get_text(strip=True)
			
			cve_attributes[key] = value

		self.cvss_score 			= cve_attributes.get('CVSS Score')
		self.confidentiality_impact = cve_attributes.get('Confidentiality Impact')
		self.integrity_impact 		= cve_attributes.get('Integrity Impact')
		self.availability_impact 	= cve_attributes.get('Availability Impact')
		self.access_complexity 		= cve_attributes.get('Access Complexity')
		self.authentication 		= cve_attributes.get('Authentication')
		self.gained_access 			= cve_attributes.get('Gained Access')
		self.vulnerability_types 	= cve_attributes.get('Vulnerability Type(s)')

		cwe = cve_attributes.get('CWE ID')
		if cwe is not None and not cwe.isnumeric():
			cwe = None
		self.cwe = cwe

	def scrape_affected_product_versions_from_page(self):

		"""
		<table class="listtable" id="vulnprodstable">
			<tbody>
				<tr>
					<th class="num">#</th>
					<th>Product Type</th>
					<th>Vendor</th>
					<th>Product</th>
					<th>Version</th>
					<th>Update</th>
					<th>Edition</th>
					<th>Language</th>
					<th></th>
				</tr>
				<tr>
					<td class="num">1</td>
					<td>Application </td>
					<td><a href="//www.cvedetails.com/vendor/452/Mozilla.html" title="Details for Mozilla">Mozilla</a></td>
					<td><a href="//www.cvedetails.com/product/3264/Mozilla-Firefox.html?vendor_id=452" title="Product Details Mozilla Firefox">Firefox</a></td>
					<td></td>
					<td></td>
					<td></td>
					<td></td>
					<td><a href="/version/12613/Mozilla-Firefox-.html" title="Mozilla Firefox ">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-452/product_id-3264/version_id-12613/Mozilla-Firefox-.html" title="Vulnerabilities of Mozilla Firefox ">Vulnerabilities</a></td>
				</tr>
				<tr>
					<td class="num">2 </td>
					<td>Application </td>
					<td><a href="//www.cvedetails.com/vendor/44/Netscape.html" title="Details for Netscape">Netscape</a></td>
					<td><a href="//www.cvedetails.com/product/64/Netscape-Navigator.html?vendor_id=44" title="Product Details Netscape Navigator">Navigator</a></td>
					<td>7.0.2 </td>
					<td></td>
					<td></td>
					<td></td>
					<td><a href="/version/11359/Netscape-Navigator-7.0.2.html" title="Netscape Navigator 7.0.2">Version Details</a>&nbsp;<a href="/vulnerability-list/vendor_id-44/product_id-64/version_id-11359/Netscape-Navigator-7.0.2.html" title="Vulnerabilities of Netscape Navigator 7.0.2">Vulnerabilities</a></td>
				</tr>
			</tbody>
		</table>
		"""

		products_table = self.cve_details_soup.find('table', id='vulnprodstable')
		if products_table is None:
			print(f'--> No products table found for {self}.')
			return

		# Parse each row in the product table.
		th_list = products_table.find_all('th')
		th_list = [th.get_text(strip=True) for th in th_list]
		column_indexes = {	'vendor': 	th_list.index('Vendor'),
							'product': 	th_list.index('Product'),
							'version': 	th_list.index('Version')}

		tr_list = products_table.find_all('tr')
		for tr in tr_list:

			# Skip the header row.
			if tr.find('th'):
				continue

			td_list = tr.find_all('td')

			# Get a specific cell value and any URL it references from the current row given its column name.
			def get_column_value_and_url(name):
				idx = column_indexes[name]
				td = td_list[idx]

				value = td.get_text(strip=True)
				url = td.find('a', href=True)

				if value in ['', '-']:
					value = None

				if url is not None:
					url = url['href']

				return value, url

			_, vendor_url  = get_column_value_and_url('vendor')
			product, product_url = get_column_value_and_url('product')
			version, _ = get_column_value_and_url('version')

			vendor_pattern = f'/{self.project.vendor_id}/'
			product_pattern = f'/{self.project.product_id}/' if self.project.product_id is not None else ''
			
			# Check if the vendor and product belong to the current project.
			if vendor_pattern in vendor_url and product_pattern in product_url:

				if product not in self.affected_products:
					self.affected_products[product] = []
				
				if version is not None and version not in self.affected_products[product]:
					self.affected_products[product].append(version)

	def scrape_references_from_page(self):

		"""
		<table class="listtable" id="vulnrefstable">
			<tbody>
				<tr>
					<td class="r_average">
						<a href="https://github.com/torvalds/linux/commit/09ccfd238e5a0e670d8178cf50180ea81ae09ae1" target="_blank" title="External url">https://github.com/torvalds/linux/commit/09ccfd238e5a0e670d8178cf50180ea81ae09ae1</a>
						CONFIRM
						<br>
					</td>
				</tr>
				<tr>
					<td class="r_average">
						<a href="https://bugzilla.redhat.com/show_bug.cgi?id=1292045" target="_blank" title="External url">https://bugzilla.redhat.com/show_bug.cgi?id=1292045</a>
						CONFIRM
						<br>
					</td>
				</tr>
			</tbody>
		</table>
		"""

		references_table = self.cve_details_soup.find('table', id='vulnrefstable')
		if references_table is None:
			print(f'--> No references table found for {self}.')
			return

		# Creates a list of URL that match a regex (or a list of regexes). If a handler function is passed as the second argument, then it will be called
		# for each URL in order to create and return a secondary list. This may be used to extract specific parts of the URL.
		def list_all_urls(url_regex: str, url_handler: Callable = None):
			a_list = references_table.find_all('a', href=url_regex)
			
			url_list = []
			for a in a_list:
				url = a['href']
				if re.search(self.project.url_pattern, url, re.IGNORECASE):
					url_list.append(url)

			secondary_list = []
			if url_handler is not None:
				for url in url_list:
					secondary_value = url_handler(url)
					if secondary_value is not None:
						secondary_list.append(secondary_value)

			return url_list, secondary_list

		# Finds the value of the first parameter in a URL's query segment given a list of keys to check. If no value was found, this function returns None.
		def get_query_param(url: str, query_key_list: list) -> Optional[str]:
			split_url = urlsplit(url)
			params = dict(parse_qsl(split_url.query))
			result = None
			
			for query_key in query_key_list:
				result = params.get(query_key)
				if result is not None:
					break

			return result

		#
		# Various helper functions to handle specific URLs from different sources.
		#

		def handle_bugzilla_urls(url: str) -> Optional[str]:
			id = get_query_param(url, ['id', 'bug_id'])
			
			if id is None:
				print(f'--> Could not find a valid Bugzilla ID in "{url}".')

			return id

		def handle_advisory_urls(url: str) -> Optional[str]:
			split_url = urlsplit(url)
			id = None

			for regex in [MFSA_ID_REGEX, XSA_ID_REGEX, APACHE_SECURITY_ID_REGEX]:
				match = regex.search(split_url.path)
				if match is not None:
					id = match.group(1)

					if regex is MFSA_ID_REGEX:
						id = id.upper()
						id = id.replace('MFSA', 'MFSA-')
					elif regex is XSA_ID_REGEX:
						id = 'XSA-' + id
					elif regex is APACHE_SECURITY_ID_REGEX:
						id = 'APACHE-' + id[0] + '.' + id[1:]

					break

			if id is None:
				print(f'--> Could not find a valid advisory ID in "{url}".')

			return id

		def handle_git_urls(url: str) -> Optional[str]:
			commit_hash = get_query_param(url, ['id', 'h'])

			# @TODO: If the hash length is less than 40, we need to refer to
			# the repository to get the full hash.
			if commit_hash is not None and len(commit_hash) < GIT_COMMIT_HASH_LENGTH:
				pass

			if commit_hash is None:
				split_url = urlsplit(url)
				path_components = split_url.path.rsplit('/')
				commit_hash = path_components[-1]

			if not GIT_COMMIT_HASH_REGEX.match(commit_hash):
				commit_hash = None
			
			if commit_hash is None:
				print(f'--> Could not find a valid commit hash in "{url}".')
			
			return commit_hash

		def handle_svn_urls(url: str) -> Optional[str]:
			revision_number = get_query_param(url, ['rev', 'revision', 'pathrev'])

			if revision_number is not None:

				# In some rare cases, the revision number can be prefixed with 'r'.
				# As such, we'll only extract the numeric part of this value.
				match = SVN_REVISION_NUMBER_REGEX.search(revision_number)
				if match is not None:
					# For most cases, this is the same value.
					revision_number = match.group(1)
				else:
					# For cases where the query parameter was not a valid number.
					revision_number = None

			if revision_number is None:
				print(f'--> Could not find a valid revision number in "{url}".')

			return revision_number

		self.bugzilla_urls, self.bugzilla_ids 		= list_all_urls(BUGZILLA_URL_REGEX, handle_bugzilla_urls)
		self.advisory_urls, self.advisory_ids 		= list_all_urls([MFSA_URL_REGEX, XSA_URL_REGEX, APACHE_SECURITY_URL_REGEX], handle_advisory_urls)

		self.git_urls, self.git_commit_hashes 		= list_all_urls([GIT_URL_REGEX, GITHUB_URL_REGEX], handle_git_urls)
		self.svn_urls, self.svn_revision_numbers 	= list_all_urls(SVN_URL_REGEX, handle_svn_urls)

	def serialize_containers(self):

		def json_or_nothing(container: Union[list, dict]) -> Optional[str]:
			# Remove duplicates from lists.
			if isinstance(container, list):
				container = list(dict.fromkeys(container))

			return json.dumps(container) if container else None

		self.vulnerability_types 	= json_or_nothing(self.vulnerability_types)

		self.affected_products 		= json_or_nothing(self.affected_products)

		self.bugzilla_urls 			= json_or_nothing(self.bugzilla_urls)
		self.bugzilla_ids 			= json_or_nothing(self.bugzilla_ids)
		self.advisory_urls 			= json_or_nothing(self.advisory_urls)
		self.advisory_ids 			= json_or_nothing(self.advisory_ids)

		self.advisory_info 			= json_or_nothing(self.advisory_info)

		self.git_urls 				= json_or_nothing(self.git_urls)
		self.git_commit_hashes 		= json_or_nothing(self.git_commit_hashes)
		self.svn_urls 				= json_or_nothing(self.svn_urls)
		self.svn_revision_numbers 	= json_or_nothing(self.svn_revision_numbers)

####################################################################################################

class Project:

	TIMESTAMP = get_current_timestamp()

	full_name: str
	short_name: str
	database_id: int
	vendor_id: int
	product_id: int
	url_pattern: str
	repository_path: str

	csv_filename: str

	def __init__(self, project_name: str, project_info: dict):
		
		self.full_name = project_name
		for key, value in project_info.items():
			setattr(self, key, value)

		try:
			self.repository = git.Repo(self.repository_path)
		except Exception as error:
			error_string = repr(error)
			print(f'Failed to get the repository for the project "{self}"" with the error: {error_string}')

		self.csv_filename = f'{self.database_id}-{self.short_name}-{self.TIMESTAMP}.csv'

	def __str__(self):
		return self.full_name

	@staticmethod
	def get_project_list_from_config(config: dict) -> list:
		
		project_config = config['projects']
		project_list = []

		for full_name, info in project_config.items():

			short_name = info['short_name']
			project: Project
		
			if short_name == 'mozilla':
				project = MozillaProject(full_name, info)
			elif short_name == 'xen':
				project = XenProject(full_name, info)
			else:
				project = Project(full_name, info)

			project_list.append(project)

		return project_list

	def scrape_additional_information_from_security_advisories(self, cve: Cve):
		pass

	def find_git_commit_hashes(self, grep_pattern: str) -> list:
		hash_list = []

		# repository.git.show(f':/{bugzilla_id}', format='oneline', no_patch=True)
		# git log --all --format=oneline --grep="[REGEX]"
		log_result = self.repository.git.log(all=True, format='oneline', grep=grep_pattern)
		
		for line in log_result.splitlines():
			hash, title = line.split(maxsplit=1)
			hash_list.append(hash)

		return hash_list

	def scrape_additional_information_from_version_control(self, cve: Cve):
		pass

	def scrape_vulnerabilities_from_cve_details(self):

		print(f'Collecting the vulnerabilities for the "{self}" project ({self.vendor_id}, {self.product_id}):')
		response = download_page('https://www.cvedetails.com/vulnerability-list.php', {'vendor_id': self.vendor_id, 'product_id': self.product_id})

		if response is None:
			print('Could not download the first hub page. No vulnerabilities will be scraped for this project.')
			return
		
		main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

		page_div = main_soup.find('div', id='pagingb')
		page_a_list = page_div.find_all('a', title=PAGE_TITLE_REGEX)
		page_url_list = ['https://www.cvedetails.com' + page_a['href'] for page_a in page_a_list]

		if DEBUG_MODE:
			previous_len = len(page_url_list)
			page_url_list = page_url_list[::-3]
			print(f'-> [DEBUG] Reduced the number of hub pages from {previous_len} to {len(page_url_list)}.')

		for i, page_url in enumerate(page_url_list):

			print(f'-> Scraping hub page {i+1} of {len(page_url_list)}...')
			page_response = download_page(page_url)
			if page_response is None:
				print(f'-> Failed to download hub page {i+1}.')
				continue
	
			page_soup = bs4.BeautifulSoup(page_response.text, 'html.parser')
			vulnerability_table = page_soup.find('table', id='vulnslisttable')
			cve_a_list = vulnerability_table.find_all('a', title=CVE_REGEX)
			
			# Test a random sample of CVEs from each page.
			if DEBUG_MODE:
				previous_len = len(cve_a_list)
				cve_a_list = random.sample(cve_a_list, 4)
				print(f'--> [DEBUG] Reduced the number of CVE pages from {previous_len} to {len(cve_a_list)}.')

			for j, cve_a in enumerate(cve_a_list):

				cve_id = cve_a.get_text(strip=True)
				cve = Cve(cve_id, self)

				print(f'--> Scraping the CVE page {j+1} of {len(cve_a_list)}: "{cve.id}" from "{cve.url}"...')
				download_success = cve.download_cve_details_page()
				
				if download_success:
					cve.scrape_dates_from_page()
					cve.scrape_basic_attributes_from_page()
					cve.scrape_affected_product_versions_from_page()
					cve.scrape_references_from_page()

					self.scrape_additional_information_from_security_advisories(cve)
					self.scrape_additional_information_from_version_control(cve)
				else:
					print(f'--> Failed to download the page for {cve}.')

				yield cve

	def collect_and_save_vulnerabilities_to_csv_file(self):

		CSV_HEADER = [
			'CVE', 'CVE URL',
			
			'Publish Date', 'Last Update Date',

			'CVSS Score', 'Confidentiality Impact', 'Integrity Impact',
			'Availability Impact', 'Access Complexity', 'Authentication',
			'Gained Access', 'Vulnerability Types', 'CWE',
			
			'Affected Product Versions',

			'Bugzilla URLs', 'Bugzilla IDs',
			'Advisory URLs', 'Advisory IDs', 'Advisory Info',
			'Git URLs', 'Git Commit Hashes',
			'SVN URLs', 'SVN Revision Numbers'
		]

		with open(self.csv_filename, 'w', newline='') as csv_file:

			csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADER)
			csv_writer.writeheader()

			for cve in self.scrape_vulnerabilities_from_cve_details():

				cve.serialize_containers()
				csv_row = {
					'CVE': cve.id, 'CVE URL': cve.url,

					'Publish Date': cve.publish_date, 'Last Update Date': cve.last_update_date,

					'CVSS Score': cve.cvss_score, 'Confidentiality Impact': cve.confidentiality_impact, 'Integrity Impact': cve.integrity_impact,
					'Availability Impact': cve.availability_impact, 'Access Complexity': cve.access_complexity, 'Authentication': cve.authentication,
					'Gained Access': cve.gained_access, 'Vulnerability Types': cve.vulnerability_types, 'CWE': cve.cwe,

					'Affected Product Versions': cve.affected_products,

					'Bugzilla URLs': cve.bugzilla_urls, 'Bugzilla IDs': cve.bugzilla_ids,
					'Advisory URLs': cve.advisory_urls, 'Advisory IDs': cve.advisory_ids, 'Advisory Info': cve.advisory_info,
					'Git URLs': cve.git_urls, 'Git Commit Hashes': cve.git_commit_hashes,
					'SVN URLs': cve.svn_urls, 'SVN Revision Numbers': cve.svn_revision_numbers
				}

				csv_writer.writerow(csv_row)

class MozillaProject(Project):

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Mozilla Foundation Security Advisories (MFSA) pages.
		for mfsa_id, mfsa_url in zip(cve.advisory_ids, cve.advisory_urls):

			mfsa_info = {}
			print(f'--> Scraping additional information from advisory page {mfsa_id}: "{mfsa_url}"...')

			mfsa_response = download_page(mfsa_url)
			if mfsa_response is None:
				print(f'--> Could not download the page for {mfsa_id}.')
				continue

			mfsa_soup = bs4.BeautifulSoup(mfsa_response.text, 'html.parser')

			"""
			[MFSA 2005-01 until (present)]
			<dl class="summary">
				<dt>Announced</dt>
				<dd>November 20, 2012</dd>
				<dt>Reporter</dt>
				<dd>Mariusz Mlynski</dd>
				<dt>Impact</dt>
				<dd><span class="level critical">Critical</span></dd>
				<dt>Products</dt>
				<dd>Firefox, Firefox ESR</dd>
				<dt>Fixed in</dt>
				<dd>
					<ul>
						<li>Firefox 17</li>
						<li>Firefox ESR 10.0.11</li>
					</ul>
				</dd>
			</dl>

			MFSA 2005-01 until MFSA 2016-84]
			<h3>References</h3>

			<p>Crashes referencing removed nodes (Jesse Ruderman, Martijn Wargers)</p>
			<ul>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=338391">https://bugzilla.mozilla.org/show_bug.cgi?id=338391</a></li>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=340733">https://bugzilla.mozilla.org/show_bug.cgi?id=340733</a></li>
				<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=338129">https://bugzilla.mozilla.org/show_bug.cgi?id=338129</a></li>
			</ul>

			<p>crypto.generateCRMFRequest callback can run on deleted context (shutdown)</p>
			<ul>
				<li>
					<a href="https://bugzilla.mozilla.org/show_bug.cgi?id=337462">https://bugzilla.mozilla.org/show_bug.cgi?id=337462</a>
					<br>CVE-2006-3811
				</li>
			</ul>

			[MFSA 2016-85 until (present)]
			<section class="cve">
				<h4 id="CVE-2018-12359" class="level-heading">
					<a href="#CVE-2018-12359"><span class="anchor">#</span>CVE-2018-12359: Buffer overflow using computed size of canvas element</a>
				</h4>
				<dl class="summary">
					<dt>Reporter</dt>
					<dd>Nils</dd>
					<dt>Impact</dt>
					<dd><span class="level critical">critical</span></dd>
				</dl>
				<h5>Description</h5>
				<p>A buffer overflow can occur when rendering canvas content while adjusting the height and width of the <code>&lt;canvas&gt;</code> element dynamically, causing data to be written outside of the currently computed boundaries. This results in a potentially exploitable crash.</p>
				<h5>References</h5>
				<ul>
					<li><a href="https://bugzilla.mozilla.org/show_bug.cgi?id=1459162">Bug 1459162</a></li>
				</ul>
			</section>

			<section class="cve">
				[...]
			</section>								
			"""

			# Get the basic information for all MFSA layout versions.
			dl_summary = mfsa_soup.find('dl', class_='summary')
			if dl_summary is not None:

				dt_list = dl_summary.find_all('dt')
				dd_list = dl_summary.find_all('dd')
				for dt, dd in zip(dt_list, dd_list):

					key = dt.get_text(strip=True)
					value = dd.get_text(strip=True)

					# Change the format of specific fields so they're consistent with the rest of the CSV file.
					if key == 'Announced':
						value = change_datetime_string_format(value, '%B %d, %Y', '%Y-%m-%d', 'en_US')
					elif key == 'Impact':
						value = value.title()
					elif key == 'Products':
						value = [product.strip() for product in value.split(',')]
					elif key == 'Fixed in':
						value = [li.get_text(strip=True) for li in dd.find_all('li')]
					
					key = key.title()
					mfsa_info[key] = value
			else:
				print(f'--> No summary description list found for {mfsa_id}.')

			# Get the CVE information for all MFSA layout versions.
			cve_list = []

			# --> For MFSA 2005-01 until MFSA 2016-84.
			h3_list = mfsa_soup.find_all('h3')
			for h3 in h3_list:

				h3_text = h3.get_text(strip=True)
				if h3_text == 'References':

					for li in h3.find_all_next('li'):
						
						li_text = li.get_text(strip=True)
						match = CVE_REGEX.search(li_text)
						if match:
							cve_list.append(match.group(1))

			# --> For MFSA 2005-01 until the latest page.
			section_list = mfsa_soup.find_all('section', class_='cve')
			for section in section_list:
				h4_cve = section.find('h4', id=CVE_REGEX)
				if h4_cve is not None:
					cve_list.append(h4_cve['id'])

			if cve_list:
				mfsa_info['CVEs'] = cve_list

			cve.advisory_info[mfsa_id] = mfsa_info

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.bugzilla_ids:
			grep_pattern = fr'^[bB]ug {id} -'
			hashes = self.find_git_commit_hashes(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

class XenProject(Project):

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Xen Security Advisories (XSA) pages.
		for xsa_full_id, xsa_url in zip(cve.advisory_ids, cve.advisory_urls):
			
			xsa_info = {}
			xsa_id = xsa_full_id.rsplit('-')[-1]
			print(f'--> Scraping additional information from advisory page {xsa_full_id}: "{xsa_url}"...')
			
			xsa_response = download_page(xsa_url)
			if xsa_response is not None:

				xsa_soup = bs4.BeautifulSoup(xsa_response.text, 'html.parser')

				"""
				<table>
					<tbody>
						<tr>
							<th>Advisory</th>
							<td><a href="advisory-55.html">XSA-55</a></td>
						</tr>
						<tr>
							<th>Public release</th>
							<td>2013-06-03 16:18</td>
						</tr>
						<tr>
							<th>Updated</th>
							<td>2013-06-20 10:26</td>
						</tr>
						<tr>
							<th>Version</th>
							<td>5</td>
						</tr>
						<tr>
							<th>CVE(s)</th>
							<td><a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2194">CVE-2013-2194</a> <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2195">CVE-2013-2195</a> <a href="http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-2196">CVE-2013-2196</a></td>
						</tr>
						<tr>
							<th>Title</th>
							<td>Multiple vulnerabilities in libelf PV kernel handling</td>
						</tr>
					</tbody>
				</table>
				"""

				xsa_info_table = xsa_soup.find('table')
				if xsa_info_table is not None:

					xsa_info_th = xsa_info_table.find_all('th')
					xsa_info_td = xsa_info_table.find_all('td')
					for th, td in zip(xsa_info_th, xsa_info_td):

						key = th.get_text(strip=True)
						value = td.get_text(strip=True)

						# Change the format of specific fields so they're consistent with the rest of the CSV file.
						if key == 'Advisory':
							continue
						elif key == 'CVE(s)':
							key = 'CVEs'
							value = [cve_a.get_text(strip=True) for cve_a in td.find_all('a')]
						else:
							key = key.title()
							
						xsa_info[key] = value

					cve.advisory_info[xsa_full_id] = xsa_info

				else:
					print(f'--> No information table found for {xsa_full_id}.')

			else:
				print(f'--> Could not download the page for {xsa_full_id}.')

			##################################################

			# Download an additional page that contains this XSA's Git commit hashes.
			xsa_meta_url = f'https://xenbits.xen.org/xsa/xsa{xsa_id}.meta'
			print(f'--> Scraping commit hashes from the metadata file related to {xsa_full_id}: "{xsa_meta_url}"...')
			
			xsa_meta_response = download_page(xsa_meta_url)
			if xsa_meta_response is not None:

				"""
				"Recipes":
				{
					"4.5":
					{
						"XenVersion": "4.5",
						"Recipes":
						{
							"xen":
							{
								"StableRef": "83724d9f3ae21a3b96362742e2f052b19d9f559a",
								"Prereqs": [],
								"Patches": ["xsa237-4.5/*"]
							}
						}
					},

					[...]
				}
				"""

				try:
					xsa_metadata = json.loads(xsa_meta_response.text)
				except json.decoder.JSONDecodeError as error:
					xsa_metadata = None
					error_string = repr(error)
					print(f'--> Failed to parse the JSON metadata for {xsa_full_id} with the error: {error_string}')
				
				# Tries to get a value from variously nested dictionaries by following
				# a sequence of keys in a given order. If any intermediate dictionary
				# doesn't exist, this function returns None.
				def nested_get(dictionary: dict, key_list: list):
					value = None
					for key in key_list:
						value = dictionary.get(key)
						
						if value is None:
							break
						elif isinstance(value, dict):
							dictionary = value

					return value

				if xsa_metadata is not None:

					# Find every commit hash in the 'Recipes' dictionary.
					for reciple_key, recipe_value in xsa_metadata['Recipes'].items():

						commit_hash = nested_get(recipe_value, ['Recipes', 'xen', 'StableRef'])

						if commit_hash is not None:
							cve.git_commit_hashes.append(commit_hash)
						else:
							print(f'--> Could not find any commit hash for {xsa_full_id} in the "{reciple_key}" branch.')

			else:
				print(f'--> Could not download the metadata file for {xsa_full_id}.')

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.advisory_ids:
			grep_pattern = fr'[tT]his is.*{id}'
			hashes = self.find_git_commit_hashes(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

project_list = Project.get_project_list_from_config(scraping_config)

print()

for project in project_list:

	project.collect_and_save_vulnerabilities_to_csv_file()

	print()
	print()

print('Finished running')
