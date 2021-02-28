#!/usr/bin/env python3

import csv
import glob
import json
import locale
import logging as log
import os
import random
import re
import subprocess
import sys
import time
from datetime import datetime
from string import Template
from typing import Callable, Iterator, Optional, Union
from urllib.parse import urlsplit, parse_qsl

import bs4 # type: ignore
import git # type: ignore
import numpy as np # type: ignore
import pandas as pd # type: ignore
import requests

####################################################################################################

# log.basicConfig(filename='scraping.log', filemode='w', format='[%(asctime)s | %(levelname)s] %(name)s: %(message)s')

####################################################################################################

def load_scraping_config(config_path: str = 'config.json') -> dict:

	try:
		with open(config_path) as file:
			config = json.loads(file.read())
	except json.decoder.JSONDecodeError as error:
		config = {}
		print(f'Failed to parse the JSON configuration file with the error: {repr(error)}')
		print()
		
	return config

SCRAPING_CONFIG = load_scraping_config()

if not SCRAPING_CONFIG:
	print(f'The module will terminate as the configuration file could not be read correctly.')
	sys.exit(1)

DEBUG_OPTIONS = SCRAPING_CONFIG['debug_options']
DEBUG_ENABLED = DEBUG_OPTIONS['enabled']

if DEBUG_ENABLED:
	print('[DEBUG MODE IS ENABLED]')
	print(DEBUG_OPTIONS)
	print()

####################################################################################################

def get_current_timestamp() -> str:
	return datetime.now().strftime("%Y%m%d%H%M%S")

def change_datetime_string_format(datetime_string: str, source_format: str, destination_format: str, desired_locale: str) -> str:
	previous_locale = locale.getlocale(locale.LC_TIME)
	locale.setlocale(locale.LC_TIME, desired_locale)
	
	datetime_string = datetime.strptime(datetime_string, source_format).strftime(destination_format)
	locale.setlocale(locale.LC_TIME, previous_locale)

	return datetime_string

def serialize_json_container(container: Union[list, dict]) -> Optional[str]:
	return json.dumps(container) if container else None

def deserialize_json_container(container_str: Optional[str]) -> Union[list, dict, None]:
	return json.loads(container_str) if pd.notna(container_str) else None # type: ignore[arg-type]

####################################################################################################

class ScrapingManager():

	session: requests.Session
	connect_timeout: float
	read_timeout: float
	
	use_random_headers: bool
	sleep_random_amounts: bool

	DEFAULT_HEADERS: dict = {
		'Accept-Language': 'en-US',
		'User-Agent': 'Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36'
	}

	BROWSER_HEADERS: list = list( SCRAPING_CONFIG['http_headers'].values() )

	def __init__(	self, url_prefixes: Union[str, list] = [],
					connect_timeout: float = 10.0, read_timeout: float = 5.0,
					max_retries: int = 5, headers: dict = DEFAULT_HEADERS,
					use_random_headers: bool = True,sleep_random_amounts: bool = True):
		
		session = requests.Session()
		adapter = requests.adapters.HTTPAdapter(max_retries=max_retries)
	
		if isinstance(url_prefixes, str):
			url_prefixes = [url_prefixes]

		for prefix in url_prefixes:
			session.mount(prefix, adapter)

		session.headers.update(headers)
		
		self.session = session
		self.connect_timeout = connect_timeout
		self.read_timeout = read_timeout
		self.use_random_headers = use_random_headers
		self.sleep_random_amounts = sleep_random_amounts

	def download_page(self, url: str, params: Optional[dict] = None) -> Optional[requests.Response]:

		response: Optional[requests.Response]

		try:

			if self.use_random_headers:
				headers = random.choice(ScrapingManager.BROWSER_HEADERS)
				self.session.headers.update(headers)
			
			if self.sleep_random_amounts:
				sleep_amount = random.uniform(1.0, 3.0)
				time.sleep(sleep_amount)

			response = self.session.get(url, params=params, timeout=(self.connect_timeout, self.read_timeout))
			response.raise_for_status()
		except Exception as error:
			response = None
			print(f'Failed to download the page "{url}" with the error: {repr(error)}')
		
		return response

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

SOURCE_FILE_EXTENSIONS = ['c', 'cpp', 'cc', 'cxx', 'c++', 'cp', 'h', 'hpp']

####################################################################################################

class Cve:

	CVE_DETAILS_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.cvedetails.com')

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
		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(self.url)
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

			if commit_hash is None:
				split_url = urlsplit(url)
				path_components = split_url.path.rsplit('/')
				commit_hash = path_components[-1]

			# If the hash length is less than 40, we need to refer to the repository
			# to get the full hash.
			if commit_hash is not None and len(commit_hash) < GIT_COMMIT_HASH_LENGTH:
				commit_hash = self.project.find_full_git_commit_hash(commit_hash)

			if commit_hash is not None and not GIT_COMMIT_HASH_REGEX.match(commit_hash):
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

	def remove_duplicated_values(self):

		def remove_duplicates_from_list(value_list: list) -> list:
			return list(dict.fromkeys(value_list))

		self.vulnerability_types 	= remove_duplicates_from_list(self.vulnerability_types)

		self.bugzilla_urls 			= remove_duplicates_from_list(self.bugzilla_urls)
		self.bugzilla_ids 			= remove_duplicates_from_list(self.bugzilla_ids)
		self.advisory_urls 			= remove_duplicates_from_list(self.advisory_urls)
		self.advisory_ids 			= remove_duplicates_from_list(self.advisory_ids)

		self.git_urls 				= remove_duplicates_from_list(self.git_urls)
		self.git_commit_hashes 		= remove_duplicates_from_list(self.git_commit_hashes)
		self.svn_urls 				= remove_duplicates_from_list(self.svn_urls)
		self.svn_revision_numbers 	= remove_duplicates_from_list(self.svn_revision_numbers)

	def serialize_containers(self):

		self.vulnerability_types 	= serialize_json_container(self.vulnerability_types)

		self.affected_products 		= serialize_json_container(self.affected_products)

		self.bugzilla_urls 			= serialize_json_container(self.bugzilla_urls)
		self.bugzilla_ids 			= serialize_json_container(self.bugzilla_ids)
		self.advisory_urls 			= serialize_json_container(self.advisory_urls)
		self.advisory_ids 			= serialize_json_container(self.advisory_ids)

		self.advisory_info 			= serialize_json_container(self.advisory_info)

		self.git_urls 				= serialize_json_container(self.git_urls)
		self.git_commit_hashes 		= serialize_json_container(self.git_commit_hashes)
		self.svn_urls 				= serialize_json_container(self.svn_urls)
		self.svn_revision_numbers 	= serialize_json_container(self.svn_revision_numbers)

####################################################################################################

class Project:

	TIMESTAMP: str = get_current_timestamp()

	full_name: str
	short_name: str
	database_id: int
	vendor_id: int
	product_id: int
	url_pattern: str
	repository_path: str
	master_branch: str

	repository: git.Repo

	output_directory_path: str
	scrape_all_branches: bool

	csv_prefix_template: Template
	csv_file_path_template: Template

	def __init__(self, project_name: str, project_info: dict):
		
		self.full_name = project_name
		for key, value in project_info.items():
			setattr(self, key, value)

		try:
			self.repository = git.Repo(self.repository_path)
			print(f'Loaded the project "{self}" located in "{self.repository_path}".')
		except Exception as error:
			self.repository = None
			print(f'Failed to get the repository for the project "{self}"" with the error: {repr(error)}')

		print()
		
		csv_prefix = os.path.join(self.output_directory_path, f'$type-{self.database_id}-')
		self.csv_prefix_template = Template(csv_prefix)

		used_branches = 'all-branches' if self.scrape_all_branches else 'master-branch'

		csv_file_path = csv_prefix + f'{self.short_name}-{used_branches}-{Project.TIMESTAMP}.csv'
		self.csv_file_path_template = Template(csv_file_path)

	def __str__(self):
		return self.full_name

	@staticmethod
	def get_project_list_from_config(config: dict = SCRAPING_CONFIG) -> list:
		
		output_directory_path = config['output_directory_path']
		scrape_all_branches = config['scrape_all_branches']
		project_config = config['projects']

		print(f'Scraping all branches? {scrape_all_branches}')
		print()

		project_list = []
		for full_name, info in project_config.items():

			short_name = info['short_name']
			info['output_directory_path'] = output_directory_path
			info['scrape_all_branches'] = scrape_all_branches
			project: Project
		
			if short_name == 'mozilla':
				project = MozillaProject(full_name, info)
			elif short_name == 'xen':
				project = XenProject(full_name, info)
			elif short_name == 'apache':
				project = ApacheProject(full_name, info)
			elif short_name == 'glibc':
				project = GlibcProject(full_name, info)
			else:
				project = Project(full_name, info)

			project_list.append(project)

		return project_list

	@staticmethod
	def ensure_all_project_repositories_were_loaded(project_list: list):
		for project in project_list:
			if project.repository is None:
				print(f'The repository for project "{project}" was not loaded correctly.')
				sys.exit(1)

	def find_output_csv_files(self, type: str) -> Iterator[str]:

		csv_path = self.csv_prefix_template.substitute(type=type) + '*'

		for path in glob.iglob(csv_path):
			yield path

	def scrape_additional_information_from_security_advisories(self, cve: Cve):
		pass

	def scrape_additional_information_from_version_control(self, cve: Cve):
		pass

	def find_full_git_commit_hash(self, short_commit_hash: str) -> Optional[str]:

		if self.repository is None:
			return None

		try:
			# git show --format="%H" --no-patch [SHORT HASH]
			full_commit_hash = self.repository.git.show(short_commit_hash, format='%H', no_patch=True)
		except git.exc.GitCommandError as error:
			full_commit_hash = None
			print(f'Failed to find the full version of the commit hash "{short_commit_hash}" with the error: {repr(error)}')

		return full_commit_hash

	def find_git_commit_hashes_from_pattern(self, grep_pattern: str) -> list:
		
		if self.repository is None:
			return []

		hash_list = []

		# git log --all --format=oneline --grep="[REGEX]" --regexp-ignore-case --extended-regexp
		# The --extended-regexp option enables the following special characters: ? + { | ( )
		log_result = self.repository.git.log(all=True, format='oneline', grep=grep_pattern, regexp_ignore_case=True, extended_regexp=True)
		
		for line in log_result.splitlines():
			hash, title = line.split(maxsplit=1)
			hash_list.append(hash)

		return hash_list

	def is_git_commit_hash_valid(self, commit_hash: str) -> bool:

		if self.repository is None:
			return False

		try:
			# git branch --contains [HASH]
			self.repository.git.branch(contains=commit_hash)
			is_valid = True
		except git.exc.GitCommandError as error:
			is_valid = False

		return is_valid	

	def remove_invalid_git_commit_hashes(self, cve: Cve):
		if self.repository is not None:
			cve.git_commit_hashes = [hash for hash in cve.git_commit_hashes if self.is_git_commit_hash_valid(hash)]

	def is_git_commit_hash_in_master_branch(self, commit_hash: str) -> bool:
		
		if self.repository is None:
			return False

		is_master = False

		try:
			# git branch --contains [HASH] --format="%(refname:short)"
			branch_result = self.repository.git.branch(contains=commit_hash, format='%(refname:short)')
			is_master = self.master_branch in branch_result.splitlines()

		except git.exc.GitCommandError as error:
			# If there's no such commit in the repository.
			pass

		return is_master
	
	def remove_git_commit_hashes_by_branch(self, cve: Cve):
		if self.repository is not None and not self.scrape_all_branches:
			cve.git_commit_hashes = [hash for hash in cve.git_commit_hashes if self.is_git_commit_hash_in_master_branch(hash)]

	def sort_git_commit_hashes_topologically(self, hash_list: list) -> list:

		if self.repository is None or not hash_list:
			return []

		try:
			# git rev-list --topo-order --reverse --no-walk=sorted [HASH 1] [HASH 2] [...] [HASH N]
			rev_list_result = self.repository.git.rev_list(*hash_list, topo_order=True, reverse=True, no_walk='sorted')
			sorted_hash_list = [commit_hash for commit_hash in rev_list_result.splitlines()]

		except git.exc.GitCommandError as error:
			# If there's no such commit in the repository.
			print('Found one or more invalid commits while trying to sort the commit hashes topologically.')
			sorted_hash_list = []

		return sorted_hash_list

	def find_changed_files_in_git_commit(self, commit_hash: str, file_extension_filter=[]) -> Iterator[str]:
		
		if self.repository is None:
			return

		# git diff --name-only [HASH] [HASH]^
		diff_result = self.repository.git.diff(commit_hash, commit_hash + '^', name_only=True)
		for file_path in diff_result.splitlines():

			yield_file = len(file_extension_filter) == 0
						
			for file_extension in file_extension_filter:
				if file_path.endswith('.' + file_extension):
					yield_file = True
					break

			if yield_file:
				yield file_path

	def find_parent_git_commit_hash(self, commit_hash) -> Optional[str]:
		
		if self.repository is None:
			return None

		try:
			# git log [HASH] --parents --max-count=1 --format="%P"
			parent_commit_hash = self.repository.git.log(commit_hash, parents=True, max_count=1, format='%P')
		except git.exc.GitCommandError as error:
			parent_commit_hash = None
			print(f'Failed to find the parent of the commit hash "{commit_hash}" with the error: {repr(error)}')

		return parent_commit_hash

	def scrape_vulnerabilities_from_cve_details(self) -> Iterator[Cve]:

		print(f'Collecting the vulnerabilities for the "{self}" project ({self.vendor_id}, {self.product_id}):')
		response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page('https://www.cvedetails.com/vulnerability-list.php', {'vendor_id': self.vendor_id, 'product_id': self.product_id})

		if response is None:
			print('Could not download the first hub page. No vulnerabilities will be scraped for this project.')
			return
		
		main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

		page_div = main_soup.find('div', id='pagingb')
		page_a_list = page_div.find_all('a', title=PAGE_TITLE_REGEX)
		page_url_list = ['https://www.cvedetails.com' + page_a['href'] for page_a in page_a_list]
		page_url_list[::-1]

		if DEBUG_ENABLED:
			previous_len = len(page_url_list)
			if previous_len > DEBUG_OPTIONS['min_hub_pages']:
				page_url_list = page_url_list[::DEBUG_OPTIONS['hub_page_step']]
			
			print(f'-> [DEBUG] Reduced the number of hub pages from {previous_len} to {len(page_url_list)}.')

		for i, page_url in enumerate(page_url_list):

			print(f'-> Scraping hub page {i+1} of {len(page_url_list)}...')
			page_response = Cve.CVE_DETAILS_SCRAPING_MANAGER.download_page(page_url)
			if page_response is None:
				print(f'-> Failed to download hub page {i+1}.')
				continue
	
			page_soup = bs4.BeautifulSoup(page_response.text, 'html.parser')
			vulnerability_table = page_soup.find('table', id='vulnslisttable')
			cve_a_list = vulnerability_table.find_all('a', title=CVE_REGEX)
			
			# Test a random sample of CVEs from each page.
			if DEBUG_ENABLED:
				previous_len = len(cve_a_list)
				if DEBUG_OPTIONS['use_random_sampling']:
					cve_a_list = random.sample(cve_a_list, DEBUG_OPTIONS['max_cves_per_hub_page'])
				else:
					cve_a_list = cve_a_list[:DEBUG_OPTIONS['max_cves_per_hub_page']]
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

					cve.remove_duplicated_values()
					self.remove_invalid_git_commit_hashes(cve)
					self.remove_git_commit_hashes_by_branch(cve)
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
		
		os.makedirs(self.output_directory_path, exist_ok=True)

		csv_file_path = self.csv_file_path_template.substitute(type='cve')

		with open(csv_file_path, 'w', newline='') as csv_file:

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

	def collect_and_save_affected_files_to_csv_file(self):

		for csv_path in self.find_output_csv_files('cve'):

			cve_results = pd.read_csv(csv_path, usecols=['CVE', 'Git Commit Hashes'])
			cve_results = cve_results.dropna()
			cve_results['Git Commit Hashes'] = cve_results['Git Commit Hashes'].map(deserialize_json_container)

			git_commit_hashes = cve_results['Git Commit Hashes'].tolist()
			hash_list = [commit_hash for hash_list in git_commit_hashes for commit_hash in hash_list]
			hash_list = self.sort_git_commit_hashes_topologically(hash_list)
			
			affected_files = pd.DataFrame(columns=[	'File Path', 'Topological Index', 'Neutral Git Commit Hash',
													'Vulnerable Git Commit Hash', 'CVEs'])

			topological_index = 0
			for commit_hash in hash_list:

				changed_file_list = self.find_changed_files_in_git_commit(commit_hash, SOURCE_FILE_EXTENSIONS)
				parent_commit_hash = self.find_parent_git_commit_hash(commit_hash)

				has_source_file = False
				for file_path in changed_file_list:

					has_source_file = True
					is_commit = cve_results['Git Commit Hashes'].map(lambda hash_list: commit_hash in hash_list)
					cve_list = cve_results.loc[is_commit, 'CVE'].tolist()
					cve_list = serialize_json_container(cve_list)

					row = {
							'File Path': file_path,
							'Topological Index': topological_index,
							'Neutral Git Commit Hash': commit_hash,
							'Vulnerable Git Commit Hash': parent_commit_hash,
							'CVEs': cve_list
					}

					affected_files = affected_files.append(row, ignore_index=True)		

				if has_source_file:
					topological_index += 1

			csv_file_path = csv_path.replace('cve-', 'affected-files-')
			affected_files.to_csv(csv_file_path, index=False)

####################################################################################################

class MozillaProject(Project):

	MOZILLA_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://www.mozilla.org')

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Mozilla Foundation Security Advisories (MFSA) pages.
		for mfsa_id, mfsa_url in zip(cve.advisory_ids, cve.advisory_urls):

			mfsa_info = {}
			print(f'--> Scraping additional information from advisory page {mfsa_id}: "{mfsa_url}"...')

			mfsa_response = MozillaProject.MOZILLA_SCRAPING_MANAGER.download_page(mfsa_url)
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
			# E.g. " Bug 945192 - Followup to support Older SDKs in loaddlls.cpp. r=bbondy a=Sylvestre"
			regex_id = re.escape(id)
			grep_pattern = fr'^Bug \b{regex_id}\b'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class XenProject(Project):

	XEN_SCRAPING_MANAGER: ScrapingManager = ScrapingManager('https://xenbits.xen.org')

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_security_advisories(self, cve: Cve):

		# Download and extract information from any referenced Xen Security Advisories (XSA) pages.
		for xsa_full_id, xsa_url in zip(cve.advisory_ids, cve.advisory_urls):
			
			xsa_info = {}
			xsa_id = xsa_full_id.rsplit('-')[-1]
			print(f'--> Scraping additional information from advisory page {xsa_full_id}: "{xsa_url}"...')
			
			xsa_response = XenProject.XEN_SCRAPING_MANAGER.download_page(xsa_url)
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
			
			xsa_meta_response = XenProject.XEN_SCRAPING_MANAGER.download_page(xsa_meta_url)
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
					print(f'--> Failed to parse the JSON metadata for {xsa_full_id} with the error: {repr(error)}')
				
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
			# E.g. "This is CVE-2015-4164 / XSA-136."
			# E.g. "This is XSA-136 / CVE-2015-4164."
			# E.g. "This is XSA-215."
			regex_cve = re.escape(str(cve))
			regex_id = re.escape(id)
			grep_pattern = fr'This is.*\b({regex_cve}|{regex_id})\b'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class ApacheProject(Project):

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_version_control(self, cve: Cve):
		# E.g. "SECURITY: CVE-2017-3167 (cve.mitre.org)"
		# E.g. "Merge r1642499 from trunk: *) SECURITY: CVE-2014-8109 (cve.mitre.org)"
		regex_cve = re.escape(str(cve))
		grep_pattern = fr'SECURITY:.*\b{regex_cve}\b'
		hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
		cve.git_commit_hashes.extend(hashes)

####################################################################################################

class GlibcProject(Project):

	def __init__(self, project_name: str, project_info: dict):
		super().__init__(project_name, project_info)

	def scrape_additional_information_from_version_control(self, cve: Cve):
		for id in cve.bugzilla_ids:
			# E.g. "Don't ignore too long lines in nss_files (BZ #17079)"
			# E.g. "Fix integer overflows in internal memalign and malloc [BZ #22343] [BZ #22774]"
			# E.g. "Fix nan functions handling of payload strings (bug 16961, bug 16962)."
			# E.g.  Don't ignore too long lines in nss_files (BZ17079, CVE-2015-5277) Tested:
			regex_id = re.escape(id)
			grep_pattern = fr'((BZ|Bug).*\b{regex_id}\b)|(\bBZ{regex_id}\b)'
			hashes = self.find_git_commit_hashes_from_pattern(grep_pattern)
			cve.git_commit_hashes.extend(hashes)

####################################################################################################

class Sat():

	name: str
	executable_path: str
	version: Optional[str]

	SAT_CONFIG: dict = SCRAPING_CONFIG['sats']

	def __init__(self, name: str, executable_path: Optional[str] = None):
		self.name = name
		self.executable_path = executable_path or Sat.SAT_CONFIG[name]['executable_path']
		self.version = None

	def __str__(self):
		return self.name

	def run(self, *args) -> Optional[str]:
		
		arguments = [self.executable_path] + [arg for arg in args]
		result = subprocess.run(arguments, capture_output=True, text=True)

		return result.stdout

	def get_version(self) -> str:
		return self.version or 'Unknown'

####################################################################################################

class UnderstandSat(Sat):

	def __init__(self, name: str = 'Understand', executable_path: str = None):
		super().__init__(name, executable_path)
		self.version = self.run('version')

	def add_files(self, file_path_list: list):
		pass

	def generate_metrics(self):
		pass

####################################################################################################

if __name__ == '__main__':
	
	understand = UnderstandSat()
	print(f'{understand} at {understand.executable_path}')
	print(f'Version: {understand.get_version()}')
	print(f'Version: {understand.get_version()}')
