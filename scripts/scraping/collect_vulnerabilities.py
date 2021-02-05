#!/usr/bin/env python3

"""
	This script collects any vulnerabilities associated with the five C/C++ projects by scraping the CVE Details website.
	
	This information includes the CVE identifier, publish date, CVSS score, various impacts, vulnerability types, the CWE ID, and
	the URLs to other relevant websites like a project's Bugzilla or Security Advisory platforms.

	For each project, this information is saved to a CSV file.

	Requirements:

	pip install beautifulsoup4
	pip install requests
"""

import csv
import json
import random
import re
import sys
from urllib.parse import urlsplit, parse_qsl

import bs4

from estagio_scraping import download_page, get_current_timestamp

DEBUG_MODE = True
if DEBUG_MODE:
	print('[DEBUG MODE IS ENABLED]')

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
"""
Examples:
- Linux: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eff73de2b1600ad8230692f00bc0ab49b166512a
- Glibc: https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=commit;h=583dd860d5b833037175247230a328f0050dbfe9

- Linux: https://github.com/torvalds/linux/commit/6ef36ab967c71690ebe7e5ef997a8be4da3bc844
- Apache: https://github.com/apache/httpd/commit/e427c41257957b57036d5a549b260b6185d1dd73 

- Apache: http://svn.apache.org/viewcvs?rev=292949&view=rev
"""

# Helper function to create a dictionary that maps each project to information that
# is used to extract the metadata in the CVE Details website.
def create_project_info(short_name, database_id, vendor_id, product_id, url_pattern):
	return {'short_name': short_name, 'database_id': database_id,
			'vendor_id': vendor_id, 'product_id': product_id,
			'url_pattern': url_pattern}

PROJECT_INFO = {
	'Glibc': 				create_project_info('glibc', 	5, 	72, 	767, 	r'sourceware'),
	'Apache	HTTP Server': 	create_project_info('apache', 	4, 	45, 	66, 	r'apache'),
	'Xen': 					create_project_info('xen', 		3, 	6276, 	None, 	r'xen'),
	'Mozilla': 				create_project_info('mozilla', 	1, 	452, 	None, 	r'mozilla'),
	'Linux Kernel': 		create_project_info('kernel', 	2, 	33, 	47, 	r'linux|kernel|redhat'),
}

timestamp = get_current_timestamp()

for full_name, info in PROJECT_INFO.items():

	vendor_id = info['vendor_id']
	product_id = info.get('product_id')

	print(f'Collecting the vulnerabilities for the "{full_name}" project ({vendor_id}, {product_id}):')
	response = download_page('https://www.cvedetails.com/vulnerability-list.php', {'vendor_id': vendor_id, product_id: product_id})

	if response is not None:
		
		main_soup = bs4.BeautifulSoup(response.text, 'html.parser')

		page_div = main_soup.find('div', id='pagingb')
		page_a_list = page_div.find_all('a', title=PAGE_TITLE_REGEX)

		page_url_list = ['https://www.cvedetails.com' + page_a['href'] for page_a in page_a_list]

		if DEBUG_MODE:
			previous_len = len(page_url_list)
			page_url_list = page_url_list[::5]
			print(f'-> [DEBUG] Reduced the number of hub pages from {previous_len} to {len(page_url_list)}.')

		database_id = info['database_id']
		short_name = info['short_name']
		csv_filename = f'{database_id}-{short_name}-{timestamp}.csv'

		with open(csv_filename, 'w', newline='') as csv_file:

			CSV_HEADER = [
				'CVE', 'CVE URL',
				
				'Publish Date', 'Last Update Date',

				'CVSS Score', 'Confidentiality Impact', 'Integrity Impact',
				'Availability Impact', 'Access Complexity', 'Authentication',
				'Gained Access', 'Vulnerability Types', 'CWE',
				
				'Affected Product Versions',

				'Bugzilla URLs', 'Bugzilla IDs',
				'Advisory URLs', 'Advisory IDs',
				'Git URLs', 'Git Commit Hashes',
				'SVN URLs', 'SVN Revision Numbers'
			]

			csv_writer = csv.DictWriter(csv_file, fieldnames=CSV_HEADER)
			csv_writer.writeheader()

			for i, page_url in enumerate(page_url_list):

				print(f'-> Scraping hub page {i+1} of {len(page_url_list)}...')
				page_response = download_page(page_url)
				if page_response is None:
					continue
		
				page_soup = bs4.BeautifulSoup(page_response.text, 'html.parser')
				vulnerability_table = page_soup.find('table', id='vulnslisttable')

				cve_a_list = vulnerability_table.find_all('a', title=CVE_REGEX)
				
				if DEBUG_MODE:
					previous_len = len(cve_a_list)
					cve_a_list = random.sample(cve_a_list, 4)
					print(f'--> [DEBUG] Reduced the number of CVE pages from {previous_len} to {len(cve_a_list)}.')

				for j, cve_a in enumerate(cve_a_list):

					cve = cve_a.get_text(strip=True)
					cve_url = f'https://www.cvedetails.com/cve/{cve}'

					print(f'--> Scraping the CVE page {j+1} of {len(cve_a_list)}: "{cve}" from "{cve_url}"...')
					cve_response = download_page(cve_url)
					if cve_response is None:
						continue

					cve_soup = bs4.BeautifulSoup(cve_response.text, 'html.parser')

					"""
					<div class="cvedetailssummary">
						Memory safety bugs were reported in Firefox 57 and Firefox ESR 52.5. Some of these bugs showed evidence of memory corruption and we presume that with enough effort that some of these could be exploited to run arbitrary code. This vulnerability affects Thunderbird &lt; 52.6, Firefox ESR &lt; 52.6, and Firefox &lt; 58.	<br>
						<span class="datenote">Publish Date : 2018-06-11	Last Update Date : 2018-08-03</span>
					</div>
					"""

					dates_span = cve_soup.find('span', class_='datenote')
					if dates_span is not None:
						
						dates_text = dates_span.get_text(strip=True)
						
						cve_dates = {}
						for date in re.split(r'\t+', dates_text):
							key, value = date.split(' : ')
							cve_dates[key] = value

						publish_date = cve_dates.get('Publish Date')
						last_update_date = cve_dates.get('Last Update Date')

					else:
						print('--> No dates span found for this CVE.')

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

					scores_table = cve_soup.find('table', id='cvssscorestable')
					if scores_table is not None:

						scores_th_list = scores_table.find_all('th')
						scores_td_list = scores_table.find_all('td')

						cve_fields = {}
						for th, td in zip(scores_th_list, scores_td_list):

							key = th.get_text(strip=True)
							value = None

							if key == 'Vulnerability Type(s)':

								span_list = td.find_all('span')
								span_text_list = [span.get_text(strip=True) for span in span_list]
								value = ','.join(span_text_list)

							else:

								span = td.find('span')
								if span is not None:
									value = span.get_text(strip=True)
								else:
									value = td.get_text(strip=True)

							cve_fields[key] = value

						cvss_score = cve_fields.get('CVSS Score')
						confidentiality_impact = cve_fields.get('Confidentiality Impact')
						integrity_impact = cve_fields.get('Integrity Impact')
						availability_impact = cve_fields.get('Availability Impact')
						access_complexity = cve_fields.get('Access Complexity')
						authentication = cve_fields.get('Authentication')
						gained_access = cve_fields.get('Gained Access')
						vulnerability_types = cve_fields.get('Vulnerability Type(s)')
						cwe = cve_fields.get('CWE ID')
						
						if cwe is not None and not cwe.isnumeric():
							cwe = None

					else:
						print('--> No scores table found for this CVE.')

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

					products_table = cve_soup.find('table', id='vulnprodstable')
					if products_table is not None:

						th_list = products_table.find_all('th')
						th_list = [th.get_text(strip=True) for th in th_list]
						column_indexes = {	'vendor': 	th_list.index('Vendor'),
											'product': 	th_list.index('Product'),
											'version': 	th_list.index('Version')}

						affected_products = {}
						tr_list = products_table.find_all('tr')
						for tr in tr_list:

							# Skip the header row.
							if tr.find('th'):
								continue

							td_list = tr.find_all('td')

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

							vendor_pattern = f'/{vendor_id}/'
							product_pattern = f'/{product_id}/' if product_id is not None else ''
							
							# Check if the vendor and product belong to the current project.
							if vendor_pattern in vendor_url and product_pattern in product_url:

								if product not in affected_products:
									affected_products[product] = []
								
								if version is not None and version not in affected_products[product]:
									affected_products[product].append(version)

						if affected_products:
							affected_products = json.dumps(affected_products)
						else:
							affected_products = None
					
					else:
						print('--> No products table found for this CVE.')


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

					references_table = cve_soup.find('table', id='vulnrefstable')
					if references_table is not None:

						bugzilla_urls = None
						advisory_urls = None
						git_urls = None
						git_commit_hashes = None
						svn_urls = None
						svn_revision_numbers = None

						# Creates a comma separated list of URL that match a regex (or a list of regexes).
						# If a handler function is passed as the second argument, then it will be called
						# for each URL in order to create and return a secondary list. This may be used
						# to extract specific parts of the URL.
						def join_all_urls(url_regex, url_handler=None):
							a_list = references_table.find_all('a', href=url_regex)
							
							url_list = []
							for a in a_list:
								url = a['href']
								if re.search(info['url_pattern'], url, re.IGNORECASE):
									url_list.append(url)

							secondary_list = []
							if url_handler is not None:
								for url in url_list:
									secondary_list.append( url_handler(url) )

							return ','.join(url_list), ','.join(secondary_list)

						# Finds the value of the first parameter in a URL's query segment given a list of
						# keys to check. If no value was found, this function returns None.
						def get_query_param(url, query_key_list):
							split_url = urlsplit(url)
							params = dict(parse_qsl(split_url.query))
							result = None
							
							for query_key in query_key_list:
								result = params.get(query_key)
								if result is not None:
									break

							if result is None:
								print(f'--> Could not find the desired parameter in "{url}".')

							return result

						#
						# Various helper functions to handle specific URLs from different sources.
						#

						def handle_bugzilla_urls(url):
							return get_query_param(url, ['id', 'bug_id'])

						def handle_advisory_urls(url):
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

						def handle_git_urls(url):
							commit_hash = get_query_param(url, ['id', 'h'])
							if commit_hash is None:
								split_url = urlsplit(url)
								path_components = split_url.path.rsplit('/')
								commit_hash = path_components[-1]

							if commit_hash is None:
								print(f'--> Could not find a valid commit hash in "{url}".')

							return commit_hash

						def handle_svn_urls(url):
							return get_query_param(url, ['rev', 'revision', 'pathrev'])

						bugzilla_urls, bugzilla_ids = join_all_urls(BUGZILLA_URL_REGEX, handle_bugzilla_urls)
						advisory_urls, advisory_ids = join_all_urls([MFSA_URL_REGEX, XSA_URL_REGEX, APACHE_SECURITY_URL_REGEX], handle_advisory_urls)

						git_urls, git_commit_hashes = join_all_urls([GIT_URL_REGEX, GITHUB_URL_REGEX], handle_git_urls)
						svn_urls, svn_revision_numbers = join_all_urls(SVN_URL_REGEX, handle_svn_urls)

					else:
						print('--> No references table found for this CVE.')
					
					##################################################

					csv_row = {
						'CVE': cve, 'CVE URL': cve_url,

						'Publish Date': publish_date, 'Last Update Date': last_update_date,

						'CVSS Score': cvss_score, 'Confidentiality Impact': confidentiality_impact, 'Integrity Impact': integrity_impact,
						'Availability Impact': availability_impact, 'Access Complexity': access_complexity, 'Authentication': authentication,
						'Gained Access': gained_access, 'Vulnerability Types': vulnerability_types, 'CWE': cwe,

						'Affected Product Versions': affected_products,

						'Bugzilla URLs': bugzilla_urls, 'Bugzilla IDs': bugzilla_ids,
						'Advisory URLs': advisory_urls, 'Advisory IDs': advisory_ids,
						'Git URLs': git_urls, 'Git Commit Hashes': git_commit_hashes,
						'SVN URLs': svn_urls, 'SVN Revision Numbers': svn_revision_numbers
					}

					csv_writer.writerow(csv_row)

	else:
		print('-> Could not download the first vulnerability page.')

	print()
	print()


print('Finished running')
