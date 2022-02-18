# Building and Evaluating Software Vulnerability Datasets

This repository contains any code and documents developed for the master thesis "Building and Evaluating Software Vulnerability Datasets" (2020/2021).

## Background

Software vulnerabilities can have serious consequences when exploited, such as unauthorized authentication, data losses, and financial losses. Although there exist techniques for detecting these vulnerabilities by analyzing the source code or executing the software, these suffer from both false positives (misidentified vulnerabilities) and false negatives (undetected vulnerabilities). One other way of identifying vulnerabilities is to combine certain source code properties (software metrics) with machine learning techniques. A previous study has shown this to be feasible, although the data that was collected is now out of date. In a similar fashion, security alerts (i.e. potential vulnerabilities) may be found directly by using static analysis tools (SATs), though these also present a high number of false positives.

## Contributions

* Implemented an automated process capable of collecting vulnerability metadata from the [CVE Details website](https://www.cvedetails.com/), retrieving any affected code units (files, functions, classes) from a project's version control system, generating software metrics and security alerts for each one, and building robust datasets capable of being fed to machine learning algorithms.

* Built datasets of vulnerable code units for five large open-source C/C++ projects: [Mozilla](https://github.com/mozilla/gecko-dev), [Linux Kernel](https://github.com/torvalds/linux), [Xen Hypervisor](https://xenbits.xen.org/gitweb/?p=xen.git;a=summary), [Apache HTTP Server](https://github.com/apache/httpd), and [GNU C Library (Glibc)](https://sourceware.org/git/glibc.git).

* Validated the function samples by exploring various machine learning configurations and investigating whether it is possible to detect vulnerable function code in current versions using static data from previous commits.

## Publications

* José D'Abruzzo Pereira, João Henggeler Antunes, and Marco Vieira. On Building a Vulnerability Dataset with Static Information from the Source Code. In Safety, Security, and Privacy in Complex Artificial Intelligence based Systems (SAFELIFE 2021), 2021.

## Authors

* João Henggeler Antunes - Student
* José Alexandre D'Abruzzo Pereira - Supervisor
* Marco Vieira - Supervisor
