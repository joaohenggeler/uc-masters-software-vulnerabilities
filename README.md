# Building and Evaluating Software Vulnerability Datasets

This repository contains any code and documents developed for the master thesis "Building and Evaluating Software Vulnerability Datasets" (2020/2021).

## Background

Software vulnerabilities can have serious consequences when exploited, such as unauthorized authentication, data losses, and financial losses. Although there exist techniques for detecting these vulnerabilities by analyzing the source code or executing the software, these suffer from both false positives (misidentified vulnerabilities) and false negatives (undetected vulnerabilities). One other way of identifying vulnerabilities is to combine certain source code properties (software metrics) with machine learning techniques. A previous study has shown this to be feasible, although the data that was collected is now out of date. Likewise, vulnerability alerts may be found directly by using one or more static analysis tools (SATs), though these also present a high number of false positives.

## Contributions

* Implement an automated mechanism capable of collecting vulnerability metadata from the CVE Details website, generating software metrics and security alerts for each affected file, and building datasets capable of being fed to machine learning algorithms.
* Build datasets of three vulnerable C/C++ code unit types: files, functions, and classes.
* Validate the function dataset by exploring various machine learning configurations and investigating whether it is possible to detect vulnerable function code using static data from previous years.
* 
## Authors

* João Henggeler Antunes - Student
* José Alexandre D'Abruzzo Pereira - Supervisor
* Marco Vieira - Supervisor
