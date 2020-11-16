# Software Vulnerabilities Discovery With Static Techniques

This repository contains any code and documents developed for the master thesis ["Software Vulnerabilities Discovery With Static Techniques" (2020/2021)](https://estagios.dei.uc.pt/cursos/mei/ano-lectivo-2020-2021/propostas-com-alunos/?idestagio=3865).

## Background

Software vulnerabilities can have serious consequences when exploited, such as unauthorized authentication, data losses, and financial losses. Although there exist techniques for detecting these vulnerabilities by analyzing the source code or executing the software, these suffer from both false positives (misidentified vulnerabilities) and false negatives (undetected vulnerabilities). One other way of identifying vulnerabilities is to combine certain source code properties (software metrics) with machine learning techniques. A previous study has shown this to be feasible, although the data that was collected is now out of date. Likewise, vulnerability alerts may be found directly by using one or more static analysis tools (SATs), though these also present a high number of false positives.

This work will focus on developing a mechanism for automatically collecting new vulnerabilities from large C/C++ projects. This method should be enchanced by combining both software metrics and static analysis alerts, and applying machine learning algorithms.

## Objectives

* Obtain and combine information about vulnerable code in order to develop robust techniques for vulnerability detection.
* Understand the most frequent types of vulnerabilities and their effects in software systems.
* Understand the most common types of software metrics.
* Understand how static code analysis (SCA) works and learn how to use some static analysis tools (SATs).
* Improve the coding skills required to create secure software.

## Authors

* João Henggeler Antunes - Student
* José Alexandre D'Abruzzo Pereira - Supervisor
* Marco Vieira - Supervisor
