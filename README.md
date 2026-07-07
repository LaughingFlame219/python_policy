# FortiGate Policy Overlap Detection Tool (Python)

## Overview
This repository provides a Python script that analyzes FortiGate firewall configurations and detects policy overlaps, helping engineers identify redundant or shadowed rules.

## What “Overlap” Means
The script evaluates all firewall policies and determines whether a lower‑priority policy is fully or partially covered by a higher‑priority policy.  
A policy is considered overlapped when the upper rule’s conditions (interfaces, addresses, actions, etc.) already encompass those of the lower rule.

## Service Overlap Handling
Service objects are checked using partial‑match logic.  
Only overlaps that meet the detection criteria are reported, and the output includes the service entries that were identified as overlapping.
