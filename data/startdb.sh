#!/bin/sh

slapd -h "ldapi://ldapi ldap://localhost:2389" -F config
