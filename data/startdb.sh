#!/bin/sh

slapd -h "ldapi://ldapi ldap://localhost:2389 ldaps://localhost:2636" -F config
