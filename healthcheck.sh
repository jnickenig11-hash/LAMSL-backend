#!/usr/bin/env bash
# Bash wrapper for healthcheck
BASE_URL=${BASE_URL:-http://localhost:3000}
node ./healthcheck.js
exit $?
