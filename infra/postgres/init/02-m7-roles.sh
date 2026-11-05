#!/bin/sh
# Runs once, on an empty data volume only, after 01-init.sh (M7): the retention role. Existing
# volumes get it from the idempotent `db-bootstrap` service, which runs the same script.
set -eu

sh /opt/cyberlab/bootstrap.sh
