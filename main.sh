#!/bin/bash

# Copy env to .bashrc
env >> ~/.exporter_env

# Run the first process
#/usr/local/bin/python3 /opt/versions-exporter.py &
/opt/versions-exporter.py &

# Run the second process
cron && tail -f /var/log/cron.log &

# Wait for any process to exit
wait -n

# Exit with status of process that exited first
exit $?