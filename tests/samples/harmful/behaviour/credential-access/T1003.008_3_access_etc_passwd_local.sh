#!/bin/sh
# T1003.008 test 3: Access /etc/passwd (Local)
# elevation_required: False
cat /etc/passwd > /tmp/T1003.008.txt
cat /tmp/T1003.008.txt
