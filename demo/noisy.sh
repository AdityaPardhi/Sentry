#!/bin/sh
# DEMO: starts many short processes and writes small files, then exits.
# Expected verdict: SUSPICIOUS (many child processes).
i=0
while [ $i -lt 14 ]; do
    sleep 4 &
    i=$((i + 1))
done
j=0
while [ $j -lt 200 ]; do
    echo "x" > /tmp/noise_$j
    j=$((j + 1))
done
wait
echo "done"
