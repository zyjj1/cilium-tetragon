#!/bin/bash

echo "$(date +%Y%m%d.%H%M%S): HOOKED ($@)"      >> /tmp/tetragon-hook-log
echo "ENV: $(env)"                              >> /tmp/tetragon-hook-log
echo "CGROUPFS: $(find /sys/fs/cgroup -type d)" >> /tmp/tetragon-hook-log
echo "END"                                      >> /tmp/tetragon-hook-log
