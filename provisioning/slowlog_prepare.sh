#!/bin/bash

sudo rm -rf /tmp/mysql-slow.log

sudo mysql << EOF
set global slow_query_log_file = '/tmp/mysql-slow.log';
set global long_query_time = 0;
set global slow_query_log = ON;
EOF
