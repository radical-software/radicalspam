#!/bin/bash

# Extraction des logs
/var/rs/addons/nagios/bin/extract-log-current-day.sh  >/dev/null 2>/dev/null

# Stats Postfix - logs
/var/rs/addons/nagios/bin/stats_postfix_logs.sh > /var/rs/addons/nagios/var/stats_postfix_logs_counters.txt

# Stats RadicalSpam - logs
/var/rs/addons/nagios/bin/stats_radicalspam_logs.sh > /var/rs/addons/nagios/var/stats_radicalspam_logs_counters.txt

