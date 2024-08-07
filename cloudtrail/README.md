### CloudTrail

This tool will dump CloudTrail .json logs to stdout with an indent allowing
you to pass the results to grep, tr, sort, uniq etc. Additionally, you can provide
a search term and the tool will only pretty print the log files or lines, that contain
the matching search term.

This tool is useful for HTB Sherlock Cloud challenges.


### Example Commands

./cloudtrail.py --successful_api --dir ~/htb/sherlocks/heartbreakdenouement/HeartBreakerDenouement/AWS/ > logs/challenge_cloudtrail_successful_api.json

./cloudtrail.py --file logs/challenge_cloudtrail_successful_api.json --userAgent python | grep dBSnapshotIdentifier | sort | uniq | tr -d " \t'r"