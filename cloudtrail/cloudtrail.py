#!/usr/bin/python3

import os
import sys
import argparse
import json


def cloudtrail_compile_logs(ct_log_dir=None, successful_api=None):
    if not ct_log_dir:
        print("You must provide a DIR to collect log files from with --dir. See --help for more information.", file=sys.stdout)
        return False

    cloudtrail_json_logs = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(ct_log_dir)) for f in fn]

    if ".json.gz" in cloudtrail_json_logs:
        print("You must first decompress the CloudTrail logs with gunzip!", file=sys.stdout)
        return

    filtered_json = {"Records": []}

    try:
        for cf in cloudtrail_json_logs:
                if '.json.bak' not in cf:
                    with open(cf, mode="r", encoding="utf-8") as f:
                        for line in f:
                            if line != "" and line != "^M" and line != "\n" and line != "\r":
                                data = json.loads(line)
                                for rec in data['Records']:
                                    if successful_api:
                                        if "errorCode" not in rec and rec['eventType'] == 'AwsApiCall':
                                            rec['sourceCloudTailFile'] = cf
                                            filtered_json['Records'].append(rec)
                                    else: 
                                        rec['sourceCloudTailFile'] = cf
                                        filtered_json['Records'].append(rec)
    except Exception as error:
        print(f"An error has occurred : {error}", file=sys.stdout)
        print("If you are running into errors you may need to remove Windows ^M from the .json files.", file=sys.stdout)
        print("NOTICE: Please take caution in running the below commands", file=sys.stdout)
        print("as they can corrupt your OS files if not ran from the correct directory!", file=sys.stdout)
        print("#", file=sys.stdout)
        print("# Change to CloudTrail Log Root Directory", file=sys.stdout)
        print("$ cd <dir>", file=sys.stdout)
        print("# Decompress the .json.gz files from CloudTrail", file=sys.stdout)
        print("$ gunzip -r", file=sys.stdout)
        print("# Remove Windows Char (^M)", file=sys.stdout)
        print("$ find . -type f | xargs -Ix sed -i.bak -r 's/\\r//g' x", file=sys.stdout)
        print("# After checking .json files are OK, remove .bak files", file=sys.stdout)
        print("$ find . -type f -name '*.bak' | xargs -Ix rm x", file=sys.stdout)
        print()

    return filtered_json


def filter_cloudtrail_logs(log_data=None, k=None, v=None):
    if not log_data:
        print("There is no CloudTrail log data to filter..", file=sys.stdout)
        return

    if not k:
        print("There is no provided key..", file=sys.stdout)
        return 

    if not v:
        print("There is no provided value..", file=sys.stdout)
        return 

    filtered_log_data = {"Records": []}

    # Filter out the records that do not match our user supplied filters
    for indx, rec in enumerate(log_data['Records']):
        if k == "search" and v:
            formatted_rec = json.dumps(rec, indent=4)
            if v in formatted_rec:
                filtered_log_data['Records'].append(rec)
        else:
            if k in rec:
                if v in rec[k]:
                    filtered_log_data['Records'].append(rec)
                
    return filtered_log_data 


if __name__ == "__main__":
    """
    init

    Initialize the script application's main function
    """
    parser = argparse.ArgumentParser()

    # Required arguments
    parser.add_argument("--dir", help="Directory to collect CloudTrail files from")
    parser.add_argument("--file", help="File to collect CloudTrail records from")

    # Additional arguments
    parser.add_argument("--successful_api", help="Filter on successful AWS API calls", action="store_true")
    parser.add_argument("--search", help="Search for a matching string anywhere in the record.")

    # AWS CloudTrail Log Key Arguments
    parser.add_argument("--eventVersion", help="Filter on an eventVersion string.")
    parser.add_argument("--eventTime", help="Filter on an eventTime string.")
    parser.add_argument("--eventSource", help="Filter on an eventSource string.")
    parser.add_argument("--eventName", help="Filter on an eventName string.")
    parser.add_argument("--awsRegion", help="Filter on an awsRegion string.")
    parser.add_argument("--sourceIPAddress", help="Filter on an sourceIPAddress string.")
    parser.add_argument("--userAgent", help="Filter on a userAgent string.")
    parser.add_argument("--requestID", help="Filter on a reaustID string.")
    parser.add_argument("--eventID", help="Filter on a eventID string.")
    parser.add_argument("--readOnly", help="Filter on a readOnly string. [true|false]")
    parser.add_argument("--eventType", help="Filter on an eventType string.")
    parser.add_argument("--managementEvent", help="Filter on an managementEvent string. [true|false]")
    parser.add_argument("--recipientAccountId", help="Filter on an recipientAccountId string.")
    parser.add_argument("--eventCategory", help="Filter on an eventCategory string.")
    parser.add_argument("--sessionCredentialFromConsole", help="Filter on an sessionCredentialFromConsole string. [true|false]")

    # Parse arguments; If no args provided print help
    args = parser.parse_args(args=None if sys.argv[1:] else parser.print_help())

    # Based on args load the requested JSON data
    if args.dir:
        log_data = cloudtrail_compile_logs(ct_log_dir=args.dir, successful_api=args.successful_api)
    elif args.file:
        log_data = json.load(open(args.file, mode="r", encoding="utf-8"))
    else:
        sys.exit(0)

    # Dynamically filter on each CloudTrail record key requested
    for k in args.__dict__:
        v = args.__dict__[k]
        if ("ct_log_dir" not in k and "dir" not in k and "successful_api" not in k and "file" not in k) and v:
            log_data = filter_cloudtrail_logs(log_data=log_data, k=k, v=v)

    # Return the filtered records to stdout. 
    # Preferred over writing to file so we can still grep, sed, awk, tr, redirect to file etc.
    formatted_filtered_log_data = json.dumps(log_data, indent=4)
    print(formatted_filtered_log_data, file=sys.stdout)