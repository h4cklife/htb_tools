#!/usr/bin/python3

import os
import sys
import argparse
import json

def cloudtrail_dump(ct_log_dir=None, search=None):
    if not ct_log_dir:
        print("You must provide a DIR to collect log files from with --dir. See --help for more information.")
        return False

    cloudtrail_json_logs = [os.path.join(dp, f) for dp, dn, fn in os.walk(os.path.expanduser(ct_log_dir)) for f in fn]

    for cf in cloudtrail_json_logs:
        if ".json.gz" in cf:
            print("You must first decompress the CloudTrail logs with gunzip!")
            return False

    try:
        for cf in cloudtrail_json_logs:
            if '.json.bak' not in cf:
                with open(cf, mode="r", encoding="utf-8") as f:
                    for line in f:
                        if line != "" and line != "^M" and line != "\n" and line != "\r":
                            data = json.loads(line)
                            data = json.dumps(data, indent=4)
                            if search:
                                if search in data:
                                    print(data)
                            else:
                                print(data)
    except Exception as error:
        print(f"An error has occureed : {error}")
        print("If you are running into errors you may need to remove Windows ^M from the .json files.")
        print("NOTICE: Please take caution in running the below commands")
        print("as they can corrupt your OS files if not ran from the correct directory!")
        print()
        print("# Change to CloudTrail Log Root Directory")
        print("$ cd <dir>")
        print("# Decompress the .json.gz files from CloudTrail")
        print("$ gunzip -r")
        print("# Remove Windows Char (^M)")
        print("$ find . -type f | xargs -Ix sed -i.bak -r 's/\\r//g' x")
        print("# After checking .json files are OK, remove .bak files")
        print("$ find . -type f -name '*.bak' | xargs -Ix rm x")
        print()
        return False


if __name__ == "__main__":
    """
    init

    Initialize the script application's main function
    """
    parser = argparse.ArgumentParser()

    # Options and required variables
    parser.add_argument("--verbose", help="Increase output verbosity",
                        action="store_true")

    parser.add_argument("--dir", help="Directory to collect files from")
    parser.add_argument("--search", help="Only show lines matching search term")

    # Functions and procedures
    parser.add_argument("--ctdump", help="Parse all CloudTrail JSON logs "
        " in DIR and dump to stdout with indent. Cannot be .json.gz. Use gunzip first. "
        "Requirements: [--dir]", action="store_true")

    args = parser.parse_args(args=None if sys.argv[1:] else parser.print_help())

    # Verbose logging of options and required variable assignments
    if args.verbose:
        print("Verbosity turned on")

        if args.dir:
            print(f"Collecting files from : {args.dir}")

    # Check and see which function or procedure we are running for the user and execute
    if args.ctdump:
        if 'search' not in args:
            args.search = None

        cloudtrail_dump(ct_log_dir=args.dir, search=args.search)