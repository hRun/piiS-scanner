#!/usr/bin/env python3

import argparse
import glob
import os
import yara

from docopt   import docopt
from pathlib  import Path

## Mount specified share at specified location
def mount(source, destination, credentials):
    try:
        o = os.popen('mount.cifs {0} {1} -o credentials={2}'.format(source, destination, credentials)).read()
        #print("o: {0}".format(o))
        #if "bad UNC" in o:
        #    raise ValueError()
        print("\tMounted {0} to {1}.".format(source, destination))
        return True
    except:
        print("\tFailed to mount {0} to {1}. Skipping scan.".format(source, destination))
        try:
            unmount(destination)
        except:
            pass
        return False

## Unmount specified share
def unmount(destination):
    os.system('umount {0}'.format(destination))
    print("\tUnmounted {0}.".format(destination))

## Do stuff if rule matched
def action(data):
    print("\t\tFound match for rule '{0}': {1}".format(data['rule'], data['strings']))
    return yara.CALLBACK_CONTINUE

## Scan specified share with specified ruleset(s)
def scan(destination, ruleset):
    try:
        rules = yara.compile(ruleset)
        print("\tYara rules compiled: {0}.".format(ruleset))
    except:
        print("\tYara rule compilation failed. Aborting scan.")
        try:
            unmount(destination)
        except:
            pass

    i = 0

    for f in glob.iglob('{0}/**/*'.format(destination), recursive=True):
        try:
            matches = rules.match(f, callback=action, which_callbacks=yara.CALLBACK_MATCHES)
            if matches:
                print("\t\tin file: {0}.\r\n".format(f))
            i += 1
        except:
            #print("\t\t\tFailed to scan {0}. Skipping file.".format(str(f)))
            pass

    return i

## Rountinely invoke all relevant actions in order
def invoke(source, destination, credentials, rules):
    print("Starting to scan {0} with {1} rules.".format(source, len(rules)))
    if(mount(source, destination, credentials)):
        i = scan(destination, rules)
        unmount(destination)
        print("Done. Scanned {0} files.".format(i))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35))
    parser.add_argument('-p', '--pass',    dest='p', help='File to read credentails for authentication from')
    parser.add_argument('-r', '--rules',   dest='r', required=True, help='File to read YARA rules from')
    parser.add_argument('-s', '--shares',  dest='s', help='File to read multiple shares to scan from')
    parser.add_argument('-t', '--target',  dest='t', help='Share to scan. Wil be overridden by -s|--shares if specified')
    parser.add_argument('-m', '--mount',   dest='m', required=True, help='Mountpoint to temporarily mount shares to')
    parser.add_argument('-w', '--write',   dest='w', help='Write output to specified file instead of stdout')
    parser.add_argument('-v', '--verbose', dest='v', action='store_true', help='Write verbose output')

    print("           _ _ _____    _____                                 ")
    print("    ____  (_|_) ___/   / ___/_________ _____  ____  ___  _____")
    print("   / __ \/ / /\__ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/")
    print("  / /_/ / / /___/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    ")
    print(" / .___/_/_//____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     ")
    print("/_/  Scan shares for PII and sensitive information using YARA.")
    print("\r\n")

    args = parser.parse_args()

    if (not args.s and not args.t) or not args.r or not args.m:
        parser.print_help()
    else:
        if args.s:
            with open(args.s, 'r') as f:
                for l in f:
                    try:
                        invoke(l, args.m, args.p, args.r)
                    except KeyboardInterrupt:
                        unmount(args.m)
                        print("Aborted scan.")
        else:
            try:
                invoke(args.t, args.m, args.p, args.r)
            except KeyboardInterrupt:
                unmount(args.m)
                print("Aborted scan.")

