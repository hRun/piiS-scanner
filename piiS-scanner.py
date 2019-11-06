#!/usr/bin/env python3

import argparse
import glob
import logging
import os
import re
import yara

from docopt   import docopt
from pathlib  import Path

## Set up logging
def logsetup(write, verbose, filename):
    level = logging.DEBUG if verbose else logging.INFO

    filename = parse(filename)['target'].replace('.', '_')

    if write:
        logging.basicConfig(filename = "{}.log".format(filename), level = level)
    else:
        logging.basicConfig(format = '%(message)s', level = level)

## Parse scan destination to universably usable format
def parse(source):
    if re.match(r'\\(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': 'share', 'target': source.split('\\')[1], 'directory': '\\'.join(source.split('\\')[2:])}
    elif re.match(r'^https?:\/\/(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': source.split('/')[0], 'target': source.split('/')[2], 'directory': '/'.join(s.split('/')[3:])}
    elif re.match(r'^ftps?:\/\/(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': source.split('/')[0], 'target': source.split('/')[2], 'directory': '/'.join(source.split('/')[3:])}
    else:
        raise ValueError("Unrecognized format for target {0}".format(source))

    return target

## Mount specified share at specified location
def mount(source, destination, credentials):
    if source['type'] == 'share':
        target = r'\\\\' + source['target'] + r'\\' + source['directory']
    if source['type'].startswith('http'):
        pass
    if source['type'].startswith('ftp'):
        pass

    try:
        o = os.popen('mount.cifs {0} {1} -o credentials={2}'.format(target, destination, credentials)).read()
        #print("o: {0}".format(o))
        #if "bad UNC" in o:
        #    raise ValueError()
        logging.debug("\tMounted {0} to {1}.".format(target, destination))
        return True
    except:
        logging.error("\tFailed to mount {0} to {1}. Skipping scan.".format(target, destination))
        try:
            unmount(destination)
        except:
            pass
        return False

## Unmount specified share
def unmount(destination):
    os.system('umount {0}'.format(destination))
    logging.debug("\tUnmounted {0}.".format(destination))

## Do stuff if rule matched
def action(data):
    logging.info("\r\n\t\tFound match for rule '{0}': {1}".format(data['rule'], data['strings']))
    return yara.CALLBACK_CONTINUE

## Scan specified share with specified ruleset(s)
def scan(destination, ruleset):
    try:
        rules = yara.compile(ruleset)
        logging.debug("\tYara rules compiled: {0}.".format(ruleset))
    except Exception as e:
        logging.error("\tYara rule compilation failed. Aborting scan.")
        logging.error("\t{0}".format(e))
        try:
            unmount(destination)
        except:
            pass

    i = 0

    for f in glob.iglob('{0}/**/*'.format(destination), recursive=True):
        try:
            #logging.debug("\tScanning {0}.".format(str(f)))
            matches = rules.match(f, callback=action, which_callbacks=yara.CALLBACK_MATCHES)
            if matches:
                logging.info("\t\tin file: {0}.\r\n".format(f))
            i += 1
        except:
            logging.debug("\t\tFailed to scan {0}. Skipping file.".format(str(f)))
            pass

    return i

## Rountinely invoke all relevant actions in order
def invoke(source, destination, credentials, rules, write):
    logging.info("Starting to scan {0} with {1} rules.".format(source, len(rules)))

    if write:
        print("Starting to scan {0} with {1} rules.".format(source, len(rules)))

    source = parse(source)

    if(mount(source, destination, credentials)):
        i = scan(destination, rules)
        unmount(destination)
        logging.info("Done. Scanned {0} files.".format(i))
        if write:
            print("Done. Scanned {0} files.".format(i))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35))
    parser.add_argument('-v', '--verbose', dest='v',       help='Write verbose output', action='store_true')
    parser.add_argument('-m', '--mount',   dest='mount',   help='Mountpoint to temporarily mount shares to', required=True)
    parser.add_argument('-r', '--rules',   dest='rules',   help='File to read YARA rules from', required=True)
    parser.add_argument('-p', '--pass',    dest='pwd',    help='File to read credentails for authentication from')
    parser.add_argument('-s', '--shares',  dest='shares',  help='File to read multiple shares to scan from')
    parser.add_argument('-t', '--target',  dest='target',  help='Share to scan. Wil be overridden by -s|--shares if specified')
    parser.add_argument('-w', '--write',   dest='write',   help='Write output to file instead of stdout', action='store_true')


    print("           _ _ _____    _____                                 ")
    print("    ____  (_|_) ___/   / ___/_________ _____  ____  ___  _____")
    print("   / __ \/ / /\__ \    \__ \/ ___/ __ `/ __ \/ __ \/ _ \/ ___/")
    print("  / /_/ / / /___/ /   ___/ / /__/ /_/ / / / / / / /  __/ /    ")
    print(" / .___/_/_//____/   /____/\___/\__,_/_/ /_/_/ /_/\___/_/     ")
    print("/_/  Scan shares for PII and sensitive information using YARA.")
    print("\r\n")

    args = parser.parse_args()

    if (not args.shares and not args.target) or not args.rules or not args.mount:
        parser.print_help()

    else:
        logsetup(args.write, args.v, args.shares if args.shares else args.target)

        if args.shares:
            with open(args.shares, 'r') as f:
                for l in f:
                    try:
                        invoke(l, args.mount, args.pwd, args.rules, args.write)
                    except KeyboardInterrupt:
                        unmount(args.mount)
                        logging.error("Received keyboard interrupt. Aborted scan.")
                    except Exception as e:
                        unmount(args.mount)
                        logging.error(e)
        else:
            try:
                invoke(args.target, args.mount, args.pwd, args.rules, args.write)
            except KeyboardInterrupt:
                unmount(args.mount)
                logging.error("Received keyboard interrupt. Aborted scan.")
            except Exception as e:
                unmount(args.mount)
                logging.error(e)
