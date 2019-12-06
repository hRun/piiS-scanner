#!/usr/bin/env python3

import argparse
import glob
import logging
import os
import re
import sys
import subprocess
import yara

from docopt   import docopt
from pathlib  import Path

## Set up logging
def logsetup(write, verbose, filename):
    logger = logging.getLogger("".format(filename))

    if write:
        handler = logging.FileHandler("{0}.log".format(filename), mode='w')
    else:
        handler = logging.StreamHandler()
    
    if verbose:
        logger.setLevel(logging.DEBUG)
        handler.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        handler.setLevel(logging.INFO)
        
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    return logger

## Parse scan destination to universably usable format
def parse(source):
    if re.match(r'\\\%?(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': 'share', 'target': source.split('\\')[1], 'directory': '\\'.join(source.split('\\')[2:])}
    if re.match(r'\\\\\%?(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': 'share', 'target': source.split('\\')[2], 'directory': '\\'.join(source.split('\\')[3:]).strip('\n')}
    elif re.match(r'^https?:\/\/(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': source.split('/')[0], 'target': source.split('/')[2], 'directory': '/'.join(s.split('/')[3:])}
    elif re.match(r'^ftps?:\/\/(\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*', source):
        target = {'type': source.split('/')[0], 'target': source.split('/')[2], 'directory': '/'.join(source.split('/')[3:])}
    elif re.match(r'#.*', source):
        target = {'type': 'comment', 'target': source.lstrip('#'), 'directory': ''}
    else:
        raise ValueError('Unrecognized format for target "{0}"'.format(source))
    
    return target

## Mount specified share at specified location
def mount(logger, write, source, destination, credentials):
    if source['type'] == 'share':
        target = r'\\\\' + source['target'] + r'\\' + source['directory']
    if source['type'].startswith('http'):
        pass
    if source['type'].startswith('ftp'):
        pass

    try:
        process = subprocess.Popen('mount.cifs {0} {1} -o credentials={2}'.format(target, destination, credentials), stderr=subprocess.PIPE, shell=True)
        try:
            error = process.communicate(timeout=60)
        except subprocess.TimeoutExpired as e:
            process = subprocess.Popen('mount.cifs {0} {1} -o credentials={2},vers=1.0'.format(target, destination, credentials), stderr=subprocess.PIPE, shell=True)
            error   = process.communicate(timeout=60)        

        #if re.match(r'.* server does not support the SMB version .*', str(error[1])):
        #    process = subprocess.Popen('mount.cifs {0} {1} -o credentials={2},vers=1.0'.format(target, destination, credentials), stderr=subprocess.PIPE, shell=True)
        #    error   = process.communicate(timeout=60)

        if re.match(r'.*mount error\(.*', str(error[1])):
            raise OSError('{0}'.format(error[1]))

        logger.debug("\tMounted {0} to {1}.".format(target, destination))
        return True
        
    except Exception as e:
        logger.error("\tFailed to mount {0} to {1}. Skipping scan.".format(target, destination))
        logger.error("\t\t{0}".format(e))
        
        if write:
            print("\tFailed to mount {0} to {1}. Skipping scan.".format(target, destination))
            print("\t\t{0}\r\n".format(e))
        
        try:
            unmount(logger, destination)
        except:
            pass
        return False

## Unmount specified share
def unmount(logger, destination):
    process = subprocess.Popen('umount {0}'.format(destination), stderr=subprocess.PIPE, shell=True)
    error   = process.communicate()
    logger.debug("\tUnmounted {0}.".format(destination))

## Do stuff if rule matched
def action(data):
    # Do something if needed
    return yara.CALLBACK_CONTINUE

## Scan specified share with specified ruleset(s)
def scan(logger, destination, ruleset):
    try:
        rules = yara.compile(ruleset)
        logger.debug("\tYara rules compiled: {0}.".format(ruleset))
    except Exception as e:
        logger.error("\tYara rule compilation failed. Aborting scan.")
        logger.error("\t{0}".format(e))
        try:
            unmount(logger, destination)
        except:
            pass

    i = 0
	
    for f in glob.iglob('{0}/**/*'.format(destination), recursive=True):
        try:
            #logger.debug("\tScanning {0}.".format(str(f)))
            matches = rules.match(f, callback=action, which_callbacks=yara.CALLBACK_MATCHES)
            if matches:
                logger.info('\r\n\t\tFound match for rule "{0}"'.format(ruleset))
                #logger.debug('\t\t\t"{0}"'.format(matches['strings']))
                logger.info("\t\tin file: {0}.\r\n".format(f))
            i += 1
        except:
            logger.debug("\t\tFailed to scan {0}. Skipping file.".format(str(f)))
            pass
			
    return i

## Rountinely invoke all relevant actions in order
def invoke(logger, source, destination, credentials, rules, write):
    if rules.startswith('[') and rules.endswith(']'):
        rules = rules[1:][:-1]
        rules = rules.split(',')
    else:
        rules = [rules]

    for rulepath in rules:
        r = open(rulepath, 'r').read().count('meta:')
        logger.info("Starting to scan {0}://{1}/{2} with {3} rules.".format(source['type'], source['target'], source['directory'].replace('\\','/'), r))

        if write:
            print("Starting to scan {0}://{1}/{2} with {3} rules.".format(source['type'], source['target'], source['directory'].replace('\\','/'), r))
        
        
        if(mount(logger, write, source, destination, credentials)):
            i = scan(logger, destination, rulepath)
            unmount(logger, destination)
            logger.info("Done. Scanned {0} files.\r\n".format(i))
            if write:
                print("Done. Scanned {0} files.\r\n".format(i))


if __name__ == "__main__":

    parser = argparse.ArgumentParser(formatter_class=lambda prog: argparse.HelpFormatter(prog, max_help_position=35))
    parser.add_argument('-v', '--verbose', dest='v',       help='Write verbose output', action='store_true')
    parser.add_argument('-m', '--mount',   dest='mount',   help='Absolute path where to temporarily mount shares to', required=True)
    parser.add_argument('-r', '--rules',   dest='rules',   help='File to read YARA rules from. Specify multiple rule files like this: [rules/file1,rules/file2]', required=True)
    parser.add_argument('-p', '--pass',    dest='pwd',     help='File to read credentials for authentication from (absolute path)')
    parser.add_argument('-s', '--shares',  dest='shares',  help='File to read multiple shares to scan from')
    parser.add_argument('-t', '--target',  dest='target',  help='Share to scan. Enclosed in single quotes. Will be overridden by -s|--shares if specified')
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
    elif args.pwd and not os.path.isabs(args.pwd):
        print("Check supplied value for -p/-pass.")
        print("Path to credential file must be absolute.")
    elif args.pwd and not os.access(args.pwd, os.R_OK):
        print("Credentials file could not be read.")
        print('Make sure you have read permissions to "{0}".'.format(args.pwd))
    else:
        if args.shares:
            with open(args.shares, 'r') as f:
                for l in f:
                    try:
                        l = parse(l)
                        
                        if l['type'] == 'comment':
                            print('Skipping commented out target "{0}".\r\n'.format(l['target'].strip('\n')))
                        else:
                            logger = logsetup(args.write, args.v, "{0}-{1}".format(l['target'].replace('.', '_'), l['directory'].replace('.', '_').replace('/', '_').replace('\\', '_')))
                            invoke(logger, l, args.mount, args.pwd, args.rules, args.write)
                            logging.shutdown()
                    except KeyboardInterrupt:
                        unmount(logger, args.mount)
                        logger.error("Received keyboard interrupt. Aborted scan.")
                        logging.shutdown()
                        sys.exit(1)
                    except ValueError as e:
                        logger.error(e)
                        logger.error("\r\nSkipping target.")
                        logging.shutdown()
                        pass
                    except Exception as e:
                        unmount(logger, args.mount)
                        logger.error(e)
                        logging.shutdown()
        else:
            try:
                target = parse(args.target)
                
                if target['type'] == 'comment':
                    raise ValueError('Single target cannot be commented out.')
                logger = logsetup(args.write, args.v, "{0}-{1}".format(target['target'].replace('.', '_'), target['directory'].replace('.', '_').replace('/', '_').replace('\\', '_')))
                invoke(logger, target, args.mount, args.pwd, args.rules, args.write)
                logging.shutdown()
            except KeyboardInterrupt:
                unmount(logger, args.mount)
                logger.error("Received keyboard interrupt. Aborted scan.")
                logging.shutdown()
                sys.exit(1)
            except ValueError as e:
                print(e)
                print("\r\nCheck supplied value for -t/--target.")
                logging.shutdown()
                pass
            except Exception as e:
                unmount(logger, args.mount)
                logger.error(e)
                logging.shutdown()
