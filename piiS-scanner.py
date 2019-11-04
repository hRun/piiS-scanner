#!/usr/bin/env python3

import yara
import os
import glob
from pathlib import Path

## Mount specified share at specified location
def mount(source, destination, credentials):
    try:
        os.popen('mount.cifs {0} {1} -o credentials={2}'.format(source, destination, credentials)).read()
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
    print("\t\t\tFound match for rule '{0}': '{1}'".format(data['rule'], data['strings']))
    return yara.CALLBACK_CONTINUE

## Scan specified share with specified ruleset(s)
def scan(destination, ruleset):
    try:
        r = {'namespace{0}'.format(counter):item for counter, item in enumerate(ruleset)}
        del r["namespace0"]
        rules = yara.compile(filepaths=r)
        print("\t\tYara rules compiled: {0}.".format(ruleset))
    except:
        print("\t\tYara rule compilation failed. Aborting scan.")
        try:
            unmount(destination)
        except:
            pass

    i = 0

    for f in glob.iglob('{0}/**/*'.format(destination), recursive=True):
        try:
            matches = rules.match(f, callback=action, which_callbacks=yara.CALLBACK_MATCHES)
            if matches:
                print("\t\t\tin file: {0}.\r\n".format(f))
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

    try:
        # Recursively scan one share
        invoke(r"\\\\10.10.10.2\\files", "/mnt/piis", "./credentials/user_creds.txt", ("", "./rules/testrule.txt"))

        # Recursively scan all shares from file
        #with open("./targets/test_targets.txt", "r") as f:
        #    for l in f:
        #        invoke(l, "/mnt/piis", "./credentials/user_creds.txt", ("", "./rules/testrule.txt"))
    except KeyboardInterrupt:
        unmount("/mnt/piis")

