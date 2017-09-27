# OptionsBleed-POC-Scanner
OptionsBleed (CVE-2017-9798) PoC / Scanner

## Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

## Usage
```
python bleeder.py -h
usage: bleeder.py [-h] [-c COUNT] [-tc THREAD_COUNT] [-nv] [-ni] [-v] [-e] url

positional arguments:
  url                   full URL (including http(s)) to be scanned

optional arguments:
  -h, --help            show this help message and exit
  -c COUNT, --count COUNT
                        number of times to scan (default: 1000)
  -tc THREAD_COUNT, --thread-count THREAD_COUNT
                        max concurrent thread count (default: 500)
  -nv, --no-verify      does not verify ssl connection (may be necessary for
                        self-signed certs)
  -ni, --no-ignore      does NOT ignore ssl warnings (default: ignored)
  -v, --verbose         print all headers
  -e, --errors          prints
```

## Simple Usage

```
python bleeder.py "http://www.example.com"
    ::OptionsBleed (CVE-2017-9798) Scanner::

[+] scanning http://www.example.com to see if it bleeds!
[+] checking OPTIONS method
[+] allow headers detected in OPTIONS response
[+] scanning with OPTION method...
[+] 1000 responses captured
[+] unique results: ['OPTIONS, GET, HEAD, POST']
[+] scan complete!
```
