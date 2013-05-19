import optparse
from socket import *

def conn_scan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET,SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send('TestData\r\n')
        results = connSkt.recv(100)
        print '[+]%d/tcp open' % tgtPort
        print '[+]', str(results)
        connSkt.close()
    except Exception as e:
        print "Error: {0}".format(str(e))
        print '[-]%d/tcp open' % tgtPort

def port_scan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print "[-] Cannot resolve '%s': Unknown host" % tgtHost
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print '\n[+]Scan Results for: ' + tgtName[0]
    except:
        print '\n[+]Scan Results for: ' + tgtIP
    
    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        print 'Scanning port', tgtPort
        conn_scan(tgtHost, int(tgtPort))

def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] seperated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = str(options.tgtPort).split(',')
    if (tgtHost == None) | (tgtPorts == None):
        print parser.usage
        exit(0)
    port_scan(tgtHost, tgtPorts)

if __name__ == '__main__':
    main()
