#!/usr/bin/env python
"""
check_sixxsd is a nagios script for checking the status of a sixxsd instance

Authors: Pim van Pelt <pim@ipng.nl> and Jeroen Massar <jeroen@massar.ch>

Connect to a sixxsd server (IPv4 or IPv6), issue command pop show status and
return OK if the sixxsd is healthy, WARNING if it is up but missing enough
tunnels and CRITICAL if we couldn't connect, write the command or read a response.
"""
import socket
import getopt
import sys

def usage():
  print """Usage:
./check_sixxsd.py [-t <numtunnels>] [-p <port>] [-o <min_online>] \\
    [-a <min_active>] [-c <min_configured>] -h <hostname>

Connects to <hostname>:<port> and issues 'pop show status' command
expecting the total amount of configured tunnels to be more than <numtunnels>.
If connect, write or read error, return CRITICAL. The sixxsd returns 
"total <active> <online> <configured>". Online in this context means "received
a packet within 15min", and Active means "has link state up", and Configured
means "is known to sixxsd".

Alerting logic:
- If total configured tunnels is 0, return CRITICAL (this POP is broken).
- If total configured tunnels is less than <numtunnels> return OK (the POP is
  too small to care).
- for each of min_online, min_active, min_configured:
  IFF it is a fraction (between 0 and 1):
  - If online/active < <min_online> then return WARNING.
  - If active/configured < <min_active> then return WARNING.
  - If min_configured is a fraction, it is ignored.
  ELSE it is considered an absolute number:
  - If online < <min_online> then return WARNING.
  - If active < <min_active> then return WARNING.
  - If configured < <min_configured> then return WARNING.
- Otherwise, return OK and the total amount of configured, online and active
tunnels.

Example:
./check_sixxsd.py # shows help.
./check_sixxsd.py -t 50 -o 0.10 -a 0.50 -p 42003 -h chtst01.example.net
./check_sixxsd.py -t 50 -o 1 -a 2 -c 5 -p 42003 -h chtst01.example.net
"""
  sys.exit(3)


def parse_args(argv):
  flags = dict()

  if not argv:
    usage()

  try:
    opts, args = getopt.getopt(argv, 'h:p:t:a:o:c:',
      ['host','port=','tunnels=','min-active','min-online','min-configured'])
  except getopt.GetoptError, err:
    print "parse_args: getopt(): "+str(err)
    usage()

  if args:
    print "parse_args: Extra args found: "+' '.join(args)
    usage()

  flags['port'] = 42003
  flags['tunnels'] = 50
  flags['min-online'] = 0.10
  flags['min-active'] = 0.50
  flags['min-configured'] = 5
  for o, a in opts:
    if o in ('-h', '--host'):
      flags['host'] = a
    if o in ('-p', '--port'):
      flags['port'] = a
    if o in ('-t', '--tunnels'):
      flags['tunnels'] = int(a)
    if o in ('-o', '--min-online'):
      flags['min-online'] = float(a)
    if o in ('-a', '--min-active'):
      flags['min-active'] = float(a)
    if o in ('-c', '--min-configured'):
      flags['min-configured'] = float(a)
  return flags

def sixxsd_get_status(host, port):
  try:
    sock = socket.create_connection ((host,port), 5)
  except:
    CRITICAL("Could not connect to [%s].%s" % (host, port))

  file = sock.makefile()
  try:
    banner = file.readline().strip()
  except:
    CRITICAL("banner read error")

  if banner[:3] != "200":
    CRITICAL("%s" % (banner.strip()))

  try:
    file.write("pop show status\r\n")
    file.flush()
  except:
    CRITICAL("status write error")

  ret = dict()
  try:
    for line in file:
      line = line.strip()
      if line[:5] == "total":
        _a = line.split(" ")
        ret['online'] = int(_a[1])
        ret['active'] = int(_a[2])
        ret['configured'] = int(_a[3])
        break
  except:
    CRITICAL("status read error")
  if not ret.has_key('configured'):
    CRITICAL("could not read 'configured' tunnels")
  return ret

def CRITICAL(text):
  print "CRITICAL - %s" % text.strip()
  sys.exit(2)

def WARNING(text):
  print "WARNING - %s" % text.strip()
  sys.exit(1)

def OK(text):
  print "OK - %s" % text.strip()
  sys.exit(0)

def main():
  argv = sys.argv[1:]
  flags = parse_args(argv)
  status = sixxsd_get_status(flags['host'], flags['port'])

  if status['configured'] == 0:
    CRITICAL("No tunnels configured")

  if status['configured'] < flags['tunnels']:
    OK(("Small/Unused POP, tunnels configured: %d (want at least %d)" %
            (status['configured'],  flags['tunnels'])))

  online_fraction = float(status['online']) / status['configured']
  active_fraction = float(status['active']) / status['online']

  if flags['min-online'] >= 1:
    if status['online'] < flags['min-online']:
      WARNING(("Too few tunnels online: %d (want %d)" %
              (status['online'], flags['min-online'])))
  else:
    if online_fraction < flags['min-online']:
      WARNING(("Too few tunnels online: %d (%.0f%%, want %.0f%%)" %
              (status['online'], online_fraction * 100, flags['min-online'] * 100)))

  if flags['min-active'] >= 1:
    if status['active'] < flags['min-active']:
      WARNING(("Too few tunnels active: %d (want %d)" %
              (status['active'], flags['min-active'])))
  else:
    if active_fraction < flags['min-active']:
      WARNING(("Too few tunnels active: %d (%.0f%%, want %.0f%%)" %
              (status['active'], active_fraction * 100, flags['min-active'] * 100)))

  if flags['min-configured'] >= 1 and status['configured'] < flags['min-configured']:
    WARNING(("Too few tunnels configured: %d (want %d)" %
            (status['configured'], flags['min-configured'])))

  OK(("Tunnels configured: %d, online: %d, active: %d" %
     (status['configured'], status['online'], status['active'])))
  ## notreached

if __name__ == '__main__':
  main()
