#!/usr/bin/env python2

from optparse import OptionParser
import sys

import frida

"""
Use frida-trace -i "snd_pcm_wr*" mpg123" to quickly discover called functions.

Give https://www.frida.re/docs/javascript-api/#apiresolver a try.

"""


def on_output(pid, fd, data):
    sys.stderr.write(data.decode("utf-8"))


def on_message(message, data):
    try:
        nature, value = message['payload']
        if nature == u"rate":
            print("P> Rate is %s" % value)
        elif nature == u"format":
            print("> PCM format is %s" % value)
        elif nature == u"channels":
            print("> Channel count is %s" % value)
        elif nature == u"pcm":
            fp.write(data)
            fp.flush()
        else:
            print(message)
        if nature == u"exit":
            fp.flush()
            # fp.close()
            # https://www.frida.re/docs/messages/
            script.post({"type": "exit_ack"})
    except KeyError:
        print("> Oops ->", message)
        pass


# start
parser = OptionParser(usage="Usage: %prog [options]", version="%prog 0.4")
parser.add_option("-p", default=None, help="attach to pid mode", dest="pid")
parser.add_option("-l", default=False, help="launch command mode",
                  action='store_true', dest="launch")
(options, args) = parser.parse_args()

if not options.pid and not options.launch:
    parser.print_help()
    print("")
    print("Example: %s -l /usr/bin/mpg123 knock.mp3" % sys.argv[0])
    print("Example: %s -l /usr/bin/ffplay knock.mp3" % sys.argv[0])
    print("Example: %s -p `pidof cmus`" % sys.argv[0])
    sys.exit(0)

device = frida.get_local_device()

if options.pid:
    print("> Working in attach mode")
    pid = int(options.pid)
else:
    print("> Working in launch mode")
    pid = device.spawn(args[:])

# global stuff
fp = open("output.pcm.frida", "wb")  # play -t raw -r 22.05k -e signed -b 16 -c 1 output.pcm.frida

device.on('output', on_output)
session = device.attach(pid)

script = session.create_script(open("payload.js").read())

script.on('message', on_message)
if options.launch:
    device.resume(pid)
script.load()

# print(session.enumerate_modules())

sys.stdin.read()
