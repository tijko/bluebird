import sys

from time import sleep
from bluebird import Bluebird

#read-in the stack setup from process startup
#

p = int(sys.argv[1])

b = Bluebird(p)
b.start()
#b.restart()
sleep(3);
sys.exit(0)
#b.stop()
#print('Trace rw')
#b.read_trace(1)
#print(b.rdata)
