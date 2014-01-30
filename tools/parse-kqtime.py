#!/usr/bin/python

'''
Intended usage is to parse the log files produced by libkqtime:
  xzcat kqtime.log.xz | pypy parse-kqtime.py | xz -T 6 > kqtime.dat.xz
This will produce a data file that can be plotted with plot-kqtime.py:
  xzcat kqtime.dat.xz | python plot-kqtime.py
'''

import sys
from multiprocessing import Process, JoinableQueue, Lock, cpu_count

def main():
    parse(sys.stdin)
    
def parse(datain):
    n = cpu_count()
    loglock = Lock()
    taskq = JoinableQueue(n*1000)

    for i in range(n): Process(target=worker, args=(taskq, loglock)).start()
    for line in datain: taskq.put(line)
    taskq.join()
    for i in range(n): taskq.put('STOP')

def worker(taskq, loglock):
    msgs = []
    for line in iter(taskq.get, 'STOP'):
        try:
            parts = line.strip().split(';')
            if parts[0] == "KQTIME-OUT" or parts[0] == "KQTIME-IN":
                ts, ms = get_time_data(parts)
                msgs.append("{0} {1} {2}".format("%06f"%ts, parts[0], ms))
            elif parts[0] == "KQTIME-STATS":
                ts, ms = get_time_data(parts)
                outlen, inlen = get_stats_data(parts)
                msgs.append("{0} KQLEN-OUT {1}".format("%06f"%ts, outlen))
                msgs.append("{0} KQLEN-IN {1}".format("%06f"%ts, inlen))
            if len(msgs) > 1000: flush_messages(loglock, msgs)
            taskq.task_done()
        except: continue
    flush_messages(loglock, msgs)

def flush_messages(l, msgs):
    l.acquire()
    while len(msgs) > 0: print msgs.pop(0)
    l.release()

def get_time_data(parts):
    #if parts[2] == 'unknown': return None, None
    d = get_dict(parts[1])
    ms = (d['end'] - d['start']) * 1000.0
    return d['start'], ms

def get_stats_data(parts):
    outlen, inlen = 0, 0
    for sock in parts[2:]:
        if not sock: continue
        d = get_dict(sock)
        outlen += d["snd_len"]
        inlen += d["rcv_len"]
    return outlen, inlen
    
def get_dict(parts):
    d = {}
    for item in parts.split(','):
        if not item: continue
        key, value = item.split('=')
        d[key] = float(value)
    return d

if __name__ == "__main__": sys.exit(main())
