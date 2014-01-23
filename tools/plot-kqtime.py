#!/usr/bin/python

'''
Intended usage is to parse the log files produced by libkqtime:
  xzcat kqtime.log.xz | pypy parse-kqtime.py | xz -T 6 > kqtime.dat.xz
This will produce a data file that can be plotted with plot-kqtime.py:
  xzcat kqtime.dat.xz | python plot-kqtime.py
'''

import matplotlib
matplotlib.use('Agg')
from matplotlib.backends.backend_pdf import PdfPages
import sys, pylab
from numpy import mean

pylab.rcParams.update({
    'backend': 'PDF',
    'font.size': 16,
    'figure.figsize': (4,3),
    'figure.dpi': 100.0,
    'figure.subplot.left': 0.18,
    'figure.subplot.right': 0.92,
    'figure.subplot.bottom': 0.15,
    'figure.subplot.top': 0.92,
    'grid.color': '0.1',
    'axes.grid' : True,
    'axes.titlesize' : 'small',
    'axes.labelsize' : 'small',
    'axes.formatter.limits': (-4,4),
    'xtick.labelsize' : 'small',
    'ytick.labelsize' : 'small',
    'lines.linewidth' : 3.0,
    'lines.markeredgewidth' : 0.5,
    'lines.markersize' : 10,
    'legend.fontsize' : 'x-small',
    'legend.fancybox' : False,
    'legend.shadow' : False,
    'legend.ncol' : 1.0,
    'legend.borderaxespad' : 0.5,
    'legend.numpoints' : 1,
    'legend.handletextpad' : 0.5,
    'legend.handlelength' : 1.6,
    'legend.labelspacing' : .75,
    'legend.markerscale' : 1.0,
    'ps.useafm' : True,
    'pdf.use14corefonts' : True,
    'text.usetex' : True,
})

def main():
    data = parse(sys.stdin)
    pp = PdfPages('kqtimes.pdf')
    #plot(pp, data)
    plot_mean(pp, data)
    pp.close()

def parse(datain):
    data = {}
    for line in datain:
        parts = line.strip().split()
        ts = int(float(parts[0]))
        valtype = parts[1] # KQLEN-IN, KQLEN-OUT, KQTIME-IN, KQTIME-OUT
        val = float(parts[2]) / 1024.0 if 'LEN' in valtype else float(parts[2])
        if ts not in data: data[ts] = {}
        if valtype not in data[ts]: data[ts][valtype] = []
        data[ts][valtype].append(val)
    return data

def plot(pp, d):
    lin, lout, tin, tout = [], [], [], []
    for s in d:
        if "KQLEN-IN" in d[s]: lin.extend(d[s]["KQLEN-IN"])
        if "KQLEN-OUT" in d[s]: lout.extend(d[s]["KQLEN-OUT"])
        if "KQTIME-IN" in d[s]: tin.extend(d[s]["KQTIME-IN"])
        if "KQTIME-OUT" in d[s]: tout.extend(d[s]["KQTIME-OUT"])

    pylab.figure()
    x, y = getcdf(tin)
    pylab.plot(x, y, c='b', label='inq')
    x, y = getcdf(tout)
    pylab.plot(x, y, c='r', label='outq')

    pylab.legend(loc="lower right", prop={'size': 10})
    pylab.title("Mean Queue Time Per Second")
    pylab.xlabel("Queue Time (ms)")
    #pylab.xscale('log')
    pylab.ylabel("Cumulative Fraction")
    pp.savefig()

    pylab.figure()
    x, y = getcdf(lin)
    pylab.plot(x, y, c='b', label='inq')
    x, y = getcdf(lout)
    pylab.plot(x, y, c='r', label='outq')

    pylab.legend(loc="lower right", prop={'size': 10})
    pylab.title("Mean Total Queue Length Per Second")
    pylab.xlabel("Total Queue Length (KiB)")
    #pylab.xscale('log')
    pylab.ylabel("Cumulative Fraction")
    pp.savefig()

def plot_mean(pp, d):
    for s in d:
        for k in d[s]:
            d[s][k] = [mean(d[s][k])]
    plot(pp, d)
    plot_time(pp, d)

def plot_time(pp, d):
    linx, loutx, tinx, toutx = [], [], [], []
    liny, louty, tiny, touty = [], [], [], []
    ts = sorted(d.keys())
    for s in ts:
        h = (s-ts[0])/3600.0
        if "KQLEN-IN" in d[s]:
            liny.append(d[s]["KQLEN-IN"][0])
            linx.append(h)
        if "KQLEN-OUT" in d[s]:
            louty.append(d[s]["KQLEN-OUT"][0])
            loutx.append(h)
        if "KQTIME-IN" in d[s]:
            tiny.append(d[s]["KQTIME-IN"][0])
            tinx.append(h)
        if "KQTIME-OUT" in d[s]:
            touty.append(d[s]["KQTIME-OUT"][0])
            toutx.append(h)

    pylab.figure()
    pylab.scatter(toutx, touty, label='outq', marker='x', s=10, c='r')
    pylab.scatter(tinx, tiny, label='inq', marker='+', s=10, c='b')

    pylab.legend(loc="upper right", prop={'size': 10})
    #pylab.title("Tor Relay Kernel Queuing Time")
    pylab.xlabel("Tick (h)")
    pylab.ylabel("Queue Time (ms)")
    pylab.xlim(xmin=0.0)
    pylab.ylim(ymin=0.0)
    #pylab.xscale('log')
    pp.savefig()

    pylab.figure()
    pylab.scatter(loutx, louty, label='outq', marker='x', s=10, c='r')
    pylab.scatter(linx, liny, label='inq', marker='+', s=10, c='b')

    pylab.legend(loc="upper right", prop={'size': 10})
    #pylab.title("Tor Relay Kernel Queue Length")
    pylab.xlabel("Tick (h)")
    pylab.ylabel("Total Queue Length (KiB)")
    pylab.xlim(xmin=0.0)
    pylab.ylim(ymin=0.0)
    #pylab.xscale('log')
    pp.savefig()

## helper - cumulative fraction for y axis
def cf(d):
    return pylab.arange(1.0,float(len(d))+1.0)/float(len(d))

## helper - return step-based CDF x and y values
## only show to the 99th percentile by default
def getcdf(data, shownpercentile=0.995):
    data.sort()
    frac = cf(data)
    x, y, lasty = [], [], 0.0
    for i in xrange(int(round(len(data)*shownpercentile))):
        x.append(data[i])
        y.append(lasty)
        x.append(data[i])
        y.append(frac[i])
        lasty = frac[i]
    return x, y

if __name__ == "__main__": sys.exit(main())
