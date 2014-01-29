# Using libkqtime

TODO

to transform the data into graphs:

```
zcat kqtime.log.gz | xz -T 6 > kqtime.log.xz
xzcat kqtime.log.xz | pypy parse-kqtime.py | xz -T 6 > kqtime.dat.xz
xzcat kqtime.dat.xz | python plot-kqtime.py
```
