# UDProxy
Simple SIP tunel/proxy for interfacing two separate networks. It rewrites the SDP payload and SIP Contact to ensure proxy traversal. Also, it writes to source and destination addresses only, ignoring the actual source address of the messages.

Usage
------------
``UDProxy`` creates a SIP tunnel between a SIP gateway and SIP phone via a proxy.

Assuming that the proxy machine running ``UDProxy`` has two interfaces, one 172.16.18.8 and another is 10.0.100.4, the SIP gateway is 172.16.18.4 and runs on port 5060 and the SIP phone runns on 10.0.100.8 on port 5064:

```
UDProxy 172.16.18.8 5061 172.16.18.4 5060 10.0.100.4 5062 10.0.100.8 5064
```

Compiling
------------

Linux, FreeBSD, macOS:
```
$ gcc -O2 UDProxy.c -o UDProxy
```

Windows:
```
gcc -O2 UDProxy.c -o UDProxy
```
