mkap
====
"mkap" is a simple tool for capturing network traffic to a file or
streaming it to a remote host. Streaming functionality is especially
useful for observing network activity of a remote host with limited
resources (e.g. embedded devices).

Captured stream is in pcap format and the file or stream
can be viewed using wireshark.

Usage
=======
## Capture interface
Capture interface can be specified using the "-i" parameter.
If no capture interface is specified, mkap will capture traffic from
all interfaces.

Ex:

    # mkap -i eth0

## Capture files
Captured data can be written to a file in pcap format. You can
use the wireshark tool to view and parse the file later on. "-f" parameter
can be used to specify the capture file. If the capture file is not specified,
the mkap tool will just wait for an incoming TCP connection from port 54321
and stream the captured data to it.

Ex:

    host1 # # capture to a local file
    host1 # mkap -i eth0 -f capture.pcap

    host1 # # capture to a stream
    host1 # mkap -i eth0

    host2 # # connect to the mkap host and dump the captured data to a file
    host2 # nc ${MKAP_HOSTIP} 54321 > capture.pcap

## real-time streaming to wireshark
"pcap2tap" tool is a filter tool to receive data from the remote
mkap host and stream it to a tun/tap virtual network interface so that one
can use mainstream packet capture utilities like wireshark to view the network
activity in real-time.

Ex:

    host1 # # capture to a stream
    host1 # mkap -i eth0

    host2 # # connect to the mkap host and feed the incoming capture data to a virtual device
    host2 # nc ${MKAP_HOSTIP} 54321 | pcap2tap
    host2 # # use wireshark to observe network activity

