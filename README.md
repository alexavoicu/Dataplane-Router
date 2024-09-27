Tema 1 PCOM - Router implementation


The flow of the implementation follows theese steps:

    The router listens on its interfaces for incoming packets. Upon receipt, it extracts the MAC address from 
the Ethernet header to determine if the packet is intended for the router itself.
If the destination MAC address does not match the router's interface MAC address (and is not a broadcast
address), the packet is discarded, otherwise we proceed to verify what type of package it is.
If it is an arp package we handle the two cases accordingly: the request and the reply. If we get a reply, than a new 
entry is created and the packages waiting in the queue are sent. If we get a request, we respond with the requested
mac address.
    We further handle the case where the package received is an ipv4 one: if the protocol is icmp we need to send
echo reply by updating the icmp header with the response values. We verify that the package was not currupted, 
using the checksum and validate that the TTL has not expired, if it did, we create an icmp package to be sent,
in order to signal the error. This icmp package is created by updating the received ethernet header and ipv4 
header, constructing a new icmp header and copying the ipv4 header and first 64 bits of its payload. We decrease
the ttl and then search through the route table to find the entry that matches the ip address that the package
should be sent to. In order to make the search more efficient, i sorted the table so that it has the longest
masks first and apply a modified version of the binary search based on that. If no appropriate route is found,
the router sends an ICMP Destination Unreachable message to the packet's source IP address. The mac address is
needed in order for the package to be sent. If an arp entry that matches is not found, we need to send an arp 
request and put our package in a queue waiting to be sent, along side the length of the package, which is 
needed in the send_to_link function.
Following the procedures described in the final forwarding stage, packets that don't need extra processing 
(non-ICMP IPv4 packets, with valid routes and ARP entries) are forwarded straight away.

    Important features of the network layer, such as packet forwarding, ARP processing, and ICMP message handling
are highlighted in this router implementation. It functions as a basic project to comprehend more intricate
network protocols and routing characteristics.

Cerinte rezolvate: Procesul de dirijare
Longest Prefix Match eficient
Protocolul ARP
Protocolul ICMP
