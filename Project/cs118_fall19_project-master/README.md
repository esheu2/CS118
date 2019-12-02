UCLA CS118 Project (Simple Router)
====================================

For more detailed information about the project and starter code, refer to the project description on CCLE.

(For build dependencies, please refer to [`Vagrantfile`](Vagrantfile).)

## Makefile

The provided `Makefile` provides several targets, including to build `router` implementation.  The starter code includes only the framework to receive raw Ethernet frames and to send Ethernet frames to the desired interfaces.  Your job is to implement the routers logic.

Additionally, the `Makefile` a `clean` target, and `tarball` target to create the submission file as well.

You will need to modify the `Makefile` to add your userid for the `.tar.gz` turn-in at the top of the file.

## Academic Integrity Note

You are encouraged to host your code in private repositories on [GitHub](https://github.com/), [GitLab](https://gitlab.com), or other places.  At the same time, you are PROHIBITED to make your code for the class project public during the class or any time after the class.  If you do so, you will be violating academic honestly policy that you have signed, as well as the student code of conduct and be subject to serious sanctions.

## Known Limitations

When POX controller is restrated, the simpler router needs to be manually stopped and started again.

## Acknowledgement

This implementation is based on the original code for Stanford CS144 lab3 (https://bitbucket.org/cs144-1617/lab3).

## TODO

NAME: Everett Sheu
UID: 704-796-167

### High Level Design:
In this project we were provided with skeleton code to implement a basic router. The files that I had to modify to implement proper router functionality are as follows:
1. simple-router.cpp
2. arp-cache.cpp
3. routing-table.cpp

#### simple-router.cpp:
For the simple router, I had to implement the handlePacket method. This method needed to handle an Ethernet frame properly based on the operations specified within the frame. These include sending/receiving ARP requests/replies, sending/receiving IP Packets, and handling ICMP echos and replies. The method first checks to see if the received ethernet packet contains either an ARP or IPv4 packet.
For ARP packets, it checks the ARP operation type to determine if it is a request or a reply. For requests, my implementation sends back a reply. For replies, it checks to see if the IP-MAC mapping of the reply is in the cache yet and inserts it if not yet present. It then dispatches the pending packets that correspond to the entry in the cache.

For IP packets, it first checks to see if the packet is even of valid size. After that, it validates the IP header checksum. Then, the packet's time to live is decremented and the checksum is recomputed for the next hop. The method then checks all of its interfaces to see if the packet was destined for the router. If destined for the router, it then checks if it carries an ICMP payload. For ICMP replies, it does nothing with the packet. For ICMP requests, it will respond back to the sender with a ICMP reply of the same contents as the ICMP payload. If it does not have an ICMP payload, it will check the routing table for the next hop IP by using a longest matching prefix algorithm. Then, it will check the ARP cache to see if it contains the mac address of the destination IP. If it does, it will forward to IP packet to the destination. Otherwise, it will queue the request and send an ARP request for the destination IP.

#### arp-cache.cpp:
For the ARP cache, I had to implement the periodicCheckArpRequestsAndCacheEntries method. This method is called once a second to reduce the staleness of the ARP cache. This is done by removing entries that are either older than 30 seconds and requests that have been sent 5 or more times. For requests that have not yet been sent 5 times, the method will dispatch another arp request to the network.

#### routing-table.cpp:
For the routing table, I had to implement the lookup method. This method is called to find the next hop IP address to forward an IP packet to. The method utilizes the Longest Matching Prefix algorithm to find a suitable next hop address.

### Problems I ran into:
The main issues I ran into were runtime errors. Compilation errors were largely not too difficult to navigate due to the compiler pin-pointing the issues for me. However runtime errors often required me to fiddle around with my logic and read Piazza posts for inspiration. The biggest headache was my ARP cache having duplicate cached entries. This was resolved by first checking if the cache had already gotten an identical entry.
