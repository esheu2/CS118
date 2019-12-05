/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "NOTE: Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  // For debugging purposes
  // print_hdrs(packet);

  // Find input network interface using findIfaceByName()
  const Interface* iface = findIfaceByName(inIface);
  // If interface unknown, then drop packet
  if (iface == nullptr) {
    std::cerr << "ERROR: Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN
  // Called when the router receives a packet on the interface

  // Read ethernet header
  ethernet_hdr e_hdr;
  memcpy(&e_hdr, packet.data(), sizeof(ethernet_hdr));

  // Get MAC address of packet
  std::string packet_addr = macToString(packet);
  std::string iface_addr = macToString(iface->addr);
  std::string b_addr = "FF:FF:FF:FF:FF:FF";
  std::string lower_b_addr = "ff:ff:ff:ff:ff:ff";

  // Should ignore frames not destined for router or sent to broadcast address
  if ((packet_addr != iface_addr) && (packet_addr != b_addr) && (packet_addr != lower_b_addr)) {
    std::cerr << "ERROR: Packet not destined for router, ignoring" << std::endl;
    return;
  }

  // Check eth_type field using ethertype() from utils.cpp
  uint16_t e_type = ethertype((const uint8_t*)packet.data());

  // Ignore ethernet frames other than type ARP and IPv4
  // Ethertypes set in protocol.hpp
  // Handle ARP and IPv4 packets accordingly
  switch(e_type) {
    case ethertype_arp:
      std::cerr << "NOTE: Handling ARP packet" << std::endl;
      handleArpPacket(packet, iface);
      break;
    case ethertype_ip:
      std::cerr << "NOTE: Handling IPv4 packet" << std::endl;
      handleIpPacket(packet, iface);
      break;
    default:
      std::cerr << "ERROR: Packet is not of type ARP or IPv4, ignoring" << std::endl;
      return;
  }
}

void
SimpleRouter::handleArpPacket(const Buffer& packet, const Interface* iface){
  // Get pointer to ARP header
  // TODO: use reinterpret_cast
  arp_hdr* a_hdr = (arp_hdr *)(packet.data() + sizeof(ethernet_hdr));

  // Get ARP operation from header
  uint16_t a_op = ntohs(a_hdr->arp_op);

  // Check if operation is a ARP request (defined in protocol.hpp)
  if (a_op == arp_op_request) {
    std::cerr << "NOTE: Handling ARP request" << std::endl;

    // Check that packet has a matching target IP address and network interface ip
    if (a_hdr->arp_tip != iface->ip) {
      std::cerr << "ERROR: Target IP address does not match, dropping packet" << std::endl;
      return;
    }

    // Create and send an ARP response packet 
    // Largely based on creating ARP request in arp-cache.cpp
    // Get required length of combined ethernet + arp headers
    uint8_t req_len = sizeof(ethernet_hdr) + sizeof(arp_hdr);

    // Create buffer for packet
    Buffer packetBuffer(req_len);
    uint8_t* req_pack = (uint8_t *)packetBuffer.data();

    // Get pointers to ethernet and arp headers
    ethernet_hdr* reply_e_hdr = (ethernet_hdr *)req_pack;
    arp_hdr* reply_a_hdr = (arp_hdr *)(req_pack + sizeof(ethernet_hdr));

    // Create ethernet header
    // Set the destination and source addresses from the ARP header and interface
    // The ARP response source is the interface's address
    // The ARP response destination is the ARP request sender's hardware address
    memcpy(reply_e_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
    memcpy(reply_e_hdr->ether_dhost, &(a_hdr->arp_sha), ETHER_ADDR_LEN);
    reply_e_hdr->ether_type = htons(ethertype_arp);

    // Create ARP header
    reply_a_hdr->arp_hrd = htons(arp_hrd_ethernet);
    reply_a_hdr->arp_pro = htons(ethertype_ip);
    reply_a_hdr->arp_hln = ETHER_ADDR_LEN;
    reply_a_hdr->arp_pln = 4;
    reply_a_hdr->arp_op = htons(arp_op_reply);

    memcpy(reply_a_hdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
    reply_a_hdr->arp_sip = iface->ip;
    memcpy(reply_a_hdr->arp_tha, &(a_hdr->arp_sha), ETHER_ADDR_LEN);
    reply_a_hdr->arp_tip = a_hdr->arp_sip;

    // For debugging purposes
    // print_hdrs(packetBuffer);

    // Send reply packet
    sendPacket(packetBuffer, iface->name);
  } else if (a_op == arp_op_reply) {
    std::cerr << "NOTE: Handling ARP reply" << std::endl;

    // Record IP-MAC mapping info in ARP cache using arp-cache.cpp

    // Get the source IP address of the arp reply
    uint32_t a_sip = a_hdr->arp_sip;

    // Get the source hardware address of the arp reply
    Buffer a_mac(ETHER_ADDR_LEN);
    memcpy(a_mac.data(), a_hdr->arp_sha, ETHER_ADDR_LEN);

    // Add IP to MAC mapping in ARP cache
    // Save a pointer to the ArpRequest with a matching IP if it exists in request queue
    std::shared_ptr<ArpRequest> a_request = m_arp.insertArpEntry(a_mac, a_sip);

    // Check if IP is in request queue
    // Given address from ARP, can send pending packets arp request
    // Iterate through packets, based on loop in arp-cache.cpp
    if (a_request != nullptr) {
      for (std::list<PendingPacket>::const_iterator packetIt = a_request->packets.begin(); packetIt != a_request->packets.end(); ++packetIt) {
        const uint8_t* arp_data = packetIt->packet.data();
        ethernet_hdr* eth_hdr = (ethernet_hdr *) arp_data;

        memcpy(eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN); 
        memcpy(eth_hdr->ether_dhost, a_hdr->arp_sha, ETHER_ADDR_LEN);

        sendPacket(packetIt->packet, packetIt->iface);
      }
      // Remove pending request from arp request queue
      m_arp.removeRequest(a_request);
    }
  } else {
    std::cerr << "ERROR: ARP operation is not of type request or reply" << std::endl;
  }
}

void
SimpleRouter::handleIpPacket(const Buffer& packet, const Interface* iface){
  // Get the packet
  Buffer ip_packet(packet);

  // Get pointer to the IP header
  ip_hdr* ip_header = (ip_hdr*)(ip_packet.data() + sizeof(ethernet_hdr));

  // Verify that minimum length of IP packet is met
  // Minimum allowed size of IP packet is the size of its header
  // Packet should be a minimum size of the ethernet + ip header sizes
  if ((packet.size() < (sizeof(ethernet_hdr) + sizeof(ip_hdr))) || (ip_header->ip_len < sizeof(ip_hdr))) {
    std::cerr << "ERROR: IP packet does not mean minimum length requirements" << std::endl;
    return;
  }

  // Verify that checksum of IP packet is valid
  uint16_t checksum = ip_header->ip_sum;
  ip_header->ip_sum = 0;

  if (checksum != cksum(ip_header, sizeof(ip_hdr))) {
    std::cerr << "ERROR: IP packet has an invalid checksum" << std::endl;
    return;
  }
  
  // For each hop, decrement TTL by 1
  ip_header->ip_ttl = ip_header->ip_ttl - 1;

  // Check that TTL > 0
  if (ip_header->ip_ttl <= 0) {
    std::cerr << "ERROR: IP packet has exceeded Time To Live" << std::endl;
    return;
  }

  // For each hop, recompute checksum 
  ip_header->ip_sum = 0;
  ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr));

  // If packet was destined to router, discard packet
  // Check all the interfaces
  for (std::set<Interface>::const_iterator ifaceIt = m_ifaces.begin(); ifaceIt != m_ifaces.end(); ++ifaceIt) {
    if (ifaceIt->ip == ip_header->ip_dst) {
      return;
    }
  }

  // Otherwise packets should be forwarded to next hop
  // Use Longest-Prefix Match Algorithm with lookup() to find next hop address
  RoutingTableEntry routing_entry = m_routingTable.lookup(ip_header->ip_dst);

  // Get interface
  const Interface* ip_iface = findIfaceByName(routing_entry.ifName);

  // Check ARP cache to see if MAC address has been mapped to destination IP
  std::shared_ptr<ArpEntry> arp_entry = m_arp.lookup(ip_header->ip_dst);

  if (arp_entry != nullptr) {
    // Found valid mapping, can forward packet
    // Create ethernet header
    ethernet_hdr* ip_e_hdr = (ethernet_hdr *)ip_packet.data();

    // Set addresses and type for ethernet header
    memcpy(ip_e_hdr->ether_shost, ip_iface->addr.data(), ETHER_ADDR_LEN);
    memcpy(ip_e_hdr->ether_dhost, arp_entry->mac.data(), ETHER_ADDR_LEN);
    ip_e_hdr->ether_type = htons(ethertype_ip);

    sendPacket(ip_packet, ip_iface->name);
  } else {
    // Address not in ARP cache
    // Router queues received packet and sends ARP request
    m_arp.queueRequest(ip_header->ip_dst, ip_packet, ip_iface->name);

    // Create and send an ARP request packet 
    // Largely based on creating ARP request in arp-cache.cpp
    // Get required length of combined ethernet + arp headers
    uint8_t req_len = sizeof(ethernet_hdr) + sizeof(arp_hdr);

    // Create buffer for packet
    Buffer packetBuffer(req_len);
    uint8_t* req_pack = (uint8_t *)packetBuffer.data();

    // Get pointers to ethernet and arp headers
    ethernet_hdr* request_e_hdr = (ethernet_hdr *)req_pack;
    arp_hdr* request_a_hdr = (arp_hdr *)(req_pack + sizeof(ethernet_hdr));

    // Create ethernet header
    // Set the destination and source addresses from the ARP header and interface
    // The ARP response source is the interface's address
    // The ARP response destination is the ARP request sender's hardware address
    memcpy(request_e_hdr->ether_shost, ip_iface->addr.data(), ETHER_ADDR_LEN);
    memcpy(request_e_hdr->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
    request_e_hdr->ether_type = htons(ethertype_arp);

    // Create ARP header
    request_a_hdr->arp_hrd = htons(arp_hrd_ethernet);
    request_a_hdr->arp_pro = htons(ethertype_ip);
    request_a_hdr->arp_hln = ETHER_ADDR_LEN;
    request_a_hdr->arp_pln = 4;
    request_a_hdr->arp_op = htons(arp_op_request);

    memcpy(request_a_hdr->arp_sha, ip_iface->addr.data(), ETHER_ADDR_LEN);
    request_a_hdr->arp_sip = ip_iface->ip;
    memcpy(request_a_hdr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
    request_a_hdr->arp_tip = ip_header->ip_dst;

    sendPacket(packetBuffer, ip_iface->name);
  }
}

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {