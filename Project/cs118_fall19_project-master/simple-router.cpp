/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/***
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
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  // FILL THIS IN

  //mac address stuff
  std::string iface_address = macToString(iface->addr);
  std::string packet_address = macToString(packet);

  std::string broadcast_address = "FF:FF:FF:FF:FF:FF";
  std:: string lower_broadcast_address = "ff:ff:ff:ff:ff:ff";

  //ignoring condition: if packet not destined for the router
  if((broadcast_address != packet_address) &&
    (lower_broadcast_address != packet_address) &&
    (iface_address != packet_address))
    {
      std::cerr << "Received packet, but address does not correspond to interface address or broadcast address. Packet ignored." << std::endl;
      return;
    }

    uint16_t ether_type = ethertype(packet.data());

    if(ether_type == ethertype_arp)
    {
      std::cerr << "Packet is type ARP." << std::endl;
      const arp_hdr *arp_header = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
      uint32_t arp_target_ip = arp_header->arp_tip;

      //find the arp op code and handle it (if it is a request or reply)
      uint16_t arp_operation = ntohs(arp_header->arp_op);
      if(arp_operation == arp_op_request)
      {
        std::cerr << "Handle ARP request" << std::endl;

        //if target and interface IP do not match, drop req
        if(arp_target_ip != iface->ip)
        {
          std::cerr << "The target IP address does not match the interface IP address. Ignoring request." << std::endl;
          return;
        }

        //otherwise respond to arp req
        //check arp cache for the corresponding MAC address
        //if found, proceed with handling the IP packet
        //otherwise, router should queue the received packet and
        //start sending  ARP request to discover the IP-MAC mapping
        std::shared_ptr<ArpEntry> entry = m_arp.lookup(arp_target_ip);
        if(entry != NULL)
        {
          std::cerr << "The ARP packet is sent" << std::endl;
          sendPacket(packet, macToString(entry->mac));
        }
        //if not in cache, broadcast
        else
        {
          std::cerr << "ARP Requesting for IP-MAC mapping" << std::endl;
          std::shared_ptr<ArpRequest> request = queueRequest(arp_target_ip, packet, inIface);

        }

      }
      else if(arp_operation == arp_op_reply)
      {

      }

    }
    else if(ether_type == ethertype_ip)
    {
      std::cerr << "Packet is type IP." << std::endl;
    }
    else
    {
      std::cerr << "Packet is neither an ARP or IP type. Packet ignored" << std::endl;
      return;
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


} // namespace simple_router {
