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
  print_hdrs(packet);
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
  std::string lower_broadcast_address = "ff:ff:ff:ff:ff:ff";

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
      const arp_hdr* arp_header = reinterpret_cast<const arp_hdr*>(packet.data() + sizeof(ethernet_hdr));
      uint32_t arp_target_ip = arp_header->arp_tip;

      //if target and interface IP do not match, drop req
      if(arp_target_ip != iface->ip)
      {
        std::cerr << "The target IP address does not match the interface IP address. Ignoring request." << std::endl;
        return;
      }

      //find the arp op code and handle it (if it is a request or reply)
      uint16_t arp_operation = ntohs(arp_header->arp_op);
      if(arp_operation == arp_op_request)
      {
        std::cerr << "Handle ARP request" << std::endl;

        //otherwise respond to arp req
        //create ethernet and arp headers, then populate buffer with them
        ethernet_hdr reply_eth_hdr;
        arp_hdr reply_arp_hdr;

        //Populating the reply ethernet header
        memcpy(reply_eth_hdr.ether_dhost, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        memcpy(reply_eth_hdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        reply_eth_hdr.ether_type = htons(ethertype_arp);

        //Populating the reply arp header
        reply_arp_hdr.arp_hrd = htons(arp_hrd_ethernet);
        reply_arp_hdr.arp_pro = htons(ethertype_ip);
        reply_arp_hdr.arp_hln = ETHER_ADDR_LEN;
        reply_arp_hdr.arp_pln = 4;
        reply_arp_hdr.arp_op = htons(arp_op_reply);
        memcpy(reply_arp_hdr.arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
        reply_arp_hdr.arp_sip = iface->ip;
        memcpy(reply_arp_hdr.arp_tha, &(arp_header->arp_sha), ETHER_ADDR_LEN);
        reply_arp_hdr.arp_tip = arp_header->arp_sip;

        //populate buffer
        Buffer packet_buff(sizeof(ethernet_hdr) + sizeof(arp_hdr));
        memcpy(packet_buff.data(), &reply_eth_hdr, sizeof(ethernet_hdr));
        memcpy(packet_buff.data() + sizeof(ethernet_hdr), &reply_arp_hdr, sizeof(arp_hdr));
        //send reply
        sendPacket(packet_buff, iface->name);
      }
      else if(arp_operation == arp_op_reply)
      {
        std::cerr << "Handle ARP reply"<< std::endl;
        // Get the IP-MAC mapping to store into the ARP cache
        Buffer arp_mac_addr(ETHER_ADDR_LEN);
        memcpy(arp_mac_addr.data(), arp_header->arp_sha, ETHER_ADDR_LEN);

        if(m_arp.lookup(arp_header->arp_sip) == NULL)
        {
          std::shared_ptr<ArpRequest> arp_req = m_arp.insertArpEntry(arp_mac_addr, arp_header->arp_sip);
          //remove pending requests
          m_arp.removeRequest(arp_req);
          //check if there are packets in the queue that correspond to the reply. Send them if they correspond
          if(arp_req != NULL)
          {
            for(std::list<PendingPacket>::iterator packet_iter = arp_req->packets.begin(); packet_iter != arp_req->packets.end(); packet_iter++)
            {
              ethernet_hdr* ether_hdr = (ethernet_hdr*) packet_iter->packet.data();

              memcpy(ether_hdr->ether_dhost, arp_header->arp_sha, ETHER_ADDR_LEN);
              memcpy(ether_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);

              sendPacket(packet_iter->packet, packet_iter->iface);
            }
          }
        }
      }
      else
      {
        std::cerr << "The ARP operation is invalid. It is neither request or reply" << std::endl;
      }

    }
    else if(ether_type == ethertype_ip)
    {
      std::cerr << "Packet is type IP" << std::endl;

      Buffer ip_packet(packet);
      ip_hdr* ip_header = (ip_hdr*) (ip_packet.data() + sizeof(ethernet_hdr));

      //check for min packet size requirement
      if(packet.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr))
      {
        std::cerr << "IP packet invalid: does not meet the minimum IP packet length requirement. Dropping packet." << std::endl;
        return;
      }

      std::cerr << "Checking IP header checksum" << std::endl;
      //checksum check
      uint16_t checksum = ip_header->ip_sum;
      ip_header->ip_sum = 0;

      if(checksum != cksum(ip_header, sizeof(ip_hdr)))
      {
        std::cerr << "IP packet invalid: checksum is invalid." << std::endl;
        return;
      }

      //see if destined for router
      if(findIfaceByIp(ip_header->ip_dst) != nullptr)
      {
        std::cerr << "Destined for router." << std::endl;
        //if it is icmp payload
        if(ip_header->ip_p == ip_protocol_icmp)
        {
          std::cerr << "Handling ICMP packet." << std::endl;
          //Properly dispatch ICMP payload

          //get pointer to icmp header
          icmp_hdr* icmp_header = (icmp_hdr*) (packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

          std::cerr << "Checking ICMP checksum" << std::endl;
          //check the checksum, if incorrect drop it
          uint16_t icmp_checksum = icmp_header->icmp_sum;
          icmp_header->icmp_sum = 0;

          if(icmp_checksum != cksum(icmp_header, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr)))
          {
            std::cerr << "ICMP payload invalid: checksum is invalid." << std::endl;
            return;
          }

          //reply correctly to icmp types
          if(icmp_header->icmp_type == 0)
          {
            std::cerr << "ICMP packet is an echo reply" << std::endl;
            return;
          }
          if(icmp_header->icmp_type == 8)
          {
            std::cerr << "ICMP packet is an echo message" << std::endl;

            //create ICMP reply
            Buffer reply_packet_buff(packet.size());
            ethernet_hdr reply_eth_hdr;
            ip_hdr reply_ip_hdr;
            icmp_hdr reply_icmp_hdr;
            //
            // //populating the ethernet header
            ethernet_hdr* old_hdr = (ethernet_hdr*) packet.data();
            memcpy(reply_eth_hdr.ether_dhost, old_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(reply_eth_hdr.ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
            reply_eth_hdr.ether_type = htons(ethertype_ip);
            memcpy(reply_packet_buff.data(), &reply_eth_hdr, sizeof(ethernet_hdr));
            // print_hdrs(reply_packet_buff);
            // //populating the IP header
            memcpy(&reply_ip_hdr, ip_header, sizeof(ip_hdr));
            reply_ip_hdr.ip_sum = 0;
            reply_ip_hdr.ip_src = ip_header->ip_dst;
            reply_ip_hdr.ip_dst = ip_header->ip_src;
            reply_ip_hdr.ip_ttl = 64;
            //calculate and update the ip checksum
            reply_ip_hdr.ip_sum = cksum(&reply_ip_hdr, sizeof(ip_hdr));
            memcpy(reply_packet_buff.data() + sizeof(ethernet_hdr), &reply_ip_hdr, sizeof(ip_hdr));
            // print_hdrs(reply_packet_buff);
            //
            // //populating the icmp header
            Buffer icmp_buff(packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));
            reply_icmp_hdr.icmp_type = 0;
            reply_icmp_hdr.icmp_code = 0;
            reply_icmp_hdr.icmp_sum = 0;
            // //copy in the header and payload to the buffer
            memcpy(icmp_buff.data(), &reply_icmp_hdr, sizeof(icmp_hdr));
            memcpy(icmp_buff.data() + sizeof(icmp_hdr), packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr), packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr) - sizeof(icmp_hdr));
            reply_icmp_hdr.icmp_sum = cksum(icmp_buff.data(), packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));
            // //load in the icmp header again, but now with updated cksum
            memcpy(icmp_buff.data(), &reply_icmp_hdr, sizeof(icmp_hdr));
            memcpy(reply_packet_buff.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr), icmp_buff.data(), icmp_buff.size());

            print_hdrs(reply_packet_buff);
            sendPacket(reply_packet_buff, iface->name);
            std::cerr << "Sent ICMP reply" << std::endl;
          }
        }
      }
      /*
      //check all interfaces to see if destined for router
      std::cerr << "Checking all interfaces to see if destined for router" << std::endl;
      for(std::set<Interface>::iterator iface_iter = m_ifaces.begin(); iface_iter != m_ifaces.end(); iface_iter++)
      {
        if(iface_iter->ip == ip_header->ip_dst)
        {
          //if it is icmp payload
          if(ip_header->ip_p == ip_protocol_icmp)
          {
            //Properly dispatch ICMP payload

            //get pointer to icmp header
            icmp_hdr* icmp_header = (icmp_hdr*) (packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));

            std::cerr << "Checking ICMP checksum" << std::endl;
            //check the checksum, if incorrect drop it
            uint16_t icmp_checksum = icmp_header->icmp_sum;
            icmp_header->icmp_sum = 0;

            if(icmp_checksum != cksum(icmp_header, packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr)))
            {
              std::cerr << "ICMP payload invalid: checksum is invalid." << std::endl;
              return;
            }

            //reply correctly to icmp types
            if(icmp_header->icmp_type == 0)
            {
              std::cerr << "ICMP packet is an echo reply" << std::endl;
              return;
            }
            if(icmp_header->icmp_type == 8)
            {
              std::cerr << "ICMP packet is an echo message" << std::endl;

              //create ICMP reply
              Buffer packet_buff(packet.size());
              ethernet_hdr reply_eth_hdr;
              ip_hdr reply_ip_hdr;
              icmp_hdr reply_icmp_hdr;

              //populating the ethernet header
              memcpy(reply_eth_hdr.ether_dhost, &(ip_header->ip_src), ETHER_ADDR_LEN);
              memcpy(reply_eth_hdr.ether_shost, (iface_iter->addr.data()), ETHER_ADDR_LEN);
              reply_eth_hdr.ether_type = htons(ethertype_arp);
              memcpy(packet_buff.data(), &reply_eth_hdr, sizeof(ethernet_hdr));

              //populating the IP header
              memcpy(&reply_ip_hdr, ip_header, sizeof(ip_hdr));
              reply_ip_hdr.ip_sum = 0;
              reply_ip_hdr.ip_src = iface_iter->ip;
              reply_ip_hdr.ip_dst = ip_header->ip_src;
              //calculate and update the ip checksum
              reply_ip_hdr.ip_sum = cksum(&reply_ip_hdr, sizeof(ip_hdr));
              reply_ip_hdr.ip_ttl = 64;
              memcpy(packet_buff.data() + sizeof(ethernet_hdr), &reply_ip_hdr, sizeof(ip_hdr));

              //populating the icmp header
              Buffer icmp_buff(packet.size() - sizeof(ethernet_hdr) - sizeof(ip_hdr));
              reply_icmp_hdr.icmp_type = 0;
              reply_icmp_hdr.icmp_code = 0;
              reply_icmp_hdr.icmp_sum = 0;
              //copy in the header and payload to the buffer
              memcpy(icmp_buff.data(), &reply_icmp_hdr, sizeof(icmp_hdr));
              memcpy(icmp_buff.data() + sizeof(icmp_hdr), packet.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr) + sizeof(icmp_hdr), packet.size() + sizeof(ethernet_hdr) - sizeof(ip_hdr) - sizeof(icmp_hdr));
              reply_icmp_hdr.icmp_sum = cksum(icmp_buff.data(), icmp_buff.size());
              //load in the icmp header again, but now with updated cksum
              memcpy(icmp_buff.data(), &reply_icmp_hdr, sizeof(icmp_hdr));

              sendPacket(packet_buff, iface_iter->name);
              std::cerr << "Sent ICMP reply" << std::endl;
            }
          }
        }
      }*/
      else
      {
        //check if TTL is 0
        if(ip_header->ip_ttl == 0)
        {
          std::cerr << "Time to Live is 0. Dropping" << std::endl;
          return;
        }

        //check if TTL is greater than 0
        std::cerr << "Decrementing TTL" << std::endl;
        ip_header->ip_ttl--;
        if(ip_header->ip_ttl <= 0)
        {
          std::cerr << "Time to Live is 0. Dropping" << std::endl;
          return;
        }

        //recompute checksum for the hop
        ip_header->ip_sum = cksum(ip_header, sizeof(ip_hdr));

        std::cerr << "Checking routing table" << std::endl;
        //Use longest matching prefix algorithm to forward packets to next hop
        RoutingTableEntry next_hop_lookup = m_routingTable.lookup(ip_header->ip_dst);
        const Interface* next_hop_iface = findIfaceByName(next_hop_lookup.ifName);
        std::cerr << "Checked the routing table" << std::endl;

        //check arp cache for the mac address of the dst IP
        std::shared_ptr<ArpEntry> arp_lookup = m_arp.lookup(ip_header->ip_dst);
        if(arp_lookup != NULL)
        {
          //create and populate eth hdr, then send it
          ethernet_hdr* ip_eth_hdr = (ethernet_hdr*) (ip_packet.data());
          memcpy(ip_eth_hdr->ether_dhost, arp_lookup->mac.data(), ETHER_ADDR_LEN);
          memcpy(ip_eth_hdr->ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN);
          ip_eth_hdr->ether_type = htons(ethertype_ip);

          sendPacket(ip_packet, next_hop_iface->name);
          std::cerr << "Forwarded the IP Packet" << std::endl;
        }

        //if not in cache, do an arp req
        else
        {
          m_arp.queueRequest(ip_header->ip_dst, ip_packet, next_hop_iface->name);
          std::cerr << "Queueing request" << std::endl;
          /*
          ethernet_hdr req_eth_hdr;
          arp_hdr req_arp_hdr;

          //Populating the req ethernet header
          memcpy(req_eth_hdr.ether_shost, next_hop_iface->addr.data(), ETHER_ADDR_LEN);
          memset(req_eth_hdr.ether_dhost, 0xFF, ETHER_ADDR_LEN);
          req_eth_hdr.ether_type = htons(ethertype_arp);

          //Populating the req arp header
          req_arp_hdr.arp_hrd = htons(arp_hrd_ethernet);
          req_arp_hdr.arp_pro = htons(ethertype_ip);
          req_arp_hdr.arp_hln = ETHER_ADDR_LEN;
          req_arp_hdr.arp_pln = 4;
          req_arp_hdr.arp_op = htons(arp_op_request);
          memcpy(req_arp_hdr.arp_sha, next_hop_iface->addr.data(), ETHER_ADDR_LEN);
          req_arp_hdr.arp_sip = next_hop_iface->ip;
          memset(req_arp_hdr.arp_tha, 0xFF, ETHER_ADDR_LEN);
          req_arp_hdr.arp_tip = ip_header->ip_dst;

          //populate buffer
          Buffer packet_buff(sizeof(ethernet_hdr) + sizeof(arp_hdr));
          memcpy(packet_buff.data(), &req_eth_hdr, sizeof(ethernet_hdr));
          memcpy(packet_buff.data() + sizeof(ethernet_hdr), &req_arp_hdr, sizeof(arp_hdr));
          //send reply
          sendPacket(packet_buff, next_hop_iface->name);
          std::cerr << "Sent an ARP Request" << std::endl;*/
        }
      }
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
