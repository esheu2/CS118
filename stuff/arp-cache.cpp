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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

// You should not need to touch the rest of this code.
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  auto now = steady_clock::now();
  std::list<std::shared_ptr<ArpRequest>>::iterator it;
  for (std::list<std::shared_ptr<ArpRequest>>::iterator it = m_arpRequests.begin();
       it != m_arpRequests.end(); ) {
    if((*it)->nTimesSent >= MAX_SENT_TIME) {
      std::list<PendingPacket>::const_iterator packetIt;
      std::cout << (*it)->packets.size() << std::endl;
      for (std::list<PendingPacket>::const_iterator packetIt = (*it)->packets.begin(); packetIt != (*it)->packets.end(); ++packetIt) {
        ethernet_hdr * eth_hdr = (ethernet_hdr *)(packetIt->packet.data());
        uint8_t host_unreachable = 1;
        const Interface * out_iface = m_router.findIfaceByName(packetIt->iface);
        const Interface * in_iface = m_router.findIfaceByMac(Buffer(eth_hdr->ether_dhost, eth_hdr->ether_dhost + ETHER_ADDR_LEN));
      }
      it = m_arpRequests.erase(it);
    }
    else {
      // Send arp request
      // Create a request packet
      uint8_t req_len = sizeof(ethernet_hdr) + sizeof(arp_hdr);
      Buffer packetBuffer(req_len);
      uint8_t* req_pack = (uint8_t *) packetBuffer.data();
      ethernet_hdr* eth_hdr = (ethernet_hdr *)req_pack;
      arp_hdr* arpHdr = (arp_hdr *)(req_pack + sizeof(ethernet_hdr));
      /* Ethernet header*/
      std::string iface_name = (*it)->packets.front().iface;
      const Interface *iface = m_router.findIfaceByName(iface_name);
      memcpy(eth_hdr->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(eth_hdr->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
      eth_hdr->ether_type = htons(ethertype_arp);
      /* ARP header*/
      arpHdr->arp_hrd = htons(arp_hrd_ethernet);
      arpHdr->arp_pro = htons(ethertype_ip);
      arpHdr->arp_hln = ETHER_ADDR_LEN;
      arpHdr->arp_pln = 4;
      arpHdr->arp_op = htons(arp_op_request);
      memcpy(arpHdr->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      arpHdr->arp_sip = iface->ip;
      memcpy(arpHdr->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);
      arpHdr->arp_tip = (*it)->ip;
      /* Send request packet*/
      std::cerr << iface_name << std::endl;
      m_router.sendPacket(packetBuffer, iface_name);
      /* Update informaton about this request */
      (*it)->timeSent = now;
      (*it)->nTimesSent ++;
      ++it;
    }
  }

  std::list<std::shared_ptr<ArpEntry>>::iterator entryIt;
  for (std::list<std::shared_ptr<ArpEntry>>::iterator entryIt = m_cacheEntries.begin();
       entryIt != m_cacheEntries.end(); ) {
    if(!(*entryIt)->isValid) {
      entryIt = m_cacheEntries.erase(entryIt);
    } else {
      entryIt ++;
    }
  }
}

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router