#pragma once

#include <icmpapi.h>
#include <algorithm>

namespace levik {

inline bool PublicGameAddress(const IN_ADDR& address) {
  const ULONG ip = ntohl(address.S_un.S_addr);
  const ULONG a = ip >> 24;
  const ULONG b = (ip >> 16) & 255;
  if (a == 0 || a == 10 || a == 127 || a >= 224 || (a == 100 && b >= 64 && b <= 127) ||
      (a == 169 && b == 254) || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
      (a == 192 && (b == 0 || (b == 88 && ((ip >> 8) & 255) == 99))) || (a == 198 && (b == 18 || b == 19)) ||
      (a == 198 && b == 51 && ((ip >> 8) & 255) == 100) ||
      (a == 203 && b == 0 && ((ip >> 8) & 255) == 113)) return false;
  return true;
}

// Do not trust a renderer-supplied interface name or a virtual adapter alias.
inline DWORD ValidatePhysicalSource(const IN_ADDR& source) {
  ULONG size = 16 * 1024;
  std::vector<BYTE> storage(size);
  auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
  ULONG result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST,
                                      nullptr, adapters, &size);
  if (result == ERROR_BUFFER_OVERFLOW && size <= 1024 * 1024) {
    storage.resize(size);
    adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(storage.data());
    result = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_MULTICAST,
                                  nullptr, adapters, &size);
  }
  if (result != ERROR_SUCCESS) return result;
  for (auto* adapter = adapters; adapter != nullptr; adapter = adapter->Next) {
    MIB_IF_ROW2 row{};
    row.InterfaceLuid = adapter->Luid;
    if (GetIfEntry2(&row) != ERROR_SUCCESS || !row.InterfaceAndOperStatusFlags.HardwareInterface ||
        row.OperStatus != IfOperStatusUp) continue;
    for (auto* entry = adapter->FirstUnicastAddress; entry != nullptr; entry = entry->Next) {
      if (entry->Address.lpSockaddr != nullptr && entry->Address.lpSockaddr->sa_family == AF_INET &&
          reinterpret_cast<sockaddr_in*>(entry->Address.lpSockaddr)->sin_addr.S_un.S_addr == source.S_un.S_addr)
        return ERROR_SUCCESS;
    }
  }
  return ERROR_NOT_FOUND;
}

inline DWORD DirectGameProbe(const wchar_t* sourceText, const wchar_t* targetText, BYTE ttl, std::string& json) {
  IN_ADDR source{}, target{};
  if (InetPtonW(AF_INET, sourceText, &source) != 1 || InetPtonW(AF_INET, targetText, &target) != 1 ||
      !PublicGameAddress(target) || ttl == 0 || ttl > 30) return ERROR_INVALID_PARAMETER;
  const DWORD physical = ValidatePhysicalSource(source);
  if (physical != ERROR_SUCCESS) return physical;
  HANDLE handle = IcmpCreateFile();
  if (handle == INVALID_HANDLE_VALUE) return GetLastError();
  IP_OPTION_INFORMATION options{};
  options.Ttl = ttl;
  alignas(ICMP_ECHO_REPLY) std::array<BYTE, sizeof(ICMP_ECHO_REPLY) + 64> reply{};
  std::array<char, 16> payload{};
  const DWORD count = IcmpSendEcho2Ex(handle, nullptr, nullptr, nullptr, source.S_un.S_addr,
      target.S_un.S_addr, payload.data(), static_cast<WORD>(payload.size()), &options,
      reply.data(), static_cast<DWORD>(reply.size()), 700);
  const DWORD failure = count == 0 ? GetLastError() : ERROR_SUCCESS;
  IcmpCloseHandle(handle);
  if (count == 0 && failure != IP_REQ_TIMED_OUT && failure != IP_TTL_EXPIRED_TRANSIT && failure != IP_GENERAL_FAILURE)
    return failure;
  const auto* response = reinterpret_cast<const ICMP_ECHO_REPLY*>(reply.data());
  const bool exact = count > 0 && response->Status == IP_SUCCESS && response->Address == target.S_un.S_addr;
  const bool hop = count > 0 && response->Status == IP_TTL_EXPIRED_TRANSIT;
  json = "{\"latencyMs\":" + (exact || hop ? std::to_string(response->RoundTripTime) : "null") +
         ",\"method\":\"" + (hop ? "ttl-hop" : "icmp") + "\",\"approximate\":" + (hop ? "true" : "false") + "}";
  return ERROR_SUCCESS;
}

inline DWORD GameProbeSelfTest() {
  IN_ADDR address{};
  for (const wchar_t* value : {L"127.0.0.1", L"10.1.1.1", L"100.64.0.1", L"192.0.2.1", L"198.51.100.1", L"203.0.113.1", L"239.1.1.1"}) {
    if (InetPtonW(AF_INET, value, &address) != 1 || PublicGameAddress(address)) return ERROR_INVALID_DATA;
  }
  if (InetPtonW(AF_INET, L"1.1.1.1", &address) != 1 || !PublicGameAddress(address)) return ERROR_INVALID_DATA;
  return ERROR_SUCCESS;
}

}  // namespace levik
