#pragma once

#include <memory>
#include <sstream>
#include <string>

namespace levik {

inline DWORD JsonInterfaceName(const wchar_t* name, std::string& json) {
  const int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, nullptr, 0, nullptr, nullptr);
  if (size == 0) return GetLastError();
  std::string utf8(static_cast<size_t>(size), '\0');
  if (WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, name, -1, utf8.data(), size, nullptr, nullptr) == 0)
    return GetLastError();
  utf8.pop_back();
  json = "\"";
  constexpr char hex[] = "0123456789abcdef";
  for (const unsigned char byte : utf8) {
    if (byte == '"' || byte == '\\') { json += '\\'; json += static_cast<char>(byte); }
    else if (byte < 0x20) { json += "\\u00"; json += hex[byte >> 4]; json += hex[byte & 0xf]; }
    else json += static_cast<char>(byte);
  }
  json += '"';
  return ERROR_SUCCESS;
}

// IP Helper reads the kernel's routes and interface flags without PowerShell,
// CIM or WMI. A broken WMI repository must not prevent a working NIC from being
// used. Emit the same contract as the legacy collectors, including virtual NICs
// for diagnostics; the caller still excludes them from outbound selection.
inline DWORD ReadOutboundInterfaces(std::string& json) {
  PMIB_IPFORWARD_TABLE2 raw = nullptr;
  const DWORD result = GetIpForwardTable2(AF_UNSPEC, &raw);
  const std::unique_ptr<MIB_IPFORWARD_TABLE2, decltype(&FreeMibTable)> table(raw, &FreeMibTable);
  if (result == ERROR_NOT_FOUND) { json = "[]"; return ERROR_SUCCESS; }
  if (result != ERROR_SUCCESS) return result;
  if (!table) return ERROR_INVALID_DATA;

  std::ostringstream output;
  output << '[';
  bool first = true;
  for (ULONG i = 0; i < table->NumEntries; ++i) {
    const MIB_IPFORWARD_ROW2& route = table->Table[i];
    const ADDRESS_FAMILY family = route.DestinationPrefix.Prefix.si_family;
    if (route.DestinationPrefix.PrefixLength != 0 || (family != AF_INET && family != AF_INET6)) continue;
    MIB_IF_ROW2 adapter{};
    adapter.InterfaceLuid = route.InterfaceLuid;
    DWORD status = GetIfEntry2(&adapter);
    // An adapter may disappear during a Wi-Fi/network transition.
    if (status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND) continue;
    if (status != ERROR_SUCCESS) return status;
    MIB_IPINTERFACE_ROW ip{};
    InitializeIpInterfaceEntry(&ip);
    ip.Family = family;
    ip.InterfaceLuid = route.InterfaceLuid;
    status = GetIpInterfaceEntry(&ip);
    if (status == ERROR_NOT_FOUND || status == ERROR_FILE_NOT_FOUND) continue;
    if (status != ERROR_SUCCESS) return status;
    std::string name;
    status = JsonInterfaceName(adapter.Alias, name);
    if (status != ERROR_SUCCESS) return status;
    if (!first) output << ',';
    first = false;
    output << "{\"name\":" << name
           << ",\"physical\":" << (adapter.InterfaceAndOperStatusFlags.HardwareInterface ? "true" : "false")
           << ",\"up\":" << (adapter.OperStatus == IfOperStatusUp && ip.Connected ? "true" : "false")
           << ",\"index\":" << adapter.InterfaceIndex
           << ",\"prefix\":\"" << (family == AF_INET ? "0.0.0.0/0" : "::/0") << '"'
           << ",\"routeMetric\":" << route.Metric
           << ",\"interfaceMetric\":" << ip.Metric << '}';
  }
  output << ']';
  json = output.str();
  return ERROR_SUCCESS;
}

inline DWORD OutboundInterfaceSelfTest() {
  std::string name;
  DWORD result = JsonInterfaceName(L"\u0421\u0435\u0442\u044c \"USB\" \\\n", name);
  if (result != ERROR_SUCCESS) return result;
  if (name != u8"\"\u0421\u0435\u0442\u044c \\\"USB\\\" \\\\\\u000a\"") return ERROR_INVALID_DATA;
  std::string routes;
  return ReadOutboundInterfaces(routes);
}

}  // namespace levik
