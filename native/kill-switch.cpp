#define _WIN32_WINNT 0x0A00
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <fwpmu.h>
#include <iphlpapi.h>
#include <userenv.h>
#include <winternl.h>

#include <array>
#include <iostream>
#include <string>
#include <vector>

#pragma comment(lib, "fwpuclnt.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "userenv.lib")

namespace {

constexpr GUID kProviderKey = {0x76a6ffea, 0xda31, 0x4ba6, {0x8e, 0x8a, 0x26, 0xd8, 0x15, 0x92, 0x77, 0xc4}};
constexpr GUID kSubLayerKey = {0xfe0d8f47, 0x83d6, 0x4f9e, {0xb7, 0x2d, 0x64, 0x66, 0x62, 0x1a, 0xd0, 0xb1}};

constexpr GUID kAppV4Key = {0x05b55772, 0x67e2, 0x4643, {0x94, 0x43, 0x84, 0xce, 0xfd, 0x1b, 0xc8, 0xf1}};
constexpr GUID kAppV6Key = {0xac1528df, 0xd4cb, 0x4701, {0x99, 0x75, 0xbc, 0x56, 0xc4, 0x08, 0x0d, 0xd1}};
constexpr GUID kXrayV4Key = {0xa66b42da, 0xaa63, 0x41a1, {0xb9, 0x8d, 0x84, 0x45, 0xd8, 0x34, 0x43, 0x6f}};
constexpr GUID kXrayV6Key = {0x99665898, 0x65cb, 0x4a1c, {0xa7, 0x82, 0xe6, 0x7b, 0x6c, 0xdf, 0x2a, 0xf0}};
constexpr GUID kTunnelV4Key = {0x3936c136, 0xe200, 0x4ce6, {0xb3, 0xe1, 0xe8, 0x3a, 0x8b, 0x45, 0x15, 0xf7}};
constexpr GUID kTunnelV6Key = {0xb13e795b, 0xcb1b, 0x4ed8, {0x9e, 0x32, 0xc2, 0x24, 0xe1, 0x4a, 0x48, 0xf5}};
constexpr GUID kBlockV4Key = {0x6c95fc3e, 0xc5ea, 0x40d5, {0x9c, 0x6e, 0x6d, 0x73, 0xe8, 0x0a, 0xce, 0x13}};
constexpr GUID kBlockV6Key = {0xe7528168, 0x7b6c, 0x43da, {0x99, 0xe2, 0x18, 0xd0, 0x35, 0x0e, 0x08, 0xe9}};

constexpr GUID kTestProviderKey = {0x60c17e46, 0xf4a7, 0x4da7, {0xaa, 0xf4, 0xe4, 0x1c, 0xdc, 0x21, 0x65, 0x12}};
constexpr GUID kTestSubLayerKey = {0xba0c67f7, 0x4cb1, 0x48d9, {0xa9, 0x7d, 0x24, 0x11, 0x63, 0x2d, 0x2a, 0x7b}};
constexpr GUID kTestFilterKey = {0x56fc4f68, 0x218f, 0x4753, {0x9c, 0xf8, 0xf8, 0x06, 0x24, 0x08, 0x51, 0xb2}};

constexpr UINT64 kPermitWeight = 0xf000000000000000ULL;
constexpr UINT64 kBlockWeight = 1;

class EngineHandle {
 public:
  ~EngineHandle() {
    if (value_ != nullptr) FwpmEngineClose0(value_);
  }

  HANDLE* receive() { return &value_; }
  HANDLE get() const { return value_; }

 private:
  HANDLE value_ = nullptr;
};

class WinHandle {
 public:
  ~WinHandle() {
    if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
  }

  HANDLE get() const { return value_; }
  void reset(HANDLE value) {
    if (value_ != INVALID_HANDLE_VALUE) CloseHandle(value_);
    value_ = value;
  }

 private:
  HANDLE value_ = INVALID_HANDLE_VALUE;
};

std::wstring ErrorMessage(DWORD code) {
  wchar_t* raw = nullptr;
  const DWORD length = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr, code, 0, reinterpret_cast<wchar_t*>(&raw), 0, nullptr);
  std::wstring message = length != 0 && raw != nullptr ? std::wstring(raw, length) : L"Windows error " + std::to_wstring(code);
  if (raw != nullptr) LocalFree(raw);
  while (!message.empty() && (message.back() == L'\r' || message.back() == L'\n')) message.pop_back();
  return message;
}

DWORD OpenEngine(EngineHandle& engine) {
  FWPM_SESSION0 session{};
  session.displayData.name = const_cast<wchar_t*>(L"Levik VPN Kill Switch");
  return FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, engine.receive());
}

DWORD IgnoreMissingFilter(DWORD result) {
  return result == FWP_E_FILTER_NOT_FOUND ? ERROR_SUCCESS : result;
}

DWORD IgnoreMissingSubLayer(DWORD result) {
  return result == FWP_E_SUBLAYER_NOT_FOUND ? ERROR_SUCCESS : result;
}

DWORD IgnoreMissingProvider(DWORD result) {
  return result == FWP_E_PROVIDER_NOT_FOUND ? ERROR_SUCCESS : result;
}

DWORD EnsureProvider(HANDLE engine, const GUID& providerKey, bool persistent) {
  FWPM_PROVIDER0 provider{};
  provider.providerKey = providerKey;
  provider.displayData.name = const_cast<wchar_t*>(L"Levik VPN");
  provider.displayData.description = const_cast<wchar_t*>(L"Levik VPN network protection");
  provider.flags = persistent ? FWPM_PROVIDER_FLAG_PERSISTENT : 0;
  const DWORD result = FwpmProviderAdd0(engine, &provider, nullptr);
  return result == FWP_E_ALREADY_EXISTS ? ERROR_SUCCESS : result;
}

DWORD EnsureSubLayer(HANDLE engine, const GUID& providerKey, const GUID& subLayerKey, bool persistent) {
  FWPM_SUBLAYER0 subLayer{};
  subLayer.subLayerKey = subLayerKey;
  subLayer.displayData.name = const_cast<wchar_t*>(L"Levik VPN Kill Switch");
  subLayer.displayData.description = const_cast<wchar_t*>(L"Fail-closed outbound network policy");
  subLayer.providerKey = const_cast<GUID*>(&providerKey);
  subLayer.flags = persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0;
  subLayer.weight = 0xffff;
  const DWORD result = FwpmSubLayerAdd0(engine, &subLayer, nullptr);
  return result == FWP_E_ALREADY_EXISTS ? ERROR_SUCCESS : result;
}

DWORD AddFilter(
    HANDLE engine,
    const GUID& providerKey,
    const GUID& subLayerKey,
    const GUID& filterKey,
    const GUID& layerKey,
    FWP_ACTION_TYPE action,
    UINT64 weight,
    FWPM_FILTER_CONDITION0* conditions,
    UINT32 conditionCount,
    bool persistent) {
  FWPM_FILTER0 filter{};
  filter.filterKey = filterKey;
  filter.displayData.name = const_cast<wchar_t*>(L"Levik VPN Kill Switch");
  filter.providerKey = const_cast<GUID*>(&providerKey);
  filter.layerKey = layerKey;
  filter.subLayerKey = subLayerKey;
  filter.flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
  filter.weight.type = FWP_UINT64;
  filter.weight.uint64 = &weight;
  filter.numFilterConditions = conditionCount;
  filter.filterCondition = conditions;
  filter.action.type = action;
  return FwpmFilterAdd0(engine, &filter, nullptr, nullptr);
}

DWORD AddApplicationPermit(HANDLE engine, const std::wstring& path, const GUID& layerKey, const GUID& filterKey) {
  FWP_BYTE_BLOB* appId = nullptr;
  DWORD result = FwpmGetAppIdFromFileName0(path.c_str(), &appId);
  if (result != ERROR_SUCCESS) return result;

  FWPM_FILTER_CONDITION0 condition{};
  condition.fieldKey = FWPM_CONDITION_ALE_APP_ID;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_BYTE_BLOB_TYPE;
  condition.conditionValue.byteBlob = appId;
  result = AddFilter(engine, kProviderKey, kSubLayerKey, filterKey, layerKey, FWP_ACTION_PERMIT,
                     kPermitWeight, &condition, 1, true);
  FwpmFreeMemory0(reinterpret_cast<void**>(&appId));
  return result;
}

DWORD AddInterfacePermit(HANDLE engine, UINT64 interfaceLuid, const GUID& layerKey, const GUID& filterKey) {
  FWPM_FILTER_CONDITION0 condition{};
  condition.fieldKey = FWPM_CONDITION_IP_LOCAL_INTERFACE;
  condition.matchType = FWP_MATCH_EQUAL;
  condition.conditionValue.type = FWP_UINT64;
  condition.conditionValue.uint64 = &interfaceLuid;
  return AddFilter(engine, kProviderKey, kSubLayerKey, filterKey, layerKey, FWP_ACTION_PERMIT,
                   kPermitWeight, &condition, 1, true);
}

DWORD AddBlock(HANDLE engine, const GUID& providerKey, const GUID& subLayerKey,
               const GUID& layerKey, const GUID& filterKey, bool persistent) {
  return AddFilter(engine, providerKey, subLayerKey, filterKey, layerKey, FWP_ACTION_BLOCK,
                   kBlockWeight, nullptr, 0, persistent);
}

DWORD BeginTransaction(HANDLE engine) {
  return FwpmTransactionBegin0(engine, 0);
}

DWORD CommitTransaction(HANDLE engine, DWORD result) {
  if (result != ERROR_SUCCESS) {
    FwpmTransactionAbort0(engine);
    return result;
  }
  return FwpmTransactionCommit0(engine);
}

DWORD Enable(const std::wstring& appPath, const std::wstring& xrayPath) {
  EngineHandle engine;
  DWORD result = OpenEngine(engine);
  if (result != ERROR_SUCCESS) return result;
  if ((result = BeginTransaction(engine.get())) != ERROR_SUCCESS) return result;

  if ((result = EnsureProvider(engine.get(), kProviderKey, true)) == ERROR_SUCCESS)
    result = EnsureSubLayer(engine.get(), kProviderKey, kSubLayerKey, true);

  const std::array<const GUID*, 6> replaced = {
      &kAppV4Key, &kAppV6Key, &kXrayV4Key, &kXrayV6Key, &kBlockV4Key, &kBlockV6Key};
  for (const GUID* key : replaced) {
    if (result != ERROR_SUCCESS) break;
    result = IgnoreMissingFilter(FwpmFilterDeleteByKey0(engine.get(), key));
  }

  if (result == ERROR_SUCCESS) result = AddApplicationPermit(engine.get(), appPath, FWPM_LAYER_ALE_AUTH_CONNECT_V4, kAppV4Key);
  if (result == ERROR_SUCCESS) result = AddApplicationPermit(engine.get(), appPath, FWPM_LAYER_ALE_AUTH_CONNECT_V6, kAppV6Key);
  if (result == ERROR_SUCCESS) result = AddApplicationPermit(engine.get(), xrayPath, FWPM_LAYER_ALE_AUTH_CONNECT_V4, kXrayV4Key);
  if (result == ERROR_SUCCESS) result = AddApplicationPermit(engine.get(), xrayPath, FWPM_LAYER_ALE_AUTH_CONNECT_V6, kXrayV6Key);
  if (result == ERROR_SUCCESS) result = AddBlock(engine.get(), kProviderKey, kSubLayerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4, kBlockV4Key, true);
  if (result == ERROR_SUCCESS) result = AddBlock(engine.get(), kProviderKey, kSubLayerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6, kBlockV6Key, true);
  return CommitTransaction(engine.get(), result);
}

DWORD FindInterfaceLuid(const std::wstring& friendlyName, UINT64& luid) {
  ULONG size = 16 * 1024;
  std::vector<BYTE> buffer(size);
  ULONG result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
                                      reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  if (result == ERROR_BUFFER_OVERFLOW) {
    buffer.resize(size);
    result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, nullptr,
                                  reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data()), &size);
  }
  if (result != ERROR_SUCCESS) return result;

  for (IP_ADAPTER_ADDRESSES* adapter = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
       adapter != nullptr; adapter = adapter->Next) {
    if (adapter->FriendlyName != nullptr && _wcsicmp(adapter->FriendlyName, friendlyName.c_str()) == 0 &&
        adapter->OperStatus == IfOperStatusUp) {
      luid = adapter->Luid.Value;
      return ERROR_SUCCESS;
    }
  }
  return ERROR_NOT_FOUND;
}

DWORD AllowTunnel(const std::wstring& friendlyName) {
  UINT64 interfaceLuid = 0;
  DWORD result = FindInterfaceLuid(friendlyName, interfaceLuid);
  if (result != ERROR_SUCCESS) return result;

  EngineHandle engine;
  if ((result = OpenEngine(engine)) != ERROR_SUCCESS) return result;
  if ((result = BeginTransaction(engine.get())) != ERROR_SUCCESS) return result;
  result = IgnoreMissingFilter(FwpmFilterDeleteByKey0(engine.get(), &kTunnelV4Key));
  if (result == ERROR_SUCCESS) result = IgnoreMissingFilter(FwpmFilterDeleteByKey0(engine.get(), &kTunnelV6Key));
  if (result == ERROR_SUCCESS) result = AddInterfacePermit(engine.get(), interfaceLuid, FWPM_LAYER_ALE_AUTH_CONNECT_V4, kTunnelV4Key);
  if (result == ERROR_SUCCESS) result = AddInterfacePermit(engine.get(), interfaceLuid, FWPM_LAYER_ALE_AUTH_CONNECT_V6, kTunnelV6Key);
  return CommitTransaction(engine.get(), result);
}

DWORD Disable() {
  EngineHandle engine;
  DWORD result = OpenEngine(engine);
  if (result != ERROR_SUCCESS) return result;
  if ((result = BeginTransaction(engine.get())) != ERROR_SUCCESS) return result;

  const std::array<const GUID*, 8> filters = {
      &kAppV4Key, &kAppV6Key, &kXrayV4Key, &kXrayV6Key,
      &kTunnelV4Key, &kTunnelV6Key, &kBlockV4Key, &kBlockV6Key};
  for (const GUID* key : filters) {
    if (result != ERROR_SUCCESS) break;
    result = IgnoreMissingFilter(FwpmFilterDeleteByKey0(engine.get(), key));
  }
  if (result == ERROR_SUCCESS) result = IgnoreMissingSubLayer(FwpmSubLayerDeleteByKey0(engine.get(), &kSubLayerKey));
  if (result == ERROR_SUCCESS) result = IgnoreMissingProvider(FwpmProviderDeleteByKey0(engine.get(), &kProviderKey));
  return CommitTransaction(engine.get(), result);
}

DWORD Status() {
  EngineHandle engine;
  DWORD result = OpenEngine(engine);
  if (result != ERROR_SUCCESS) return result;
  FWPM_FILTER0* filter = nullptr;
  result = FwpmFilterGetByKey0(engine.get(), &kBlockV4Key, &filter);
  if (result == FWP_E_FILTER_NOT_FOUND) return 2;
  if (filter != nullptr) FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
  return result;
}

bool EqualPath(const std::wstring& left, const std::wstring& right) {
  return left.size() == right.size() &&
         CompareStringOrdinal(left.c_str(), static_cast<int>(left.size()),
                              right.c_str(), static_cast<int>(right.size()), TRUE) == CSTR_EQUAL;
}

bool IsPathBelow(const std::wstring& parent, const std::wstring& child) {
  return child.size() > parent.size() && child[parent.size()] == L'\\' &&
         CompareStringOrdinal(parent.c_str(), static_cast<int>(parent.size()),
                              child.c_str(), static_cast<int>(parent.size()), TRUE) == CSTR_EQUAL;
}

DWORD OpenDirectoryWithoutFollowingReparsePoints(const std::wstring& path, WinHandle& directory) {
  const HANDLE value = CreateFileW(
      path.c_str(), FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
      FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
  if (value == INVALID_HANDLE_VALUE) return GetLastError();
  directory.reset(value);

  FILE_ATTRIBUTE_TAG_INFO attributes{};
  if (!GetFileInformationByHandleEx(directory.get(), FileAttributeTagInfo, &attributes, sizeof(attributes))) {
    return GetLastError();
  }
  if ((attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) return ERROR_REPARSE_TAG_MISMATCH;
  return ERROR_SUCCESS;
}

DWORD FinalPath(HANDLE handle, std::wstring& path) {
  const DWORD required = GetFinalPathNameByHandleW(handle, nullptr, 0, FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (required == 0) return GetLastError();
  std::vector<wchar_t> buffer(static_cast<size_t>(required) + 1);
  const DWORD written = GetFinalPathNameByHandleW(handle, buffer.data(), static_cast<DWORD>(buffer.size()),
                                                   FILE_NAME_NORMALIZED | VOLUME_NAME_DOS);
  if (written == 0 || written >= buffer.size()) return written == 0 ? GetLastError() : ERROR_INSUFFICIENT_BUFFER;
  path.assign(buffer.data(), written);
  while (path.size() > 4 && path.back() == L'\\') path.pop_back();
  return ERROR_SUCCESS;
}

DWORD CurrentProfilePath(std::wstring& path) {
  WinHandle token;
  HANDLE rawToken = INVALID_HANDLE_VALUE;
  if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &rawToken)) return GetLastError();
  token.reset(rawToken);

  DWORD size = 0;
  GetUserProfileDirectoryW(token.get(), nullptr, &size);
  if (size == 0) return GetLastError();
  std::vector<wchar_t> buffer(size);
  if (!GetUserProfileDirectoryW(token.get(), buffer.data(), &size)) return GetLastError();
  path.assign(buffer.data());
  return ERROR_SUCCESS;
}

DWORD DeleteLegacyConfigRelativeTo(HANDLE runtimeDirectory) {
  using NtCreateFileFunction = NTSTATUS(NTAPI*)(
      PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
      ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
  using RtlNtStatusToDosErrorFunction = ULONG(WINAPI*)(NTSTATUS);

  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr) return GetLastError();
#pragma warning(push)
#pragma warning(disable : 4191)
  const auto ntCreateFile = reinterpret_cast<NtCreateFileFunction>(GetProcAddress(ntdll, "NtCreateFile"));
  const auto statusToError = reinterpret_cast<RtlNtStatusToDosErrorFunction>(GetProcAddress(ntdll, "RtlNtStatusToDosError"));
#pragma warning(pop)
  if (ntCreateFile == nullptr || statusToError == nullptr) return ERROR_PROC_NOT_FOUND;

  wchar_t fileName[] = L"xray-config.json";
  UNICODE_STRING name{};
  name.Buffer = fileName;
  name.Length = static_cast<USHORT>(wcslen(fileName) * sizeof(wchar_t));
  name.MaximumLength = static_cast<USHORT>(name.Length + sizeof(wchar_t));
  OBJECT_ATTRIBUTES attributes{};
  InitializeObjectAttributes(&attributes, &name, OBJ_CASE_INSENSITIVE, runtimeDirectory, nullptr);
  IO_STATUS_BLOCK statusBlock{};
  WinHandle file;
  HANDLE rawFile = INVALID_HANDLE_VALUE;
  constexpr ULONG kFileOpen = 1;
  constexpr ULONG kFileSynchronousIoNonAlert = 0x00000020;
  constexpr ULONG kFileNonDirectoryFile = 0x00000040;
  constexpr ULONG kFileOpenReparsePoint = 0x00200000;
  const NTSTATUS status = ntCreateFile(
      &rawFile, DELETE | FILE_READ_ATTRIBUTES | SYNCHRONIZE, &attributes, &statusBlock, nullptr,
      FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, kFileOpen,
      kFileSynchronousIoNonAlert | kFileNonDirectoryFile | kFileOpenReparsePoint, nullptr, 0);
  if (status < 0) {
    const DWORD error = statusToError(status);
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND ? ERROR_SUCCESS : error;
  }
  file.reset(rawFile);

  FILE_DISPOSITION_INFO disposition{};
  disposition.DeleteFile = TRUE;
  return SetFileInformationByHandle(file.get(), FileDispositionInfo, &disposition, sizeof(disposition))
      ? ERROR_SUCCESS
      : GetLastError();
}

DWORD CleanupLegacyConfig(const std::wstring& userDataPath) {
  std::wstring profilePath;
  DWORD result = CurrentProfilePath(profilePath);
  if (result != ERROR_SUCCESS) return result;

  WinHandle profileDirectory;
  result = OpenDirectoryWithoutFollowingReparsePoints(profilePath, profileDirectory);
  if (result != ERROR_SUCCESS) return result;
  std::wstring finalProfilePath;
  if ((result = FinalPath(profileDirectory.get(), finalProfilePath)) != ERROR_SUCCESS) return result;

  WinHandle userDataDirectory;
  result = OpenDirectoryWithoutFollowingReparsePoints(userDataPath, userDataDirectory);
  if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
  if (result != ERROR_SUCCESS) return result;
  std::wstring finalUserDataPath;
  if ((result = FinalPath(userDataDirectory.get(), finalUserDataPath)) != ERROR_SUCCESS) return result;
  if (!IsPathBelow(finalProfilePath, finalUserDataPath)) return ERROR_ACCESS_DENIED;

  std::wstring runtimePath = userDataPath;
  if (!runtimePath.empty() && runtimePath.back() != L'\\') runtimePath.push_back(L'\\');
  runtimePath.append(L"runtime");
  WinHandle runtimeDirectory;
  result = OpenDirectoryWithoutFollowingReparsePoints(runtimePath, runtimeDirectory);
  if (result == ERROR_FILE_NOT_FOUND || result == ERROR_PATH_NOT_FOUND) return ERROR_SUCCESS;
  if (result != ERROR_SUCCESS) return result;
  std::wstring finalRuntimePath;
  if ((result = FinalPath(runtimeDirectory.get(), finalRuntimePath)) != ERROR_SUCCESS) return result;
  if (!EqualPath(finalUserDataPath + L"\\runtime", finalRuntimePath)) return ERROR_ACCESS_DENIED;

  return DeleteLegacyConfigRelativeTo(runtimeDirectory.get());
}

DWORD SelfTest() {
  EngineHandle engine;
  DWORD result = OpenEngine(engine);
  if (result != ERROR_SUCCESS) return result;
  if ((result = BeginTransaction(engine.get())) != ERROR_SUCCESS) return result;
  if ((result = EnsureProvider(engine.get(), kTestProviderKey, false)) == ERROR_SUCCESS)
    result = EnsureSubLayer(engine.get(), kTestProviderKey, kTestSubLayerKey, false);
  if (result == ERROR_SUCCESS)
    result = AddBlock(engine.get(), kTestProviderKey, kTestSubLayerKey,
                      FWPM_LAYER_ALE_AUTH_CONNECT_V4, kTestFilterKey, false);
  const DWORD abortResult = FwpmTransactionAbort0(engine.get());
  return result == ERROR_SUCCESS ? abortResult : result;
}

}  // namespace

int wmain(int argc, wchar_t* argv[]) {
  if (argc < 2) {
    std::wcerr << L"Usage: levik-kill-switch <enable|allow-tunnel|disable|status|cleanup-legacy|self-test>\n";
    return ERROR_INVALID_PARAMETER;
  }

  const std::wstring command = argv[1];
  DWORD result = ERROR_INVALID_PARAMETER;
  if (command == L"enable" && argc == 4) result = Enable(argv[2], argv[3]);
  else if (command == L"allow-tunnel" && argc == 3) result = AllowTunnel(argv[2]);
  else if (command == L"disable" && argc == 2) result = Disable();
  else if (command == L"status" && argc == 2) result = Status();
  else if (command == L"cleanup-legacy" && argc == 3) result = CleanupLegacyConfig(argv[2]);
  else if (command == L"self-test" && argc == 2) result = SelfTest();

  if (result != ERROR_SUCCESS && result != 2) {
    std::wcerr << ErrorMessage(result) << L" (" << result << L")\n";
  }
  return static_cast<int>(result);
}
