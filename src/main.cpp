#include "../include/main.h"
#ifdef _M_IX86
#error "architecture unsupported"
#endif


HRESULT GetStringValue(IDxDiagContainer* pContainerObject, wchar_t* lpwszName, char* lpszValue, int nValueLength)
{
	VARIANT var{};
	VariantInit(&var);

	HRESULT hr{};
	if (FAILED(hr = pContainerObject->GetPropA(lpwszName, &var)))
		return hr;

	if (var.vt != VT_BSTR)
		return E_INVALIDARG;

	size_t cbConvSize = 0;
	wcstombs_s(&cbConvSize, lpszValue, nValueLength, var.bstrVal, SysStringLen(var.bstrVal));
	lpszValue[nValueLength - 1] = '\0';

	VariantClear(&var);
	return S_OK;
}
HRESULT GetIntValue(IDxDiagContainer* pContainerObject, wchar_t* lpwszName, int* pnValue)
{
	VARIANT var{};
	VariantInit(&var);

	HRESULT hr{};
	if (FAILED(hr = pContainerObject->GetPropA(lpwszName, &var)))
		return hr;

	if (var.vt != VT_UI4)
		return E_INVALIDARG;

	*pnValue = var.ulVal;

	VariantClear(&var);
	return S_OK;
}

const std::string WebhookURL = "";

// Source: https://stackoverflow.com/a/579448
bool GetMonitorSizeFromEDID(const HKEY hEDIDRegKey, short& WidthMm, short& HeightMm)
{
	BYTE EDID[1024];
	DWORD edidsize = sizeof(EDID);

	const auto lStatus = RegQueryValueExA(hEDIDRegKey, "EDID", nullptr, nullptr, EDID, &edidsize);
	if (lStatus != ERROR_SUCCESS)
	{
		std::cerr << "RegQueryValueExA(EDID) failed with status: " << std::to_string(lStatus) << std::endl;
		return false;
	}

	DWORD p = 8;
	char model2[9]{ '\0' };

	char byte1 = EDID[p];
	char byte2 = EDID[p + 1];
	model2[0] = ((byte1 & 0x7C) >> 2) + 64;
	model2[1] = ((byte1 & 3) << 3) + ((byte2 & 0xE0) >> 5) + 64;
	model2[2] = (byte2 & 0x1F) + 64;
	sprintf_s(model2 + 3, sizeof(model2) - 3, "%X%X%X%X", (EDID[p + 3] & 0xf0) >> 4, EDID[p + 3] & 0xf, (EDID[p + 2] & 0xf0) >> 4, EDID[p + 2] & 0x0f);

	WidthMm = EDID[22];
	HeightMm = EDID[21];
	return true;
}

std::string StreamToString(std::ostream& ss) {
	std::string data = dynamic_cast<std::ostringstream&>(ss).str();
	std::cerr << data;
	return data;
}

std::string SModeCheck(const HMODULE hNtdll) {
	typedef NTSTATUS(NTAPI* TRtlGetVersion)(LPOSVERSIONINFOEX OsVersionInfoEx);
	const auto RtlGetVersion = reinterpret_cast<TRtlGetVersion>(GetProcAddress(hNtdll, "RtlGetVersion"));
	std::string returnString = "";
	if (!RtlGetVersion)
	{
		return StreamToString(std::ostringstream() << "GetProcAddress(RtlGetVersion) failed with error: " << GetLastError() << std::endl);
	}

	// S Mode
	std::cout << "S Mode checking..." << std::endl;

	OSVERSIONINFOEX osVerEx{ 0 };
	const auto ntStatus = RtlGetVersion(&osVerEx);
	if (ntStatus != STATUS_SUCCESS)
	{
		return StreamToString(std::ostringstream() << "RtlGetVersion failed with status: " << std::hex << ntStatus << std::endl);
	}

	std::cout << "\tVersion: " << osVerEx.dwMajorVersion << "." << osVerEx.dwMinorVersion << std::endl;

	DWORD dwProductType = 0;
	if (!GetProductInfo(osVerEx.dwMajorVersion, osVerEx.dwMinorVersion, 0, 0, &dwProductType))
	{
		return StreamToString(std::ostringstream() << "GetProductInfo failed with error: " << GetLastError() << std::endl);
	}

	std::cout << "\tProduct type: " << dwProductType << std::endl;

	if (dwProductType == PRODUCT_CLOUD || dwProductType == PRODUCT_CLOUDN)
	{
		return StreamToString(std::ostringstream() << "S Mode is not supported!" << std::endl);
	}

	std::cout << "S Mode check passed!" << std::endl;
	return "";
	
}

std::string CPUCheck() {
	// 1 Ghz, 64-bit, dual core, known CPU

	std::cout << "CPU checking..." << std::endl;
	std::string res;

	const auto dwActiveProcessorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
	if (!dwActiveProcessorCount)
	{
		return StreamToString(std::ostringstream() << "Active CPU does not exist in your system, GetActiveProcessorCount failed with error: " << GetLastError() << std::endl);
	}

	std::cout << "\tActive processor count: " << dwActiveProcessorCount << std::endl;

	const auto hProcHeap = GetProcessHeap();
	if (!hProcHeap)
	{
		return StreamToString(std::ostringstream() << "GetProcessHeap failed with error: " << GetLastError() << std::endl);
	}

	SYSTEM_INFO sysInfo{ 0 };
	GetNativeSystemInfo(&sysInfo);

	std::cout << "\tProcessor arch: " << sysInfo.wProcessorArchitecture << std::endl;

	if (sysInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_AMD64 &&
		sysInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_IA64 &&
		sysInfo.wProcessorArchitecture != PROCESSOR_ARCHITECTURE_ARM64)
	{
		return StreamToString(std::ostringstream() << "System processor arch must be x64!" << std::endl);
	}

	std::cout << "\tProcessor count: " << sysInfo.dwNumberOfProcessors << std::endl;

	if (sysInfo.dwNumberOfProcessors < 2)
	{
		return StreamToString(std::ostringstream() << "System processor count: " << sysInfo.dwNumberOfProcessors << " is less than minimum requirement!" << std::endl);
	}

	PROCESSOR_POWER_INFORMATION processorPowerInfo{ 0 };
	const auto ulBufferSize = static_cast<ULONG>(sizeof(processorPowerInfo) * sysInfo.dwNumberOfProcessors);
	const auto lpBuffer = reinterpret_cast<PROCESSOR_POWER_INFORMATION*>(HeapAlloc(hProcHeap, HEAP_ZERO_MEMORY, ulBufferSize));
	if (!lpBuffer)
	{
		return StreamToString(std::ostringstream() << "HeapAlloc(" << ulBufferSize << " bytes) failed with error: " << GetLastError() << std::endl);
	}

	const auto lStatus = CallNtPowerInformation(ProcessorInformation, nullptr, 0, lpBuffer, ulBufferSize);
	if (lStatus != STATUS_SUCCESS)
	{
		HeapFree(hProcHeap, 0, lpBuffer);
		return StreamToString(std::ostringstream() << "CallNtPowerInformation failed with status: " << lStatus << std::endl);
	}

	auto nSpeedCheckCounter = 0;
	for (size_t i = 0; i < sysInfo.dwNumberOfProcessors; ++i)
	{
		const auto lpCurrProcessorInfo = *(reinterpret_cast<PROCESSOR_POWER_INFORMATION*>(reinterpret_cast<LPBYTE>(lpBuffer) + (sizeof(processorPowerInfo) * i)));
		std::cout << "\tProcessor: " << lpCurrProcessorInfo.Number + 1 << " Speed: " << lpCurrProcessorInfo.MaxMhz << std::endl;
		if (lpCurrProcessorInfo.MaxMhz >= 1000)
		{
			nSpeedCheckCounter++;
		}
	}
	HeapFree(hProcHeap, 0, lpBuffer);

	if (nSpeedCheckCounter < 2)
	{
		return StreamToString(std::ostringstream() << "System processor speed is less than minimum requirement!" << std::endl);
	}

	const auto dwRevision = sysInfo.wProcessorRevision >> 8;
	const auto byRevision = LOBYTE(sysInfo.wProcessorRevision);

	int arCPUID[4]{ 0 };
	__cpuid(arCPUID, 0);

	std::string stVendor;
	stVendor += std::string(reinterpret_cast<const char*>(&arCPUID[1]), sizeof(arCPUID[1]));
	stVendor += std::string(reinterpret_cast<const char*>(&arCPUID[3]), sizeof(arCPUID[3]));
	stVendor += std::string(reinterpret_cast<const char*>(&arCPUID[2]), sizeof(arCPUID[2]));

	std::cout << "\tProcessor level: " << sysInfo.wProcessorLevel << " revision: " << dwRevision << " " << std::to_string(byRevision) << " vendor: " << stVendor << std::endl;

	// Reversed checks from Windows's tool
	if (stVendor == "AuthenticAMD")
	{
		if (sysInfo.wProcessorLevel < 0x17 || (sysInfo.wProcessorLevel == 23 && !((dwRevision - 1) & 0xFFFFFFEF)))
		{
			return StreamToString(std::ostringstream() << "Unsupported AMD CPU detected!" << std::endl);
		}
	}
	else if (stVendor == "GenuineIntel")
	{
		if (sysInfo.wProcessorLevel == 6)
		{
			if ((dwRevision < 0x5F && dwRevision != 85) ||
				//					(dwRevision == 142 && byRevision == 9) ||
				(dwRevision == 158 && byRevision == 9))
			{
				return StreamToString(std::ostringstream() << "Unsupported Intel CPU detected!" << std::endl);
			}
		}
	}
	else if (stVendor.find("Qualcomm") == std::string::npos)
	{
		return StreamToString(std::ostringstream() << "Unknown CPU vendor detected!" << std::endl);
	}
	else if (!IsProcessorFeaturePresent(PF_ARM_V81_ATOMIC_INSTRUCTIONS_AVAILABLE))
	{
		return StreamToString(std::ostringstream() << "Unsupported Qualcomm CPU detected!" << std::endl);
	}

	std::cout << "CPU check passed!" << std::endl;
	return "";
}

std::string RAMCheck() {
	std::cout << "RAM checking..." << std::endl;

	ULONGLONG ullTotalyMemory = 0;
	if (!GetPhysicallyInstalledSystemMemory(&ullTotalyMemory))
	{
		std::cerr << "GetPhysicallyInstalledSystemMemory failed with error: " << GetLastError() << std::endl;

		MEMORYSTATUSEX memInfo{ 0 };
		memInfo.dwLength = sizeof(memInfo);
		if (!GlobalMemoryStatusEx(&memInfo))
		{
			return StreamToString(std::ostringstream() << "GlobalMemoryStatusEx failed with error: " << GetLastError() << std::endl);
		}
		else
		{
			ullTotalyMemory = memInfo.ullTotalPhys / 1024;
		}
	}

	std::cout << "\tRAM capacity: " << ullTotalyMemory << std::endl;

	if (ullTotalyMemory <= 4096000)
	{
		return StreamToString(std::ostringstream() << "RAM capacity is less than minimum requirement!" << std::endl);
	}

	std::cout << "RAM check passed!" << std::endl;
	return "";
}

std::string DiskCheck() {
	// 64 GB Free disk space

	std::cout << "Disk checking..." << std::endl;

	char szWinDir[MAX_PATH]{ '\0' };
	const auto c_nWinDirLength = GetSystemWindowsDirectoryA(szWinDir, sizeof(szWinDir));
	if (!c_nWinDirLength)
	{
		return StreamToString(std::ostringstream() << "GetSystemWindowsDirectoryA failed with error: " << GetLastError() << std::endl);
	}

	const auto c_stWinDir = std::string(szWinDir, c_nWinDirLength);
	const auto c_stTargetDev = c_stWinDir.substr(0, 3);
	std::cout << "\tWindows directory: " << c_stWinDir << " Target device: " << c_stTargetDev << std::endl;

	ULARGE_INTEGER uiTotalNumberOfBytes{ 0 };
	if (!GetDiskFreeSpaceExA(c_stTargetDev.c_str(), nullptr, &uiTotalNumberOfBytes, nullptr))
	{
		return StreamToString(std::ostringstream() << "GetDiskFreeSpaceExA failed with error: " << GetLastError() << std::endl);
	}

	const auto c_dwFreeSpaceAsGB = uiTotalNumberOfBytes.QuadPart / 1024 / 1024 / 1024;
	std::cout << "\tDisk space: " << std::to_string(c_dwFreeSpaceAsGB) << " GB" << std::endl;

	if (c_dwFreeSpaceAsGB < 64)
	{
		return StreamToString(std::ostringstream() << "Disk capacity is less than minimum requirement!" << std::endl);
	}

	std::cout << "Disk check passed!" << std::endl;
	return "";
}

std::string MonitorCheck() {
	// 720p display, 9, 8 BPC

	std::cout << "Resolution checking..." << std::endl;

	// Enum monitors
	const auto hDC = GetDC(nullptr);
	if (!hDC)
	{
		return StreamToString(std::ostringstream() << "GetDC failed with error: " << GetLastError() << std::endl);
	}

	BOOL bHasAvailableMonitor = FALSE;
	auto OnMonitorEnum = [](HMONITOR hMonitor, HDC hdcMonitor, LPRECT lprcMonitor, LPARAM dwData) -> BOOL {
		static auto s_nIdx = 0;
		const auto c_pbHasAvailableMonitor = reinterpret_cast<BOOL*>(dwData);

		s_nIdx++;

		MONITORINFO monInfo{ 0 };
		monInfo.cbSize = sizeof(monInfo);

		if (!GetMonitorInfoA(hMonitor, &monInfo))
		{
			std::cerr << "GetMonitorInfoA(" << s_nIdx << ") failed with error : " << GetLastError() << std::endl;
			return TRUE;
		}

		const auto c_nBPC = GetDeviceCaps(hdcMonitor, BITSPIXEL);
		const auto c_stIsPrimary = (monInfo.dwFlags & MONITORINFOF_PRIMARY) ? "true" : "false";

		std::cout <<
			"\tMonitor: " << s_nIdx <<
			" Primary: " << c_stIsPrimary <<
			" BPC: " << c_nBPC <<
			" Resolution: " << monInfo.rcMonitor.right << "x" << monInfo.rcMonitor.bottom <<
			std::endl;

		if (monInfo.rcMonitor.bottom >= 720 && c_nBPC >= 8)
		{
			*c_pbHasAvailableMonitor = TRUE;
			return TRUE;
		}

		return TRUE;
	};

	if (!EnumDisplayMonitors(hDC, nullptr, OnMonitorEnum, reinterpret_cast<LPARAM>(&bHasAvailableMonitor)))
	{
		return StreamToString(std::ostringstream() << "EnumDisplayMonitors failed with error: " << GetLastError() << std::endl);
	}

	if (!bHasAvailableMonitor)
	{
		return StreamToString(std::ostringstream() << "Any available display device could not detected!" << std::endl);
	}

	ReleaseDC(nullptr, hDC);
	std::cout << "Resolution check passed!" << std::endl;


	std::cout << "Display devices checking..." << std::endl;

	HKEY hKey{};
	auto lStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY", 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hKey);
	if (lStatus == ERROR_SUCCESS)
	{
		std::vector <std::string> vDisplayDevList;
		DWORD dwIndex = 0;
		while (true)
		{
			DWORD dwKeyLen = MAX_PATH;
			char szNewKeyName[MAX_PATH]{ '\0' };

			lStatus = RegEnumKeyExA(hKey, dwIndex, szNewKeyName, &dwKeyLen, 0, nullptr, nullptr, nullptr);
			if (ERROR_SUCCESS != lStatus)
				break;

			if (szNewKeyName[0] != '\0')
			{
				std::cout << "\t[" << std::to_string(dwIndex + 1) << "] display device detected: " << szNewKeyName << std::endl;
				vDisplayDevList.emplace_back(szNewKeyName);
			}
			dwIndex++;
		}

		std::vector <std::string> vDisplayDevRegDir;
		for (const auto& stDisplayDevice : vDisplayDevList)
		{
			const auto stSubKey = "SYSTEM\\CurrentControlSet\\Enum\\DISPLAY\\" + stDisplayDevice;

			HKEY hSubKey{};
			lStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, stSubKey.c_str(), 0, KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE, &hSubKey);
			if (lStatus == ERROR_SUCCESS)
			{
				while (true)
				{
					DWORD dwKeyLen = MAX_PATH;
					char szNewKeyName[MAX_PATH]{ '\0' };

					lStatus = RegEnumKeyExA(hSubKey, dwIndex, szNewKeyName, &dwKeyLen, 0, nullptr, nullptr, nullptr);
					if (ERROR_SUCCESS != lStatus)
						break;

					char szParamPath[512]{ '\0' };
					sprintf_s(szParamPath, "%s\\%s\\Device Parameters", stSubKey.c_str(), szNewKeyName);
					vDisplayDevRegDir.emplace_back(szParamPath);
					dwIndex++;
				}
			}
		}

		auto bHasCompatibleDisplay = false;
		for (const auto& stDisplayDevRegPath : vDisplayDevRegDir)
		{
			HKEY hSubPathKey{};
			lStatus = RegOpenKeyExA(HKEY_LOCAL_MACHINE, stDisplayDevRegPath.c_str(), 0, KEY_READ | KEY_QUERY_VALUE, &hSubPathKey);
			if (lStatus == ERROR_SUCCESS)
			{
				// Get monitor size as MM
				short sWidthMM = 0, sHeightMM = 0;
				if (GetMonitorSizeFromEDID(hSubPathKey, sWidthMM, sHeightMM))
				{
					// Convert to diagonal
					const auto dDisplayMM = sqrt(sWidthMM * sWidthMM + sHeightMM * sHeightMM);

					// MM to inches
					const auto dDisplayInches = dDisplayMM * 0.393700787;

					// Check size
					if (dDisplayInches >= 9)
					{
						std::cout << "\tAvailable display device with size: " << std::to_string(dDisplayInches) << " detected!" << std::endl;
						bHasCompatibleDisplay = true;
						break;
					}
				}

				RegCloseKey(hSubPathKey);
			}
		}

		if (!vDisplayDevRegDir.empty() && !bHasCompatibleDisplay)
		{
			return StreamToString(std::ostringstream() << "9 or greater display device does not exist!" << std::endl);
		}
	}

	std::cout << "Display devices check passed!" << std::endl;
	return "";
}

std::string UEFICheck(const HMODULE hNtdll) {
	// UEFI

	typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(UINT SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	const auto NtQuerySystemInformation = reinterpret_cast<TNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));

	const auto GetFirmwareName = [](const uint8_t type) -> std::string {
		if (type == FirmwareTypeBios)
			return "Legacy/Bios";
		else if (type == FirmwareTypeUefi)
			return "UEFI";
		else
			return "Unknown: " + std::to_string(type);
	};

	std::cout << "Firmware checking..." << std::endl;

	ULONG cbSize = 0;
	SYSTEM_BOOT_ENVIRONMENT_INFORMATION sbei{ 0 };
	const auto ntStatus = NtQuerySystemInformation(SystemBootEnvironmentInformation, &sbei, sizeof(sbei), &cbSize);
	if (ntStatus != STATUS_SUCCESS)
	{
		return StreamToString(std::ostringstream() << "NtQuerySystemInformation(SystemBootEnvironmentInformation) failed with status: " << std::hex << ntStatus << std::endl);
	}

	std::cout << "\tFirmware type: " << GetFirmwareName(sbei.FirmwareType) << std::endl;

	if (sbei.FirmwareType != FirmwareTypeUefi)
	{
		return StreamToString(std::ostringstream() << "Boot firmware: " << GetFirmwareName(sbei.FirmwareType) << " is not allowed!" << std::endl);
	}

	std::cout << "Firmware check passed!" << std::endl;
	return "";
}

std::string SecureBootCheck(const HMODULE hNtdll) {
	// Secure boot

	std::cout << "Secure boot checking..." << std::endl;

	typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(UINT SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	const auto NtQuerySystemInformation = reinterpret_cast<TNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));

	ULONG cbSize = 0;
	SYSTEM_SECUREBOOT_INFORMATION ssbi{ 0 };
	const auto ntStatus = NtQuerySystemInformation(SystemSecureBootInformation, &ssbi, sizeof(ssbi), &cbSize);
	if (ntStatus != STATUS_SUCCESS)
	{
		return StreamToString(std::ostringstream() << "NtQuerySystemInformation(SystemSecureBootInformation) failed with status: " << std::hex << ntStatus << std::endl);
	}

	std::cout << "\tSecure boot capable: " << std::to_string(ssbi.SecureBootCapable) << " Enabled: " << std::to_string(ssbi.SecureBootEnabled) << std::endl;

	if (!ssbi.SecureBootCapable)
	{
		return StreamToString(std::ostringstream() << "Secure boot must be capable!" << std::endl);
	}

	std::cout << "Secure boot check passed!" << std::endl;
	return "";
}

std::string TPMCheck() {
	// TPM 2.0 

	std::cout << "TPM checking..." << std::endl;

	TPM_DEVICE_INFO tpmDevInfo{ 0 };
	const auto nTpmRet = Tbsi_GetDeviceInfo(sizeof(tpmDevInfo), &tpmDevInfo);
	if (nTpmRet == TBS_E_TPM_NOT_FOUND)
	{
		return StreamToString(std::ostringstream() << "TPM module does not exist or activated in system!" << std::endl);
	}
	else if (nTpmRet != TBS_SUCCESS)
	{
		return StreamToString(std::ostringstream() << "Tbsi_GetDeviceInfo failed with status: " << nTpmRet << std::endl);
	}

	std::cout << "\tTPM module detected! Version: " << std::to_string(tpmDevInfo.tpmVersion) << std::endl;

	if (tpmDevInfo.tpmVersion != 2)
	{
		return StreamToString(std::ostringstream() << "TPM version: " << tpmDevInfo.tpmVersion << " is less than minimum requirement!" << std::endl);
	}

	std::cout << "TPM check passed!" << std::endl;
	return "";
}

std::string Dx12Check() {
	// DirectX 12, WDDM 2

	std::cout << "DirectX/WDDM checking..." << std::endl;

	DIRECTX_VERSION_INFORMATION dxVerInfo{};
	std::vector <std::shared_ptr <DISPLAY_DEVICE_INFORMATION>> vDisplayDevices;

	auto bCompleted = false;
	auto bComInitialized = false;
	IDxDiagContainer* pObject = nullptr;
	IDxDiagContainer* pContainer = nullptr;
	IDxDiagProvider* pDxDiagProvider = nullptr;
	IDxDiagContainer* pDxDiagRoot = nullptr;
	IDxDiagContainer* pDxDiagSystemInfo = nullptr;

	do
	{
		HRESULT hr = CoInitialize(nullptr);
		bComInitialized = SUCCEEDED(hr);

		hr = CoCreateInstance(CLSID_DxDiagProvider, nullptr, CLSCTX_INPROC_SERVER, IID_IDxDiagProvider, (LPVOID*)&pDxDiagProvider);
		if (FAILED(hr))
		{
			std::cerr << "CoCreateInstance(CLSID_DxDiagProvider) failed with status: " << std::hex << hr << std::endl;
			break;
		}
		if (!pDxDiagProvider)
		{
			std::cerr << "CoCreateInstance(CLSID_DxDiagProvider) returned nullptr" << std::endl;
			hr = E_POINTER;
			break;
		}

		DXDIAG_INIT_PARAMS dxDiagInitParam{ 0 };
		dxDiagInitParam.dwSize = sizeof(dxDiagInitParam);
		dxDiagInitParam.dwDxDiagHeaderVersion = DXDIAG_DX9_SDK_VERSION;
		dxDiagInitParam.bAllowWHQLChecks = false;
		dxDiagInitParam.pReserved = nullptr;

		hr = pDxDiagProvider->Initialize(&dxDiagInitParam);
		if (FAILED(hr))
		{
			std::cerr << "pDxDiagProvider->Initialize failed with status: " << std::hex << hr << std::endl;
			break;
		}

		hr = pDxDiagProvider->GetRootContainer(&pDxDiagRoot);
		if (FAILED(hr))
		{
			std::cerr << "pDxDiagProvider->GetRootContainer failed with status: " << std::hex << hr << std::endl;
			break;
		}

		if (FAILED(hr = pDxDiagRoot->GetChildContainer(L"DxDiag_DisplayDevices", &pContainer)))
		{
			std::cerr << "pDxDiagRoot->GetChildContainer(DxDiag_DisplayDevices) failed with status: " << std::hex << hr << std::endl;
			break;
		}

		DWORD dwInstanceCount = 0;
		if (FAILED(hr = pContainer->GetNumberOfChildContainers(&dwInstanceCount)))
		{
			std::cerr << "pContainer->GetNumberOfChildContainers failed with status: " << std::hex << hr << std::endl;
			break;
		}

		std::cout << "\t" << std::to_string(dwInstanceCount) << " instance found!" << std::endl;

		// Display devices
		for (DWORD i = 0; i < dwInstanceCount; i++)
		{
			const auto devInfo = std::make_shared<DISPLAY_DEVICE_INFORMATION>();

			wchar_t wszContainer[256]{ L'\0' };
			hr = pContainer->EnumChildContainerNames(i, wszContainer, 256);
			if (FAILED(hr))
			{
				std::cerr << "pContainer->EnumChildContainerNames failed with status: " << std::hex << hr << std::endl;
				break;
			}

			hr = pContainer->GetChildContainer(wszContainer, &pObject);
			if (FAILED(hr) || !pObject)
			{
				std::cerr << "pContainer->GetChildContainer failed with status: " << std::hex << hr << std::endl;
				break;
			}

			if (FAILED(hr = GetStringValue(pObject, L"szDescription", devInfo->szDescription, _countof(devInfo->szDescription))))
			{
				std::cerr << "GetStringValue(szDescription) failed with status: " << std::hex << hr << std::endl;
				break;
			}

			if (FAILED(hr = GetStringValue(pObject, L"szDriverModelEnglish", devInfo->szDriverModel, _countof(devInfo->szDriverModel))))
			{
				std::cerr << "GetStringValue(szDriverModelEnglish) failed with status: " << std::hex << hr << std::endl;
				break;
			}

			std::cout << "\tDevice index: " << std::to_string(i + 1) << " Description: " << devInfo->szDescription << " Model: " << devInfo->szDriverModel << std::endl;

			vDisplayDevices.emplace_back(devInfo);
			SAFE_RELEASE(pObject);
		}

		// DirectX
		if (FAILED(hr = pDxDiagRoot->GetChildContainer(L"DxDiag_SystemInfo", &pDxDiagSystemInfo)))
			break;

		if (FAILED(hr = GetIntValue(pDxDiagSystemInfo, L"dwDirectXVersionMajor", &dxVerInfo.nMajorVersion)))
			break;

		if (FAILED(hr = GetIntValue(pDxDiagSystemInfo, L"dwDirectXVersionMinor", &dxVerInfo.nMinorVersion)))
			break;

		bCompleted = true;
	} while (FALSE);

	SAFE_RELEASE(pObject);
	SAFE_RELEASE(pContainer);
	SAFE_RELEASE(pDxDiagSystemInfo);
	SAFE_RELEASE(pDxDiagRoot);
	SAFE_RELEASE(pDxDiagProvider);

	if (bComInitialized)
		CoUninitialize();

	if (!bCompleted)
	{
		return StreamToString(std::ostringstream() << "DirectX/WDDM check failed!" << std::endl);
	}

	if (dxVerInfo.nMajorVersion < 12)
	{
		return StreamToString(std::ostringstream() << "System DirectX version: " << std::to_string(dxVerInfo.nMajorVersion) << " lower than 12!" << std::endl);
	}

	for (const auto& spDeviceInfo : vDisplayDevices)
	{
		if (spDeviceInfo)
		{
			const std::string c_stModelInfo = spDeviceInfo->szDriverModel;
			if (c_stModelInfo.find("WDDM 2") == std::string::npos &&
				c_stModelInfo.find("WDDM 3") == std::string::npos)
			{
				return StreamToString(std::ostringstream() << "WDDM 2/3 is not found in dxdiag config!" << std::endl);
			}
		}
	}

	std::cout << "DirectX/WDDM check passed!" << std::endl;
	return "";
}

std::string InternetCheck() {
	// Internet connection

	std::cout << "Internet connection checking..." << std::endl;

	DWORD dwFlags = 0;
	if (!InternetGetConnectedState(&dwFlags, 0))
	{
		return StreamToString(std::ostringstream() << "InternetGetConnectedState failed with error: " << GetLastError() << std::endl);
	}

	const auto dwTestConnectionRet = InternetAttemptConnect(0);
	if (dwTestConnectionRet != ERROR_SUCCESS)
	{
		return StreamToString(std::ostringstream() << "InternetAttemptConnect failed with error: " << GetLastError() << std::endl);
	}

	std::cout << "Internet connection check passed!" << std::endl;
	return "Connected";
}

std::string InformWebhook(std::string message) {
	std::stringstream body;
	body << "{ \"text\" : \"" << message << "\" }";

	cpr::Response r = cpr::Post(cpr::Url{ WebhookURL }, cpr::Body{ body.str() });
	std::cout << r.text << std::endl;
}

std::string GetSystemName() {
	char name[MAX_COMPUTERNAME_LENGTH + 1];
	DWORD size = sizeof(name);
	if (GetComputerName(name, &size)) {
		return name;
	}
	return "Unknown";
}

std::string GetUsername(){
	char username[UNLEN + 1];
	DWORD username_len = UNLEN + 1;
	if (GetUserName(username, &username_len)) {
		return username;
	}
	return "Unknown";
}

std::string GetErrors(std::string sModeCheck, std::string cpuCheck, std::string ramCheck, std::string diskCheck, std::string uefiCheck, std::string secureBootCheck, std::string tmpCheck, std::string dx12Check) {
	std::string errors = "";
	std::stringstream errorStream;

	if (sModeCheck != "") {
		errorStream << "*S Mode Check Failed:* \n`" << sModeCheck << "`\n";
	}

	if (cpuCheck != "") {
		errorStream << "*CPU Check Failed:* \n`" << cpuCheck << "`\n";
	}

	if (ramCheck != "") {
		errorStream << "*RAM Check Failed:* \n`" << ramCheck << "`\n";
	}

	if (diskCheck != "") {
		errorStream << "*Disk Check Failed:* \n`" << diskCheck << "`\n";
	}

	if (uefiCheck != "") {
		errorStream << "*UEFI Check Failed:* \n`" << uefiCheck << "`\n";
	}

	if (secureBootCheck != "") {
		errorStream << "*Secure Boot Check Failed:* \n`" << secureBootCheck << "`\n";
	}

	if (tmpCheck != "") {
		errorStream << "*TMP Check Failed:* \n`" << tmpCheck << "`\n";
	}

	if (dx12Check != "") {
		errorStream << "*DirectX12 Check Failed:* \n`" << dx12Check << "`\n";
	}

	errors = errorStream.str();
	if (errors != "") {
		std::stringstream returnStream;
		returnStream << "*Windows 11 System Check Errors:*\n" << "*PC Name:* `" << GetSystemName() << "`\n" << "*Username:* `" << GetUsername() << "`\n" << errors;
		return returnStream.str();
	}

	return "";
}

int main(int, char* argv[])
{
	std::cout << "Windows 11 minimum requirement checker tool: '" << argv[0] << "' started!" << std::endl;

	const auto hNtdll = LoadLibraryA("ntdll.dll");
	if (!hNtdll)
	{
		std::cerr << "LoadLibraryA(ntdll) failed with error: " << GetLastError() << std::endl;
		std::system("PAUSE");
		return EXIT_FAILURE;
	}

	typedef NTSTATUS(NTAPI* TNtQuerySystemInformation)(UINT SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	const auto NtQuerySystemInformation = reinterpret_cast<TNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
	if (!NtQuerySystemInformation)
	{
		std::cerr << "GetProcAddress(NtQuerySystemInformation) failed with error: " << GetLastError() << std::endl;
		std::system("PAUSE");
		return EXIT_FAILURE;
	}

	std::string errors = GetErrors(SModeCheck(hNtdll), CPUCheck(), RAMCheck(), DiskCheck(), UEFICheck(hNtdll), SecureBootCheck(hNtdll), TPMCheck(), Dx12Check());
	// For testing
	// std::string errors = GetErrors("Smode Error 123","CPU Error 123","RAM Error 123", "Disk Error 123", "UEFI Error 123", "Secure Boot Error 123", "TPM Error 123", "Dx12 Error 123");

	if (InternetCheck() == "Connected") {
		if (errors != "") {
			InformWebhook(errors);
		}
	}
	else {
		std::cout << "Please connect to the internet and run again to upload results.";
	}

	if (errors == "") {
		std::cout << "All checks passed! Your system can be upgradable to Windows 11" << std::endl;
		std::system("PAUSE");
		return EXIT_SUCCESS;
	}
	else {
		std::cout << "Some checks failed! Please address before upgrading to Windows 11" << std::endl;
		std::system("PAUSE");
		return EXIT_FAILURE;
	}
}

