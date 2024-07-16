#include <windows.h>
#include <stdio.h>
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
int main() {
	HRESULT hres;
	hres = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hres)) {
		printf("Failed to initialize COM library. Error code = 0x%x\n", hres);
		return 1;
	}
	hres = CoInitializeSecurity(NULL,
		-1, NULL,
		NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hres)) {
		printf("Failed to initialize security. Error code = 0x%x\n", hres);
		CoUninitialize();
		return 1;
	}
	IWbemLocator* pLoc = NULL;
	hres = CoCreateInstance(CLSID_WbemLocator, 0,
		CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
	if (FAILED(hres)) {
		printf("Failed to create IWbemLocator object. Error code = 0x%x\n", hres);
		CoUninitialize();
		return 1;
	}
	IWbemServices* pSvc = NULL;
	hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

	if (FAILED(hres)) {
		printf("Could not connect. Error code = 0x%x\n", hres);
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (FAILED(hres)) {
		printf("Could not set proxy blanket. Error code = 0x%x\n", hres);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	IEnumWbemClassObject* pEnumerator = NULL;
	hres = pSvc->ExecQuery(bstr_t("WQL"), bstr_t("SELECT * FROM SoftwareLicensingService"),
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

	if (FAILED(hres)) {
		printf("Query for operating system name failed. Error code = 0x%x\n", hres);
		pSvc->Release();
		pLoc->Release();
		CoUninitialize();
		return 1;
	}
	IWbemClassObject* pclsObj = NULL;
	ULONG uReturn = 0;
	while (pEnumerator) {
		HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
		if (0 == uReturn) {
			break;
		}
		VARIANT vtProp;
		hr = pclsObj->Get(LR"(OA3xOriginalProductKey)", 0, &vtProp, 0, 0);
		if (SUCCEEDED(hr)) {
			printf("Windows Product Key: %ls\n", vtProp.bstrVal);
			VariantClear(&vtProp);
		}
		pclsObj->Release();
	}
	pSvc->Release();
	pLoc->Release();
	pEnumerator->Release();
	CoUninitialize();
	return 0;
}
