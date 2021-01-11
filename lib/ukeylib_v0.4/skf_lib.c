#include <stdio.h>
#include <string.h>
#include <Windows.h>

#include <tchar.h>
#include "gmskf.h"
#include "skf_int.h"

#define SAR_OK				0x00000000
#define DEVAPI


#define SKF_METHOD_BIND_FUNCTION_EX(func,name) \
	skf->func = (SKF_##func##_FuncPtr)GetProcAddress(skf->module, "SKF_"#name)

#define SKF_METHOD_BIND_FUNCTION(func) \
	SKF_METHOD_BIND_FUNCTION_EX(func,func)

SKF_METHOD *skf_method = NULL;
SKF_VENDOR *skf_vendor = NULL;

SKF_METHOD *SKF_METHOD_load_library(const char *so_path)
{
	SKF_METHOD *ret = NULL;
	SKF_METHOD *skf = NULL;

	if (!(skf = malloc(sizeof(*skf)))) {
		goto end;
	}
    skf->module = LoadLibrary(so_path);
	if (skf->module == NULL) {
		goto end;
	}

	SKF_METHOD_BIND_FUNCTION(WaitForDevEvent);
	SKF_METHOD_BIND_FUNCTION(CancelWaitForDevEvent);
	SKF_METHOD_BIND_FUNCTION(EnumDev);
	SKF_METHOD_BIND_FUNCTION(ConnectDev);
	SKF_METHOD_BIND_FUNCTION(DisConnectDev);
	SKF_METHOD_BIND_FUNCTION(GetDevState);
	SKF_METHOD_BIND_FUNCTION(SetLabel);
	SKF_METHOD_BIND_FUNCTION(GetDevInfo);
	SKF_METHOD_BIND_FUNCTION(LockDev);
	SKF_METHOD_BIND_FUNCTION(UnlockDev);
	SKF_METHOD_BIND_FUNCTION(Transmit);
	SKF_METHOD_BIND_FUNCTION(ChangeDevAuthKey);
	SKF_METHOD_BIND_FUNCTION(DevAuth);
	SKF_METHOD_BIND_FUNCTION(ChangePIN);
	SKF_METHOD_BIND_FUNCTION(GetPINInfo);
	SKF_METHOD_BIND_FUNCTION(VerifyPIN);
	SKF_METHOD_BIND_FUNCTION(UnblockPIN);
	SKF_METHOD_BIND_FUNCTION(ClearSecureState);
	SKF_METHOD_BIND_FUNCTION(CreateApplication);
	SKF_METHOD_BIND_FUNCTION(EnumApplication);
	SKF_METHOD_BIND_FUNCTION(DeleteApplication);
	SKF_METHOD_BIND_FUNCTION(OpenApplication);
	SKF_METHOD_BIND_FUNCTION(CloseApplication);
	SKF_METHOD_BIND_FUNCTION_EX(CreateObject,CreateFile);
	SKF_METHOD_BIND_FUNCTION_EX(DeleteObject,DeleteFile);
	SKF_METHOD_BIND_FUNCTION_EX(EnumObjects,EnumFiles);
	SKF_METHOD_BIND_FUNCTION_EX(GetObjectInfo,GetFileInfo);
	SKF_METHOD_BIND_FUNCTION_EX(ReadObject,ReadFile);
	SKF_METHOD_BIND_FUNCTION_EX(WriteObject,WriteFile);
	SKF_METHOD_BIND_FUNCTION(CreateContainer);
	SKF_METHOD_BIND_FUNCTION(DeleteContainer);
	SKF_METHOD_BIND_FUNCTION(EnumContainer);
	SKF_METHOD_BIND_FUNCTION(OpenContainer);
	SKF_METHOD_BIND_FUNCTION(CloseContainer);
	SKF_METHOD_BIND_FUNCTION(GetContainerType);
	SKF_METHOD_BIND_FUNCTION(ImportCertificate);
	SKF_METHOD_BIND_FUNCTION(ExportCertificate);
	SKF_METHOD_BIND_FUNCTION(ExportPublicKey);
	SKF_METHOD_BIND_FUNCTION(GenRandom);
	SKF_METHOD_BIND_FUNCTION(GenExtRSAKey);
	SKF_METHOD_BIND_FUNCTION(GenRSAKeyPair);
	SKF_METHOD_BIND_FUNCTION(ImportRSAKeyPair);
	SKF_METHOD_BIND_FUNCTION(RSASignData);
	SKF_METHOD_BIND_FUNCTION(RSAVerify);
	SKF_METHOD_BIND_FUNCTION(RSAExportSessionKey);
	SKF_METHOD_BIND_FUNCTION(ExtRSAPubKeyOperation);
	SKF_METHOD_BIND_FUNCTION(ExtRSAPriKeyOperation);
	SKF_METHOD_BIND_FUNCTION(GenECCKeyPair);
	SKF_METHOD_BIND_FUNCTION(ImportECCKeyPair);
	SKF_METHOD_BIND_FUNCTION(ECCSignData);
	SKF_METHOD_BIND_FUNCTION(ECCVerify);
	SKF_METHOD_BIND_FUNCTION(ECCExportSessionKey);
	SKF_METHOD_BIND_FUNCTION(ExtECCEncrypt);
	SKF_METHOD_BIND_FUNCTION(ExtECCDecrypt);
	SKF_METHOD_BIND_FUNCTION(ExtECCSign);
	SKF_METHOD_BIND_FUNCTION(ExtECCVerify);
	SKF_METHOD_BIND_FUNCTION(GenerateAgreementDataWithECC);
	SKF_METHOD_BIND_FUNCTION(GenerateAgreementDataAndKeyWithECC);
	SKF_METHOD_BIND_FUNCTION(GenerateKeyWithECC);
	SKF_METHOD_BIND_FUNCTION(ImportSessionKey);
	SKF_METHOD_BIND_FUNCTION(SetSymmKey);
	SKF_METHOD_BIND_FUNCTION(EncryptInit);
	SKF_METHOD_BIND_FUNCTION(Encrypt);
	SKF_METHOD_BIND_FUNCTION(EncryptUpdate);
	SKF_METHOD_BIND_FUNCTION(EncryptFinal);
	SKF_METHOD_BIND_FUNCTION(DecryptInit);
	SKF_METHOD_BIND_FUNCTION(Decrypt);
	SKF_METHOD_BIND_FUNCTION(DecryptUpdate);
	SKF_METHOD_BIND_FUNCTION(DecryptFinal);
	SKF_METHOD_BIND_FUNCTION(DigestInit);
	SKF_METHOD_BIND_FUNCTION(Digest);
	SKF_METHOD_BIND_FUNCTION(DigestUpdate);
	SKF_METHOD_BIND_FUNCTION(DigestFinal);
	SKF_METHOD_BIND_FUNCTION(MacInit);
	SKF_METHOD_BIND_FUNCTION(Mac);
	SKF_METHOD_BIND_FUNCTION(MacUpdate);
	SKF_METHOD_BIND_FUNCTION(MacFinal);
	SKF_METHOD_BIND_FUNCTION(CloseHandle);
#ifdef SKF_HAS_ECCDECRYPT
	SKF_METHOD_BIND_FUNCTION(ECCDecrypt);
#endif

	ret = skf;
	skf = NULL;

end:
	//SKF_METHOD_free(skf);
	return ret;
}

static SKF_ERR_REASON skf_errors[] = {
	{ SAR_OK,			SKF_R_SUCCESS },
	{ SAR_FAIL,			SKF_R_FAILURE },
	{ SAR_UNKNOWNERR,		SKF_R_UNKNOWN_ERROR },
	{ SAR_NOTSUPPORTYETERR,		SKF_R_OPERATION_NOT_SUPPORTED },
	{ SAR_FILEERR,			SKF_R_FILE_ERROR },
	{ SAR_INVALIDHANDLEERR,		SKF_R_INVALID_HANDLE },
	{ SAR_INVALIDPARAMERR,		SKF_R_INVALID_PARAMETER },
	{ SAR_READFILEERR,		SKF_R_READ_FILE_FAILURE },
	{ SAR_WRITEFILEERR,		SKF_R_WRITE_FILE_FAILURE },
	{ SAR_NAMELENERR,		SKF_R_INVALID_NAME_LENGTH },
	{ SAR_KEYUSAGEERR,		SKF_R_INVALID_KEY_USAGE },
	{ SAR_MODULUSLENERR,		SKF_R_INVALID_MODULUS_LENGTH },
	{ SAR_NOTINITIALIZEERR,		SKF_R_NOT_INITIALIZED },
	{ SAR_OBJERR,			SKF_R_INVALID_OBJECT },
	{ SAR_MEMORYERR,		SKF_R_MEMORY_ERROR },
	{ SAR_TIMEOUTERR,		SKF_R_TIMEOUT },
	{ SAR_INDATALENERR,		SKF_R_INVALID_INPUT_LENGTH },
	{ SAR_INDATAERR,		SKF_R_INVALID_INPUT_VALUE },
	{ SAR_GENRANDERR,		SKF_R_RANDOM_GENERATION_FAILED },
	{ SAR_HASHOBJERR,		SKF_R_INVALID_DIGEST_HANDLE },
	{ SAR_HASHERR,			SKF_R_DIGEST_ERROR },
	{ SAR_GENRSAKEYERR,		SKF_R_RSA_KEY_GENERATION_FAILURE },
	{ SAR_RSAMODULUSLENERR,		SKF_R_INVALID_RSA_MODULUS_LENGTH },
	{ SAR_CSPIMPRTPUBKEYERR,	SKF_R_CSP_IMPORT_PUBLIC_KEY_ERROR },
	{ SAR_RSAENCERR,		SKF_R_RSA_ENCRYPTION_FAILURE },
	{ SAR_RSADECERR,		SKF_R_RSA_DECRYPTION_FAILURE },
	{ SAR_HASHNOTEQUALERR,		SKF_R_HASH_NOT_EQUAL },
	{ SAR_KEYNOTFOUNTERR,		SKF_R_KEY_NOT_FOUND },
	{ SAR_CERTNOTFOUNTERR,		SKF_R_CERTIFICATE_NOT_FOUND },
	{ SAR_NOTEXPORTERR,		SKF_R_EXPORT_FAILED },
	{ SAR_DECRYPTPADERR,		SKF_R_DECRYPT_INVALID_PADDING },
	{ SAR_MACLENERR,		SKF_R_INVALID_MAC_LENGTH },
	{ SAR_BUFFER_TOO_SMALL,		SKF_R_BUFFER_TOO_SMALL },
	{ SAR_KEYINFOTYPEERR,		SKF_R_INVALID_KEY_INFO_TYPE },
	{ SAR_NOT_EVENTERR,		SKF_R_NO_EVENT },
	{ SAR_DEVICE_REMOVED,		SKF_R_DEVICE_REMOVED },
	{ SAR_PIN_INCORRECT,		SKF_R_PIN_INCORRECT },
	{ SAR_PIN_LOCKED,		SKF_R_PIN_LOCKED },
	{ SAR_PIN_INVALID,		SKF_R_INVALID_PIN },
	{ SAR_PIN_LEN_RANGE,		SKF_R_INVALID_PIN_LENGTH },
	{ SAR_USER_ALREADY_LOGGED_IN,	SKF_R_USER_ALREADY_LOGGED_IN },
	{ SAR_USER_PIN_NOT_INITIALIZED,	SKF_R_USER_PIN_NOT_INITIALIZED },
	{ SAR_USER_TYPE_INVALID,	SKF_R_INVALID_USER_TYPE },
	{ SAR_APPLICATION_NAME_INVALID, SKF_R_INVALID_APPLICATION_NAME },
	{ SAR_APPLICATION_EXISTS,	SKF_R_APPLICATION_ALREADY_EXIST },
	{ SAR_USER_NOT_LOGGED_IN,	SKF_R_USER_NOT_LOGGED_IN },
	{ SAR_APPLICATION_NOT_EXISTS,	SKF_R_APPLICATION_NOT_EXIST },
	{ SAR_FILE_ALREADY_EXIST,	SKF_R_FILE_ALREADY_EXIST },
	{ SAR_NO_ROOM,			SKF_R_NO_SPACE },
	{ SAR_FILE_NOT_EXIST,		SKF_R_FILE_NOT_EXIST },
};




ULONG SKF_LoadLibrary(LPSTR so_path)
{
	if (!(skf_method = SKF_METHOD_load_library((char *)so_path))) {
		return SAR_FAIL;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_WaitForDevEvent(
	LPSTR szDevName,
	ULONG *pulDevNameLen,
	ULONG *pulEvent)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->WaitForDevEvent) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->WaitForDevEvent(
		szDevName,
		pulDevNameLen,
		pulEvent)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CancelWaitForDevEvent(
	void)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CancelWaitForDevEvent) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_method->CancelWaitForDevEvent) {
		return skf_method->CancelWaitForDevEvent();
	}

	if ((rv = skf_method->CancelWaitForDevEvent()) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumDev(
	BOOL bPresent,
	LPSTR szNameList,
	ULONG *pulSize)
{
	ULONG rv;

				
	// check output of all enum functions !!!!

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumDev) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (szNameList) {
		memset(szNameList, 0, *pulSize);
	}

	if ((rv = skf_method->EnumDev(
		bPresent,
		szNameList,
		pulSize)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ConnectDev(
	LPSTR szName,
	DEVHANDLE *phDev)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ConnectDev) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ConnectDev(
		szName,
		phDev)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DisConnectDev(
	DEVHANDLE hDev)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DisConnectDev) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DisConnectDev(
		hDev)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevState(
	LPSTR szDevName,
	ULONG *pulDevState)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetDevState) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GetDevState(
		szDevName,
		pulDevState)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_SetLabel(
	DEVHANDLE hDev,
	LPSTR szLabel)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->SetLabel) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->SetLabel(
		hDev,
		szLabel)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetDevInfo(
	DEVHANDLE hDev,
	DEVINFO *pDevInfo)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetDevInfo) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	memset(pDevInfo, 0, sizeof(DEVINFO));

	if ((rv = skf_method->GetDevInfo(
		hDev,
		pDevInfo)) != SAR_OK) {
		
		printf("rv = %8x\n", rv);
		return rv;
	}

	if (skf_vendor) {
		pDevInfo->AlgSymCap = skf_vendor->get_cipher_cap(pDevInfo->AlgSymCap);
		pDevInfo->AlgAsymCap = skf_vendor->get_pkey_cap(pDevInfo->AlgAsymCap);
		pDevInfo->AlgHashCap = skf_vendor->get_digest_cap(pDevInfo->AlgHashCap);
		pDevInfo->DevAuthAlgId = skf_vendor->get_cipher_cap(pDevInfo->DevAuthAlgId);
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_LockDev(
	DEVHANDLE hDev,
	ULONG ulTimeOut)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->LockDev) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->LockDev(
		hDev,
		ulTimeOut)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_UnlockDev(
	DEVHANDLE hDev)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->UnlockDev) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->UnlockDev(
		hDev)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Transmit(
	DEVHANDLE hDev,
	BYTE *pbCommand,
	ULONG ulCommandLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Transmit) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Transmit(
		hDev,
		pbCommand,
		ulCommandLen,
		pbData,
		pulDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ChangeDevAuthKey(
	DEVHANDLE hDev,
	BYTE *pbKeyValue,
	ULONG ulKeyLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ChangeDevAuthKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ChangeDevAuthKey(
		hDev,
		pbKeyValue,
		ulKeyLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DevAuth(
	DEVHANDLE hDev,
	BYTE *pbAuthData,
	ULONG ulLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DevAuth) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DevAuth(
		hDev,
		pbAuthData,
		ulLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ChangePIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szOldPin,
	LPSTR szNewPin,
	ULONG *pulRetryCount)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ChangePIN) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ChangePIN(
		hApplication,
		ulPINType,
		szOldPin,
		szNewPin,
		pulRetryCount)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

LONG DEVAPI SKF_GetPINInfo(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	ULONG *pulMaxRetryCount,
	ULONG *pulRemainRetryCount,
	BOOL *pbDefaultPin)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetPINInfo) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GetPINInfo(
		hApplication,
		ulPINType,
		pulMaxRetryCount,
		pulRemainRetryCount,
		pbDefaultPin)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_VerifyPIN(
	HAPPLICATION hApplication,
	ULONG ulPINType,
	LPSTR szPIN,
	ULONG *pulRetryCount)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->VerifyPIN) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->VerifyPIN(
		hApplication,
		ulPINType,
		szPIN,
		pulRetryCount)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_UnblockPIN(
	HAPPLICATION hApplication,
	LPSTR szAdminPIN,
	LPSTR szNewUserPIN,
	ULONG *pulRetryCount)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->UnblockPIN) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->UnblockPIN(
		hApplication,
		szAdminPIN,
		szNewUserPIN,
		pulRetryCount)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ClearSecureState(
	HAPPLICATION hApplication)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ClearSecureState) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ClearSecureState(
		hApplication)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CreateApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	LPSTR szAdminPin,
	DWORD dwAdminPinRetryCount,
	LPSTR szUserPin,
	DWORD dwUserPinRetryCount,
	DWORD dwCreateFileRights,
	HAPPLICATION *phApplication)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CreateApplication) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CreateApplication(
		hDev,
		szAppName,
		szAdminPin,
		dwAdminPinRetryCount,
		szUserPin,
		dwUserPinRetryCount,
		dwCreateFileRights,
		phApplication)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	ULONG *pulSize)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumApplication) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EnumApplication(
		hDev,
		szAppName,
		pulSize)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteApplication(
	DEVHANDLE hDev,
	LPSTR szAppName)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DeleteApplication) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DeleteApplication(
		hDev,
		szAppName)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_OpenApplication(
	DEVHANDLE hDev,
	LPSTR szAppName,
	HAPPLICATION *phApplication)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->OpenApplication) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->OpenApplication(
		hDev,
		szAppName,
		phApplication)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CloseApplication(
	HAPPLICATION hApplication)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CloseApplication) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CloseApplication(
		hApplication)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CreateFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulFileSize,
	ULONG ulReadRights,
	ULONG ulWriteRights)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CreateObject) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CreateObject(
		hApplication,
		szFileName,
		ulFileSize,
		ulReadRights,
		ulWriteRights)) != SAR_OK) {
		

		//LPSTR str = NULL;
		//printf("error = %08X\n", rv);
		//SKF_GetErrorString(rv, &str);
		//printf("error = %s\n", (char *)str);
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DeleteObject) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DeleteObject(
		hApplication,
		szFileName)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumFiles(
	HAPPLICATION hApplication,
	LPSTR szFileList,
	ULONG *pulSize)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumObjects) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EnumObjects(
		hApplication,
		szFileList,
		pulSize)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetFileInfo(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	FILEATTRIBUTE *pFileInfo)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetObjectInfo) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	memset(pFileInfo, 0, sizeof(FILEATTRIBUTE));

	if ((rv = skf_method->GetObjectInfo(
		hApplication,
		szFileName,
		pFileInfo)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ReadFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	ULONG ulSize,
	BYTE *pbOutData,
	ULONG *pulOutLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ReadObject) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ReadObject(
		hApplication,
		szFileName,
		ulOffset,
		ulSize,
		pbOutData,
		pulOutLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_WriteFile(
	HAPPLICATION hApplication,
	LPSTR szFileName,
	ULONG ulOffset,
	BYTE *pbData,
	ULONG ulSize)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->WriteObject) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->WriteObject(
		hApplication,
		szFileName,
		ulOffset,
		pbData,
		ulSize)) != SAR_OK) {
		

		printf("error = %08X\n", rv);

		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CreateContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CreateContainer) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CreateContainer(
		hApplication,
		szContainerName,
		phContainer)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DeleteContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DeleteContainer) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DeleteContainer(
		hApplication,
		szContainerName)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EnumContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	ULONG *pulSize)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EnumContainer) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EnumContainer(
		hApplication,
		szContainerName,
		pulSize)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_OpenContainer(
	HAPPLICATION hApplication,
	LPSTR szContainerName,
	HCONTAINER *phContainer)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->OpenContainer) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->OpenContainer(
		hApplication,
		szContainerName,
		phContainer)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CloseContainer(
	HCONTAINER hContainer)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CloseContainer) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CloseContainer(
		hContainer)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GetContainerType(
	HCONTAINER hContainer,
	ULONG *pulContainerType)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GetContainerType) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GetContainerType(
		hContainer,
		pulContainerType)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportCertificate(
	HCONTAINER hContainer,
	BOOL bExportSignKey,
	BYTE *pbCert,
	ULONG ulCertLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportCertificate) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ImportCertificate(
		hContainer,
		bExportSignKey,
		pbCert,
		ulCertLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExportCertificate(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbCert,
	ULONG *pulCertLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExportCertificate) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExportCertificate(
		hContainer,
		bSignFlag,
		pbCert,
		pulCertLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExportPublicKey(
	HCONTAINER hContainer,
	BOOL bSignFlag,
	BYTE *pbBlob,
	ULONG *pulBlobLen)
{
	ULONG rv;

	// TODO: check the output length, clear the memmory.
	// if pbBlob is NULL, return the length

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExportPublicKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExportPublicKey(
		hContainer,
		bSignFlag,
		pbBlob,
		pulBlobLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenRandom(
	DEVHANDLE hDev,
	BYTE *pbRandom,
	ULONG ulRandomLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenRandom) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GenRandom(
		hDev,
		pbRandom,
		ulRandomLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenExtRSAKey(
	DEVHANDLE hDev,
	ULONG ulBitsLen,
	RSAPRIVATEKEYBLOB *pBlob)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenExtRSAKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GenExtRSAKey(
		hDev,
		ulBitsLen,
		pBlob)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulBitsLen,
	RSAPUBLICKEYBLOB *pBlob)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenRSAKeyPair) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	memset(pBlob, 0, sizeof(RSAPUBLICKEYBLOB));
	if ((rv = skf_method->GenRSAKeyPair(
		hContainer,
		ulBitsLen,
		pBlob)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportRSAKeyPair(
	HCONTAINER hContainer,
	ULONG ulSymAlgId,
	BYTE *pbWrappedKey,
	ULONG ulWrappedKeyLen,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportRSAKeyPair) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulSymAlgId = skf_vendor->get_cipher_algor(ulSymAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->ImportRSAKeyPair(
		hContainer,
		ulSymAlgId,
		pbWrappedKey,
		ulWrappedKeyLen,
		pbEncryptedData,
		ulEncryptedDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_RSASignData(
	HCONTAINER hContainer,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG *pulSignLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->RSASignData) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->RSASignData(
		hContainer,
		pbData,
		ulDataLen,
		pbSignature,
		pulSignLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_RSAVerify(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbSignature,
	ULONG ulSignLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->RSAVerify) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->RSAVerify(
		hDev,
		pRSAPubKeyBlob,
		pbData,
		ulDataLen,
		pbSignature,
		ulSignLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_RSAExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	RSAPUBLICKEYBLOB *pPubKey,
	BYTE *pbData,
	ULONG *pulDataLen,
	HANDLE *phSessionKey)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->RSAExportSessionKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->RSAExportSessionKey(
		hContainer,
		ulAlgId,
		pPubKey,
		pbData,
		pulDataLen,
		phSessionKey)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtRSAPubKeyOperation(
	DEVHANDLE hDev,
	RSAPUBLICKEYBLOB *pRSAPubKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtRSAPubKeyOperation) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtRSAPubKeyOperation(
		hDev,
		pRSAPubKeyBlob,
		pbInput,
		ulInputLen,
		pbOutput,
		pulOutputLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtRSAPriKeyOperation(
	DEVHANDLE hDev,
	RSAPRIVATEKEYBLOB *pRSAPriKeyBlob,
	BYTE *pbInput,
	ULONG ulInputLen,
	BYTE *pbOutput,
	ULONG *pulOutputLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtRSAPriKeyOperation) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtRSAPriKeyOperation(
		hDev,
		pRSAPriKeyBlob,
		pbInput,
		ulInputLen,
		pbOutput,
		pulOutputLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenECCKeyPair(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pBlob)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenECCKeyPair) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_pkey_algor(ulAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	memset(pBlob, 0, sizeof(ECCPUBLICKEYBLOB));
	if ((rv = skf_method->GenECCKeyPair(
		hContainer,
		ulAlgId,
		pBlob)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportECCKeyPair(
	HCONTAINER hContainer,
	ENVELOPEDKEYBLOB *pEnvelopedKeyBlob)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportECCKeyPair) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ImportECCKeyPair(
		hContainer,
		pEnvelopedKeyBlob)) != SAR_OK) {
		
		printf("%s %d: error = %08X\n", __FILE__, __LINE__, rv);
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCSignData(
	HCONTAINER hContainer,
	BYTE *pbDigest,
	ULONG ulDigestLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCSignData) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ECCSignData(
		hContainer,
		pbDigest,
		ulDigestLen,
		pSignature)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCVerify) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ECCVerify(
		hDev,
		pECCPubKeyBlob,
		pbData,
		ulDataLen,
		pSignature)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCExportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pPubKey,
	ECCCIPHERBLOB *pData,
	HANDLE *phSessionKey)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCExportSessionKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->ECCExportSessionKey(
		hContainer,
		ulAlgId,
		pPubKey,
		pData,
		phSessionKey)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ECCDecrypt(
	HCONTAINER hContainer,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ECCDecrypt) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ECCDecrypt(
		hContainer,
		pCipherText,
		pbPlainText,
		pulPlainTextLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCEncrypt(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbPlainText,
	ULONG ulPlainTextLen,
	ECCCIPHERBLOB *pCipherText)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCEncrypt) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCEncrypt(
		hDev,
		pECCPubKeyBlob,
		pbPlainText,
		ulPlainTextLen,
		pCipherText)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCDecrypt(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	ECCCIPHERBLOB *pCipherText,
	BYTE *pbPlainText,
	ULONG *pulPlainTextLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCDecrypt) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCDecrypt(
		hDev,
		pECCPriKeyBlob,
		pCipherText,
		pbPlainText,
		pulPlainTextLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCSign(
	DEVHANDLE hDev,
	ECCPRIVATEKEYBLOB *pECCPriKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCSign) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCSign(
		hDev,
		pECCPriKeyBlob,
		pbData,
		ulDataLen,
		pSignature)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ExtECCVerify(
	DEVHANDLE hDev,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	BYTE *pbData,
	ULONG ulDataLen,
	ECCSIGNATUREBLOB *pSignature)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ExtECCVerify) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->ExtECCVerify(
		hDev,
		pECCPubKeyBlob,
		pbData,
		ulDataLen,
		pSignature)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateAgreementDataWithECC(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phAgreementHandle)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenerateAgreementDataWithECC) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->GenerateAgreementDataWithECC(
		hContainer,
		ulAlgId,
		pTempECCPubKeyBlob,
		pbID,
		ulIDLen,
		phAgreementHandle)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateAgreementDataAndKeyWithECC(
	HANDLE hContainer,
	ULONG ulAlgId,
	ECCPUBLICKEYBLOB *pSponsorECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pSponsorTempECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	BYTE *pbSponsorID,
	ULONG ulSponsorIDLen,
	HANDLE *phKeyHandle)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenerateAgreementDataAndKeyWithECC) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->GenerateAgreementDataAndKeyWithECC(
		hContainer,
		ulAlgId,
		pSponsorECCPubKeyBlob,
		pSponsorTempECCPubKeyBlob,
		pTempECCPubKeyBlob,
		pbID,
		ulIDLen,
		pbSponsorID,
		ulSponsorIDLen,
		phKeyHandle)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_GenerateKeyWithECC(
	HANDLE hAgreementHandle,
	ECCPUBLICKEYBLOB *pECCPubKeyBlob,
	ECCPUBLICKEYBLOB *pTempECCPubKeyBlob,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phKeyHandle)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->GenerateKeyWithECC) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->GenerateKeyWithECC(
		hAgreementHandle,
		pECCPubKeyBlob,
		pTempECCPubKeyBlob,
		pbID,
		ulIDLen,
		phKeyHandle)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_ImportSessionKey(
	HCONTAINER hContainer,
	ULONG ulAlgId,
	BYTE *pbWrapedData,
	ULONG ulWrapedLen,
	HANDLE *phKey)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->ImportSessionKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgId = skf_vendor->get_cipher_algor(ulAlgId))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->ImportSessionKey(
		hContainer,
		ulAlgId,
		pbWrapedData,
		ulWrapedLen,
		phKey)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_SetSymmKey(
	DEVHANDLE hDev,
	BYTE *pbKey,
	ULONG ulAlgID,
	HANDLE *phKey)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->SetSymmKey) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgID = skf_vendor->get_cipher_algor(ulAlgID))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->SetSymmKey(
		hDev,
		pbKey,
		ulAlgID,
		phKey)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM EncryptParam)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EncryptInit) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EncryptInit(
		hKey,
		EncryptParam)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Encrypt(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Encrypt) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Encrypt(
		hKey,
		pbData,
		ulDataLen,
		pbEncryptedData,
		pulEncryptedLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptUpdate(
	HANDLE hKey,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EncryptUpdate) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EncryptUpdate(
		hKey,
		pbData,
		ulDataLen,
		pbEncryptedData,
		pulEncryptedLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_EncryptFinal(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG *pulEncryptedDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->EncryptFinal) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->EncryptFinal(
		hKey,
		pbEncryptedData,
		pulEncryptedDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM DecryptParam)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DecryptInit) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DecryptInit(
		hKey,
		DecryptParam)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Decrypt(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Decrypt) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Decrypt(
		hKey,
		pbEncryptedData,
		ulEncryptedLen,
		pbData,
		pulDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptUpdate(
	HANDLE hKey,
	BYTE *pbEncryptedData,
	ULONG ulEncryptedLen,
	BYTE *pbData,
	ULONG *pulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DecryptUpdate) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DecryptUpdate(
		hKey,
		pbEncryptedData,
		ulEncryptedLen,
		pbData,
		pulDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DecryptFinal(
	HANDLE hKey,
	BYTE *pbDecryptedData,
	ULONG *pulDecryptedDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DecryptFinal) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DecryptFinal(
		hKey,
		pbDecryptedData,
		pulDecryptedDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DigestInit(
	DEVHANDLE hDev,
	ULONG ulAlgID,
	ECCPUBLICKEYBLOB *pPubKey,
	BYTE *pbID,
	ULONG ulIDLen,
	HANDLE *phHash)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DigestInit) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if (skf_vendor) {
		if (!(ulAlgID = skf_vendor->get_digest_algor(ulAlgID))) {
			
				
			return SAR_NOTSUPPORTYETERR;
		}
	}

	if ((rv = skf_method->DigestInit(
		hDev,
		ulAlgID,
		pPubKey,
		pbID,
		ulIDLen,
		phHash)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Digest(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbHashData,
	ULONG *pulHashLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Digest) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Digest(
		hHash,
		pbData,
		ulDataLen,
		pbHashData,
		pulHashLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DigestUpdate(
	HANDLE hHash,
	BYTE *pbData,
	ULONG ulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DigestUpdate) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DigestUpdate(
		hHash,
		pbData,
		ulDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_DigestFinal(
	HANDLE hHash,
	BYTE *pHashData,
	ULONG *pulHashLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->DigestFinal) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->DigestFinal(
		hHash,
		pHashData,
		pulHashLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacInit(
	HANDLE hKey,
	BLOCKCIPHERPARAM *pMacParam,
	HANDLE *phMac)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->MacInit) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->MacInit(
		hKey,
		pMacParam,
		phMac)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_Mac(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen,
	BYTE *pbMacData,
	ULONG *pulMacLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->Mac) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->Mac(
		hMac,
		pbData,
		ulDataLen,
		pbMacData,
		pulMacLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacUpdate(
	HANDLE hMac,
	BYTE *pbData,
	ULONG ulDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->MacUpdate) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->MacUpdate(
		hMac,
		pbData,
		ulDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_MacFinal(
	HANDLE hMac,
	BYTE *pbMacData,
	ULONG *pulMacDataLen)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->MacFinal) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->MacFinal(
		hMac,
		pbMacData,
		pulMacDataLen)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

ULONG DEVAPI SKF_CloseHandle(
	HANDLE hHandle)
{
	ULONG rv;

	if (!skf_method) {
		
			
		return SAR_NOTINITIALIZEERR;
	}

	if (!skf_method->CloseHandle) {
		
			
		return SAR_NOTSUPPORTYETERR;
	}

	if ((rv = skf_method->CloseHandle(
		hHandle)) != SAR_OK) {
		
		return rv;
	}

	return SAR_OK;
}

