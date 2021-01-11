#include <stdio.h>
#include <string.h>
#include <Windows.h>

#include <tchar.h>
//#include "openssl/err.h"
//#include "openssl/gmskf.h"
//#include "skf_int.h"
#include "skf_lib.c"

#define SAR_OK				0x00000000
#define DEVAPI

#define OSSL_NELEM(x)    (sizeof(x)/sizeof(x[0]))
//typedef CHAR *			LPSTR;
//typedef UINT32			ULONG2;

typedef struct {
	ULONG id;
	char *name;
} table_item_t;

static table_item_t skf_cipher_caps[] = {
	{ SGD_SM1_ECB, "sm1-ecb" },
	{ SGD_SM1_CBC, "sm1-cbc" },
	{ SGD_SM1_CFB, "sm1-cfb" },
	{ SGD_SM1_OFB, "sm1-ofb128" },
	{ SGD_SM1_MAC, "cbcmac-sm1" },
	{ SGD_SSF33_ECB, "ssf33-ecb" },
	{ SGD_SSF33_CBC, "ssf33-cbc" },
	{ SGD_SSF33_CFB, "ssf33-cfb" },
	{ SGD_SSF33_OFB, "ssf33-ofb128" },
	{ SGD_SSF33_MAC, "cbcmac-ssf33" },
	{ SGD_SM4_ECB, "sms4-ecb" },
	{ SGD_SM4_CBC, "sms4-cbc" },
	{ SGD_SM4_CFB, "sms4-cfb" },
	{ SGD_SM4_OFB, "sms4-ofb128" },
	{ SGD_SM4_MAC, "cbcmac-sms4" },
	{ SGD_ZUC_EEA3, "zuc_128eea3" },
	{ SGD_ZUC_EIA3, "zuc_128eia3" }
};

static table_item_t skf_digest_caps[] = {
	{ SGD_SM3,  "sm3" },
	{ SGD_SHA1, "sha1" },
	{ SGD_SHA256, "sha256" },
};

static table_item_t skf_pkey_caps[] = {
	{ SGD_RSA_SIGN, "rsa" },
	{ SGD_RSA_ENC, "rsaEncryption" },
	{ SGD_SM2_1, "sm2sign" },
	{ SGD_SM2_2, "sm2exchange" },
	{ SGD_SM2_3, "sm2encrypt" }
};

DEVHANDLE hDev = NULL;
HAPPLICATION hApp = NULL;
HCONTAINER hContainer = NULL;
char devnames[100];
char appnames[100];
char connames[100];

int Ukey_init(char *pin){
    printf("func Ukey_init output:\npin:");
    int i;
    for(i=0; i< 6; i++){
        printf("%c", pin[i]);
    }
    printf("\n");
    int ret = 0;
	BOOL bPresent = TRUE;
	char *nameList = NULL;
    char *applist = NULL;
    char *conlist = NULL;
	ULONG nameListLen, retry_cnt;
    SKF_LoadLibrary(_TEXT("USK218_GM_x64.dll"));
    //printf("ret:%s\n", ret);
    ret = SKF_EnumDev(bPresent, nameList, &nameListLen);
    printf("ret:%s\n", ret);
    nameList = (char *)malloc((size_t)nameListLen);
    ret = SKF_EnumDev(bPresent, nameList, &nameListLen);
    for(i = 0; *nameList; i++){
        devnames[i] = *nameList;
        nameList++;
    }
    devnames[++i] = '\0';
    printf("devnames:%s\n", devnames);
    for(int j=0;j<i;j++) {
        printf("%2x", devnames[j]);
    }
    printf("\n");
    char* a = "UltraSec SMARTCARD READER 0\0";
    printf("a:%s\n", a);
    ret = SKF_ConnectDev(a, &hDev);
    printf("ra:%d\n", ret);
    SKF_EnumApplication(hDev, NULL, &nameListLen);
    applist = (char *)malloc((size_t)nameListLen);
    SKF_EnumApplication(hDev, (LPSTR)applist, &nameListLen);
    for(i = 0; *applist; i++){
        appnames[i] = *applist;
        applist++;
    }
    appnames[++i] = '\0';
    appnames[++i] = '\0';
    printf("appname:%s\n", appnames);
    for(int j=0;j<i;j++) {
        printf("%2x", appnames[j]);
    }
    printf("\n");
    char* b = "BJCA-Application\0";
    printf("b:%s\n", b);
    ret = SKF_OpenApplication(hDev, b, &hApp);
    printf("rb:%d\n", ret);
    SKF_EnumContainer(hApp, NULL, &nameListLen);
    conlist = (char *)malloc((size_t)nameListLen);
    SKF_EnumContainer(hApp, (LPSTR)conlist, &nameListLen);
    for(i = 0; *conlist; i++){
        connames[i] = *conlist;
        conlist++;
    }
    connames[++i] = '\0';
    printf("connames:%s\n", connames);
    char* c = "998000100322438\0";
    printf("c:%s\n", c);
    ret = SKF_OpenContainer(hApp, c, &hContainer);
    printf("rc:%d\n", ret);
    return SKF_VerifyPIN(hApp, USER_TYPE, pin, &retry_cnt);
}

void sign(unsigned char *in, unsigned long inLen, unsigned char *r, unsigned char *s){
    ULONG rv;
    int i;
    printf("func sign output:\n");
    printf("inLen: %lu\n",inLen);
    printf("data in:");
    for(i = 0;i < inLen; i++){
        printf("%02x",in[i]);
    }
    printf("\n");
    ECCSIGNATUREBLOB sig;
    rv = SKF_ECCSignData(hContainer, in, inLen, &sig);
    printf("%lu\n",rv);
    for(i = 0;i < 64; i++){
        r[i] = sig.r[i];
        s[i] = sig.s[i];
    }
    printf("signature r:");
    for (i=0;i<64;i++){
		printf("%02x", sig.r[i]);
	}
    printf("\n");
    printf("signature s:");
    for (i=0;i<64;i++){
		printf("%02x", s[i]);
	}
    printf("\n");
}

unsigned long verify(unsigned char *in, unsigned long inLen, unsigned char *r, unsigned char *s){
    ECCPUBLICKEYBLOB sign_pub;
    ECCSIGNATUREBLOB sig;
    ULONG rv, len;
    int i;
    printf("func verify output:\n");
    printf("inLen: %lu\n",inLen);
    printf("data in:");
    for(i = 0;i < inLen; i++){
        printf("%02x",in[i]);
    }
    printf("\n");
    printf("signature r:");
    for (i=0;i<64;i++){
		printf("%02x", r[i]);
	}
    printf("\n");
    printf("signature s:");
    for (i=0;i<64;i++){
		printf("%02x", s[i]);
	}
	len = sizeof (sign_pub);
    for(i = 0;i < 64; i++){
        sig.r[i] = r[i];
        sig.s[i] = s[i];
    }
    rv = SKF_ExportPublicKey(hContainer, 1, (BYTE *)&sign_pub, &len);
    rv = SKF_ECCVerify(hDev, &sign_pub, in, inLen, &sig);
    return rv;
}
