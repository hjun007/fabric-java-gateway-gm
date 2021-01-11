#include "skfdll.h"

int main(){
    char *pin = "111111";
    BYTE in[32] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    unsigned long inLen;
    BYTE r[64],s[64];
    int i, res;
    Ukey_init(pin);
    //LoadLibrary(_TEXT("ukey.dll"));
    inLen = sizeof (in) / sizeof (BYTE);
    sign(in, inLen, r, s);
    /*
    for (i=0;i<32;i++){
		printf("%02x", s[i]);
	}
	printf("\n");
    */
    res = verify(in, inLen, r, s);
    if(res == 0){
        printf("verify success\n");
    }
}