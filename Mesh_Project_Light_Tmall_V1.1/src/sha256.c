#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "sha256.h"


#define SHA256_ROTL(a,b) (((a>>(32-b))&(0x7fffffff>>(31-b)))|(a<<b))
#define SHA256_SR(a,b) ((a>>b)&(0x7fffffff>>(b-1)))
#define SHA256_Ch(x,y,z) ((x&y)^((~x)&z))
#define SHA256_Maj(x,y,z) ((x&y)^(x&z)^(y&z))
#define SHA256_E0(x) (SHA256_ROTL(x,30)^SHA256_ROTL(x,19)^SHA256_ROTL(x,10))
#define SHA256_E1(x) (SHA256_ROTL(x,26)^SHA256_ROTL(x,21)^SHA256_ROTL(x,7))
#define SHA256_O0(x) (SHA256_ROTL(x,25)^SHA256_ROTL(x,14)^SHA256_SR(x,3))
#define SHA256_O1(x) (SHA256_ROTL(x,15)^SHA256_ROTL(x,13)^SHA256_SR(x,10))

#define rightrotate(w, n) ((w >> n) | (w) << (32-(n)))
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define copy_uint32(p, val) *((uint32_t *)p) = __builtin_bswap32((val))
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define copy_uint32(p, val) *((uint32_t *)p) = (val)
#else
#error "Unsupported target architecture endianess!"
#endif

static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void swap32(uint8_t dst[4], const uint8_t src[4])
{   
    int i;
    for (i = 0; i < 4; i++)
        dst[3 - i] = src[i];
}

static void swap48(uint8_t dst[4], const uint8_t src[6])
{  
    int i;
    for (i = 0; i < 6; i++)
        dst[5 - i] = src[i];
}

const char num2char[] = "0123456789abcdef";

static void create_sha256_input_string(unsigned char *p_input, uint8_t *pid, uint8_t *p_mac, uint8_t *p_secret)
{
	uint8_t idx =0;
	uint8_t con_product_id_rev[4];
	swap32(con_product_id_rev,pid);
	
	for(int i=0;i<4;i++){
		p_input[idx++] = num2char [(con_product_id_rev[i]>>4) & 15];
		p_input[idx++] = num2char [ con_product_id_rev[i] & 15];
	}
	p_input[idx++]=',';
	for(int i=0;i<6;i++){
		p_input[idx++] = num2char [(p_mac[i]>>4) & 15];
		p_input[idx++] = num2char [ p_mac[i] & 15];
	}
	p_input[idx++]=',';
/*#if(MESH_USER_DEFINE_MODE == MESH_CLOUD_ENABLE)
	memcpy(p_input + idx, con_sec_data, strlen((char *)con_sec_data));
	idx += strlen((char *)con_sec_data);
#else	*/
	for(int i=0;i<16;i++){// need to change to string .
		p_input[idx++] = num2char [(p_secret[i]>>4) & 15];
		p_input[idx++] = num2char [p_secret[i] & 15];
	}
//#endif
}

static void sha256(uint8_t *data, size_t len, uint8_t *out) {
    uint32_t h0 = 0x6a09e667;
    uint32_t h1 = 0xbb67ae85;
    uint32_t h2 = 0x3c6ef372;
    uint32_t h3 = 0xa54ff53a;
    uint32_t h4 = 0x510e527f;
    uint32_t h5 = 0x9b05688c;
    uint32_t h6 = 0x1f83d9ab;
    uint32_t h7 = 0x5be0cd19;
    int r = (int)(len * 8 % 512);
    int append = ((r < 448) ? (448 - r) : (448 + 512 - r)) / 8;
    size_t new_len = len + append + 8;
    unsigned char buf[new_len];
    memset(buf + len, 0, append);
    if (len > 0) {
        memcpy(buf, data, len);
    }
    buf[len] = (unsigned char)0x80;
    uint64_t bits_len = len * 8;
    for (int i = 0; i < 8; i++) {
        buf[len + append + i] = (bits_len >> ((7 - i) * 8)) & 0xff;
    }
    uint32_t w[64];
    memset(w, 0, 64);
    size_t chunk_len = new_len / 64;
    for (int idx = 0; idx < chunk_len; idx++) {
        uint32_t val = 0;
        for (int i = 0; i < 64; i++) {
            val =  val | (*(buf + idx * 64 + i) << (8 * (3 - i)));
            if (i % 4 == 3) {
                w[i / 4] = val;
                val = 0;
            }
        }
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = rightrotate(w[i - 15], 7) ^ rightrotate(w[i - 15], 18) ^ (w[i - 15] >> 3);
            uint32_t s1 = rightrotate(w[i - 2], 17) ^ rightrotate(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        uint32_t f = h5;
        uint32_t g = h6;
        uint32_t h = h7;
        for (int i = 0; i < 64; i++) {
            uint32_t s_1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            uint32_t ch = (e & f) ^ (~e & g);
            uint32_t temp1 = h + s_1 + ch + k[i] + w[i];
            uint32_t s_0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
            uint32_t temp2 = s_0 + maj;
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }
    /*copy_uint32(out, h0);
    copy_uint32(out + 4,  h1);
    copy_uint32(out + 8,  h2);
    copy_uint32(out + 12, h3);
    copy_uint32(out + 16, h4);
    copy_uint32(out + 20, h5);
    copy_uint32(out + 24, h6);
    copy_uint32(out + 28, h7);*/
		
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h0 : 0x%08X  \n", h0);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h1 : 0x%08X  \n", h1);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h2 : 0x%08X  \n", h2);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h3 : 0x%08X  \n", h3);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h4 : 0x%08X  \n", h4);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h5 : 0x%08X  \n", h5);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h6 : 0x%08X  \n", h6);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " h7 : 0x%08X  \n", h7);
		
		uint32_t Retult[8] = { h0, h1, h2, h3, h4, h5, h6, h7 };
		
		uint8_t y = 0;
    
    for( uint8_t i = 0; i < 8 ; i++ )
    {
    	y=0;
    	for(; y < 4 ; y++)
    	 {
    		 *(out + (i*4 + (3-y))) = (uint8_t)(Retult[i] >> (8*(y)));
		   }
	  }
    
    //sprintf((char*)out, "%08X%08X%08X%08X%08X%08X%08X%08X", h0, h1, h2, h3, h4, h5, h6, h7);
}


static char* StrSHA256(const char* str, long long length, char* sha256)
{
    /*
    计算字符串SHA-256
    参数说明：
    str         字符串指针
    length      字符串长度
    sha256         用于保存SHA-256的字符串指针
    返回值为参数sha256
    */
    char *pp, *ppend;
    long l, i, W[64], T1, T2, A, B, C, D, E, F, G, H, H0, H1, H2, H3, H4, H5, H6, H7;
    H0 = 0x6a09e667, H1 = 0xbb67ae85, H2 = 0x3c6ef372, H3 = 0xa54ff53a;
    H4 = 0x510e527f, H5 = 0x9b05688c, H6 = 0x1f83d9ab, H7 = 0x5be0cd19;
    long K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    };
    l = length + ((length % 64 >= 56) ? (128 - length % 64) : (64 - length % 64));
    if (!(pp = (char*)malloc((unsigned long)l))) return 0;
    for (i = 0; i < length; pp[i + 3 - 2 * (i % 4)] = str[i], i++);
    for (pp[i + 3 - 2 * (i % 4)] = 128, i++; i < l; pp[i + 3 - 2 * (i % 4)] = 0, i++);
    *((long*)(pp + l - 4)) = length << 3;
    *((long*)(pp + l - 8)) = length >> 29;
    for (ppend = pp + l; pp < ppend; pp += 64){
        for (i = 0; i < 16; W[i] = ((long*)pp)[i], i++);
        for (i = 16; i < 64; W[i] = (SHA256_O1(W[i - 2]) + W[i - 7] + SHA256_O0(W[i - 15]) + W[i - 16]), i++);
        A = H0, B = H1, C = H2, D = H3, E = H4, F = H5, G = H6, H = H7;
        for (i = 0; i < 64; i++){
            T1 = H + SHA256_E1(E) + SHA256_Ch(E, F, G) + K[i] + W[i];
            T2 = SHA256_E0(A) + SHA256_Maj(A, B, C);
            H = G, G = F, F = E, E = D + T1, D = C, C = B, B = A, A = T1 + T2;
        }
        H0 += A, H1 += B, H2 += C, H3 += D, H4 += E, H5 += F, H6 += G, H7 += H;
    }
    free(pp - l);
		
		/*__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H0 : 0x%08X  \n", H0);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H1 : 0x%08X  \n", H1);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H2 : 0x%08X  \n", H2);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H3 : 0x%08X  \n", H3);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H4 : 0x%08X  \n", H4);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H5 : 0x%08X  \n", H5);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H6 : 0x%08X  \n", H6);
		__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " H7 : 0x%08X  \n", H7);*/
		
		uint32_t Retult[8] = { H0, H1, H2, H3, H4, H5, H6, H7 };
		
		uint8_t y = 0;
    
    for( uint8_t i = 0; i < 8 ; i++ )
    {
    	y=0;
    	for(; y < 4 ; y++)
    	 {
    		 *(sha256 + (i*4 + (3-y))) = (uint8_t)(Retult[i] >> (8*(y)));
		   }
	  }
    
    //sprintf(sha256, "%08X%08X%08X%08X%08X%08X%08X%08X", H0, H1, H2, H3, H4, H5, H6, H7);
    return sha256;
}

void Create_Static_OOB_AuthValue(uint8_t *AuthValue, uint8_t *pid, const uint8_t *con_mac_address, uint8_t *p_secret)
{
	uint8_t sha256_out[32];
	uint8_t sha256_in[54];
	uint8_t mac_address_sha256[6];
	
	__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " Start SHA256 Calculation  \n");
	
	swap48(mac_address_sha256,con_mac_address); 
	
	create_sha256_input_string(sha256_in, pid, mac_address_sha256, p_secret);   //连接字符串
	
	__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " sha256_in : %s  \n", sha256_in);
	
	//sha256(sha256_in, 54, sha256_out) ;  //函数1不成功   与在线检验的不同  后期需改进
	
	StrSHA256(sha256_in , 54, sha256_out);   //函数2   成功！
	
	memcpy(AuthValue, sha256_out , 16);
	
	/*__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " sha256_out : 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  \n", 
																			 sha256_out[0], sha256_out[1],
																			 sha256_out[2], sha256_out[3],
																			 sha256_out[4], sha256_out[5],
																			 sha256_out[6], sha256_out[7],
																			 sha256_out[8], sha256_out[9],
																			 sha256_out[10],sha256_out[11],
																			 sha256_out[12],sha256_out[13],
																			 sha256_out[15],sha256_out[15]);*/
																			 
		/*__LOG(LOG_SRC_APP, LOG_LEVEL_INFO, " AuthValue : 0x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x  \n", 
																			 AuthValue[0], AuthValue[1],
																			 AuthValue[2], AuthValue[3],
																			 AuthValue[4], AuthValue[5],
																			 AuthValue[6], AuthValue[7],
																			 AuthValue[8], AuthValue[9],
																			 AuthValue[10],AuthValue[11],
																			 AuthValue[12],AuthValue[13],
																			 AuthValue[14],AuthValue[15]);*/
}