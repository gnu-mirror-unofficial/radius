#ifndef MD5_H
#define MD5_H

#ifdef __alpha
typedef unsigned int uint32;
#else
typedef unsigned long uint32;
#endif

struct MD5Context {
        uint32 buf[4];
        uint32 bits[2];
        unsigned char in[64];
};

void grad_MD5Init(struct MD5Context *context);
void grad_MD5Update(struct MD5Context *context, unsigned char const *buf,
		    unsigned len);
void grad_MD5Final(unsigned char digest[16], struct MD5Context *context);
void grad_MD5Transform(uint32 buf[4], uint32 const in[16]);
void grad_md5_calc(unsigned char *output, unsigned char *input,
		   unsigned int inlen);

typedef struct MD5Context MD5_CTX;

#endif /* !MD5_H */
