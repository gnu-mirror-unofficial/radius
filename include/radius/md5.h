#ifndef GRAD_MD5_H
#define GRAD_MD5_H

struct MD5Context {
        uint32_t buf[4];
        uint32_t bits[2];
        unsigned char in[64];
};

void grad_MD5Init(struct MD5Context *context);
void grad_MD5Update(struct MD5Context *context, unsigned char const *buf,
		    unsigned len);
void grad_MD5Final(unsigned char digest[16], struct MD5Context *context);
void grad_MD5Transform(uint32_t buf[4], uint32_t const in[16]);
void grad_md5_calc(unsigned char *output, unsigned char *input,
		   unsigned int inlen);

typedef struct MD5Context MD5_CTX;

#endif /* !MD5_H */
