#ifndef crypto_sign_edwards25519blake2bbatch_H
#define crypto_sign_edwards25519blake2bbatch_H

#define SECRETKEYBYTES 32
#define PUBLICKEYBYTES 32
#define SIGNATUREBYTES 64

extern int crypto_sign(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_open(unsigned char *,unsigned long long *,const unsigned char *,unsigned long long,const unsigned char *);
extern int crypto_sign_keypair(unsigned char *,unsigned char *);
extern int crypto_sign_publickey(unsigned char *pk, unsigned char *sk, unsigned char *seed);
extern int derive_public_from_secret(unsigned char *pk, const unsigned char *sk);

#endif
