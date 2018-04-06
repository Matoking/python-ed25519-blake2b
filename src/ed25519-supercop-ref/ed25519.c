#include "crypto_sign.h"

#include "crypto_verify_32.h"
#include "blake2.h"

#include "ge25519.h"

static void get_hram(unsigned char *hram, const unsigned char *sm, const unsigned char *pk, unsigned char *playground, unsigned long long smlen)
{
  unsigned long long i;

  for (i =  0;i < 32;++i)    playground[i] = sm[i];
  for (i = 32;i < 64;++i)    playground[i] = pk[i-32];
  for (i = 64;i < smlen;++i) playground[i] = sm[i];

  crypto_hash_blake2b(hram,playground,smlen);
}


int crypto_sign_publickey(
    unsigned char *pk,  // write 32 bytes into this
    unsigned char *sk,  // write 32 bytes into this
    unsigned char *seed // 32 bytes
    )
{
  sc25519 scsk;
  ge25519 gepk;
  int i;
  unsigned char d[64];

  crypto_hash_blake2b(d, seed, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  sc25519_from32bytes(&scsk,d);

  ge25519_scalarmult_base(&gepk, &scsk);
  ge25519_pack(pk, &gepk);
  for(i=0;i<32;i++)
    sk[i] = seed[i];
  return 0;
}

int derive_public_from_secret(
    unsigned char *pk,
    const unsigned char *sk
    )
{
  sc25519 scsk;
  ge25519 gepk;

  unsigned char d[64];

  crypto_hash_blake2b(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  sc25519_from32bytes(&scsk,d);

  ge25519_scalarmult_base(&gepk, &scsk);
  ge25519_pack(pk, &gepk);

  return 0;
}

int crypto_sign(
    unsigned char *sm,unsigned long long *smlen,
    const unsigned char *m,unsigned long long mlen,
    const unsigned char *sk
    )
{
  sc25519 sck, scs, scsk;
  ge25519 ger;
  unsigned char r[32];
  unsigned char s[32];
  unsigned char extsk[64];
  unsigned long long i;
  unsigned char hmg[crypto_hash_blake2b_BYTES];
  unsigned char hram[crypto_hash_blake2b_BYTES];
  unsigned char pk[32];

  derive_public_from_secret(pk, sk);

  crypto_hash_blake2b(extsk, sk, 32);
  extsk[0] &= 248;
  extsk[31] &= 127;
  extsk[31] |= 64;

  *smlen = mlen+64;
  for(i=0;i<mlen;i++)
    sm[64 + i] = m[i];
  for(i=0;i<32;i++)
    sm[32 + i] = extsk[32+i];

  crypto_hash_blake2b(hmg, sm+32, mlen+32); /* Generate k as h(extsk[32],...,extsk[63],m) */

  /* Computation of R */
  sc25519_from64bytes(&sck, hmg);
  ge25519_scalarmult_base(&ger, &sck);
  ge25519_pack(r, &ger);

  /* Computation of s */
  for(i=0;i<32;i++)
    sm[i] = r[i];

  get_hram(hram, sm, pk, sm, mlen+64);

  sc25519_from64bytes(&scs, hram);
  sc25519_from32bytes(&scsk, extsk);
  sc25519_mul(&scs, &scs, &scsk);

  sc25519_add(&scs, &scs, &sck);

  sc25519_to32bytes(s,&scs); /* cat s */
  for(i=0;i<32;i++)
    sm[32 + i] = s[i];

  return 0;
}

int crypto_sign_open(
    unsigned char *m,unsigned long long *mlen,
    const unsigned char *sm,unsigned long long smlen,
    const unsigned char *pk
    )
{
  int i, ret;
  unsigned char t2[32];
  ge25519 get1, get2;
  sc25519 schram, scs;
  unsigned char hram[crypto_hash_blake2b_BYTES];

  get_hram(hram,sm,pk+32,m,smlen);
  if (ge25519_unpackneg_vartime(&get1, pk)) {
      return -1;
  }

  get_hram(hram,sm,pk,m,smlen);

  sc25519_from64bytes(&schram, hram);

  sc25519_from32bytes(&scs, sm+32);

  ge25519_double_scalarmult_vartime(&get2, &get1, &schram, &ge25519_base, &scs);
  ge25519_pack(t2, &get2);

  ret = crypto_verify_32(sm, t2);

  if (!ret)
  {
    for(i=0;i<smlen-64;i++)
      m[i] = sm[i + 64];
    *mlen = smlen-64;
  }
  else
  {
    for(i=0;i<smlen-64;i++)
      m[i] = 0;
    *mlen = (unsigned long long) -1;
  }
  return ret;
}
