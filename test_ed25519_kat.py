import unittest
import binascii
from binascii import hexlify, unhexlify

import ed25519_blake2b


class KnownAnswerTests(unittest.TestCase):
    def test_all(self):
        # kat-ed25519_blake2b-blake2b.txt has been derived from the original
        # kat-ed25519_blake2b.txt sample collection included with the library
        for i,line in enumerate(open("kat-ed25519-blake2b.txt")):
            x = line.split(":")
            A,B,C,D = [unhexlify(i.encode("ascii")) for i in x[:4]]
            # A is the 32 byte seed (the entropy input to H())
            # B is the public point (pubkey)
            # C is the message
            # D is 64 bytes of signature (R+S) prepended to the message

            seed = A
            vk_s = B
            # the NaCl signature is R+S, which happens to be the same as ours
            msg = C
            sig = D[:64]
            # note that R depends only upon the second half of H(seed). S
            # depends upon both the first half (the exponent) and the second
            # half

            #if len(msg) % 16 == 1:
            #    print "msg len = %d" % len(msg), time.time()

            sk = ed25519_blake2b.SigningKey(seed)
            vk = sk.get_verifying_key()
            self.failUnlessEqual(vk.to_bytes(), vk_s)
            vk2 = ed25519_blake2b.VerifyingKey(vk_s)
            self.failUnlessEqual(vk2, vk) # objects should compare equal
            self.failUnlessEqual(vk2.to_bytes(), vk_s)
            newsig = sk.sign(msg)
            sig_R,sig_S = sig[:32],sig[32:]
            newsig_R,newsig_S = newsig[:32],newsig[32:]
            self.failUnlessEqual(hexlify(newsig), hexlify(sig)) # deterministic sigs
            self.failUnlessEqual(vk.verify(sig, msg), None) # no exception


if __name__ == '__main__':
    unittest.main()
