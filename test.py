import unittest
import hashlib

import hash

class sha1Test(unittest.TestCase):

    def test_oneBlockMessage(self):
        message = "abc"
        messageHash = hash.sha1(message)
        print("SHA-1(", message, ")= ", "{:x}".format(messageHash))
        self.assertEqual(messageHash, 0xa9993e364706816aba3e25717850c26c9cd0d89d)

    def test_multiBlockMessage(self):
        message = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        messageHash = hash.sha1(message)
        print("SHA-1(", message, ")= ", "{:x}".format(messageHash))
        self.assertEqual(messageHash, 0x84983e441c3bd26ebaae4aa1f95129e5e54670f1)

    def test_longMessage(self):
        message = "a" * 1000000
        messageHash = hash.sha1(message)
        print("SHA-1(long message)= ", "{:x}".format(messageHash))
        self.assertEqual(messageHash, 0x34aa973cd4c4daa4f61eeb2bdbad27316534016f)

    def test_builtinHash(self):
        message = "sdf sdf sdf sdfy29387r23en ioasdu naijds 839e niasd niaushd32r237 asdasn"
        messageHash = hash.sha1(message)
        print("SHA-1(", message, ")= ", "{:x}".format(messageHash))
        self.assertEqual("{:x}".format(messageHash), hashlib.sha1(bytes(message, "utf-8")).hexdigest())

if __name__ == '__main__':
    unittest.main()
