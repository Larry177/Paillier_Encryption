#paillier公钥加密算法 基于加法的同态加密
# encoding:utf-8
from sys import platlibdir
import gmpy2 as gy
import random
import time
import libnum
from ast import literal_eval
import binascii

class Paillier(object):
    def __init__(self, pubKey=None, priKey=None):
        self.pubKey = pubKey
        self.priKey = priKey

    def __gen_prime__(self, rs):
        p = gy.mpz_urandomb(rs, 1024)
        while not gy.is_prime(p):
            p += 1
        return p
    
    def __L__(self, x, n):
        res = gy.div((x - 1), n)
        return res
    
    def __key_gen__(self):
        # generate random state
        while True:
            rs = gy.random_state(int(time.time()))
            p = self.__gen_prime__(rs)
            q = self.__gen_prime__(rs)
            n = p * q
            lmd =(p - 1) * (q - 1)
            if gy.gcd(n, lmd) == 1:
                break
        g = n + 1
        mu = gy.invert(lmd, n)
        self.pubKey = [n, g]
        self.priKey = [lmd, mu]
        return
        
    def decipher(self, ciphertext):
        n, g = self.pubKey
        lmd, mu = self.priKey
        m =  self.__L__(gy.powmod(ciphertext, lmd, n ** 2), n) * mu % n
        plaintext = libnum.n2s(int(m))
        return plaintext

    def encipher(self, plaintext):
        m = libnum.s2n(plaintext)
        n, g = self.pubKey
        r = gy.mpz_random(gy.random_state(int(time.time())), n)
        while gy.gcd(n, r)  != 1:
            r += 1
        ciphertext = gy.powmod(g, m, n ** 2) * gy.powmod(r, n, n ** 2) % (n ** 2)
        return ciphertext

    def is_chinese(self,word):
        for ch in word:
            if '\u4e00' <= ch <= '\u9fff':
                return True
        return False

    def to_unicode(self,string):
        ret = ''
        for v in string:
            ret = ret + hex(ord(v)).upper().replace('0X', '\\u')
        return ret

if __name__ == "__main__":
    pai = Paillier()
    pai.__key_gen__()
    pubKey = pai.pubKey
    print("Public/Private key generated.")
    #print(pubKey)
    #plaintext = input("Input text: ")
    plaintext = '测试！'

    if pai.is_chinese(plaintext):
        plaintext = str(plaintext.encode('utf-8'))[2:-1]
        print("Original text:", plaintext)
        ciphertext = pai.encipher(plaintext)
        print("Ciphertext:", ciphertext)
        deciphertext = pai.decipher(ciphertext)
        print("Deciphertext: ", literal_eval("b'{}'".format(deciphertext)).decode('utf-8'))

    else:
        print("Original text:", plaintext)
        ciphertext = pai.encipher(plaintext)
        print("Ciphertext:", ciphertext)
        deciphertext = pai.decipher(ciphertext)
        print("Deciphertext: ", deciphertext)
    
