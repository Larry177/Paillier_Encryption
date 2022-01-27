# Paillier_Encryption
Implement Chinese and English encryption and decryption by using Paillier<br>


Introduction
------------
[Paillier_cryptosysten](https://en.wikipedia.org/wiki/Paillier_cryptosystem)<br><br>

Code
-----
To implement Chinese string encryption and decryption, it is necessary to solve the Chinese transcoding problem:<br>
    
    Chinese---->encode(utf-8)---->encrypt---->decrypt---->decode(utf-8)---->Chinese

First, you should install gmpy2 and libnum<br>
```python
pip install gmpy2
pip install libnum
```
<br>

Ref
----
[Python实现Paillier加密解密算法 - B3ale](https://qianfei11.github.io/2019/10/24/Python%E5%AE%9E%E7%8E%B0Paillier%E5%8A%A0%E5%AF%86%E8%A7%A3%E5%AF%86%E7%AE%97%E6%B3%95/#Getting-started)
