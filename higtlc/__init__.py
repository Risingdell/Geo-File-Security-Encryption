"""HIG-TLC: Hybrid Identity-Geographic Time-Locked Cryptosystem (prototype).

K_file = HKDF(K_R || K_G, policy). K_R is wrapped to the recipient's key;
K_G is held by a Location-Time Authority and released only inside the policy's
zone and time window.
"""
__version__ = "0.1.0"
