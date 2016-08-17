ZLRSACrypto
===========

ZLRSACrypto is an easy-to-use RSA library with many utility functions.

###Encryption and decryption without key files
ZLRSACrypto allows you to generate keypairs and use them instantly,instead of dealing with files.

###SecKeyRef to NSData,and the other way around
I've never found a working implementation for this function online,so I whiped up my own.This function comes in handy when you want to transfer RSA keys between different devices.

###Simple API
I'm not exactly a security expert,so the API is pretty simple,as long as you know what public and private keys are,you can use it.
