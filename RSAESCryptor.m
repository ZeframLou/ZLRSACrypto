//
//  RSAESCryptor.m
//  RSAESCryptor
//
//  Created by San Chen on 7/15/12.
//  Copyright (c) 2012 Learningtech. All rights reserved.
//

#import "RSAESCryptor.h"
#import "NSData+CommonCrypto.h"
#import <Security/Security.h>

@interface RSAESCryptor()
{
    SecKeyRef _publicKeyRef;
    SecKeyRef _privateKeyRef;
}
+ (NSData *)randomDataOfLength:(size_t)length;
- (NSData *)generateKey;
- (NSData *)generateIV;
- (NSData *)wrapSymmetricKey:(NSData *)symmetricKey keyRef:(SecKeyRef)publicKey;
- (NSData *)unwrapSymmetricKey:(NSData *)wrappedSymmetricKey keyRef:(SecKeyRef)privateKey;

@end

@implementation RSAESCryptor

+ (RSAESCryptor *)cryptor
{
    RSAESCryptor *cryptor = [[RSAESCryptor alloc] init];
    return cryptor;
}

#pragma mark -
+ (NSData *)randomDataOfLength:(size_t)length
{
    NSMutableData *data = [NSMutableData dataWithLength:length];
    int result = SecRandomCopyBytes(NULL, length, data.mutableBytes);
    NSAssert(result == 0, @"Unable to generate random bytes: %d", errno);
    
    return data;
}

- (NSData *)generateKey {
    return [[self class] randomDataOfLength:kCCKeySizeAES256];
}

- (NSData *)generateIV {
    return [[self class] randomDataOfLength:kCCBlockSizeAES128];
}

- (NSData *)wrapSymmetricKey:(NSData *)symmetricKey keyRef:(SecKeyRef)publicKey {
	size_t keyBufferSize = [symmetricKey length];	
	size_t cipherBufferSize = SecKeyGetBlockSize(publicKey);
    
    NSMutableData *cipher = [NSMutableData dataWithLength:cipherBufferSize];
	OSStatus sanityCheck = SecKeyEncrypt(publicKey,
                                         kSecPaddingPKCS1,
                                         (const uint8_t *)[symmetricKey bytes],
                                         keyBufferSize,
                                         cipher.mutableBytes,
                                         &cipherBufferSize);
    NSAssert(sanityCheck == noErr, @"Error encrypting, OSStatus == %d.", sanityCheck);
    [cipher setLength:cipherBufferSize];
    
    return cipher;
}

- (NSData *)unwrapSymmetricKey:(NSData *)wrappedSymmetricKey keyRef:(SecKeyRef)privateKey {
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKey);
    size_t keyBufferSize = [wrappedSymmetricKey length];

    NSMutableData *key = [NSMutableData dataWithLength:keyBufferSize];
    OSStatus sanityCheck = SecKeyDecrypt(privateKey,
                                         kSecPaddingPKCS1,
                                         (const uint8_t *) [wrappedSymmetricKey bytes],
                                         cipherBufferSize,
                                         [key mutableBytes],
                                         &keyBufferSize);
    NSAssert(sanityCheck == noErr, @"Error decrypting, OSStatus == %d.", sanityCheck);
    [key setLength:keyBufferSize];

    return key;
}

#pragma mark -

- (void)loadPublicKey:(SecKeyRef)publicKey
{
    _publicKeyRef = publicKey;
}

- (void)loadPrivateKey:(SecKeyRef)privateKey
{
    _privateKeyRef = privateKey;
}

- (NSData *)encryptData:(NSData *)content {
    NSData *aesKey = [self generateKey];
    NSData *iv = [self generateIV];
    NSData *encryptedData = [content AES256EncryptedDataUsingKey:aesKey andIV:iv error:nil];
    // encrypt aesKey with publicKey
    NSData *encryptedAESKey = [self wrapSymmetricKey:aesKey keyRef:_publicKeyRef];
    
    NSMutableData *result = [NSMutableData data];
    [result appendData:iv];
    [result appendData:encryptedAESKey];
    [result appendData:encryptedData];
    return result;
}

- (NSData *)decryptData:(NSData *)content {
    NSData *iv = [content subdataWithRange:NSMakeRange(0, 16)];
    NSData *wrappedSymmetricKey = [content subdataWithRange:NSMakeRange(16, 256)];
    NSData *encryptedData = [content subdataWithRange:NSMakeRange(272, [content length] - 272)];
    
    // decrypt wrappedSymmetricKey with privateKey
    NSData *key = [self unwrapSymmetricKey:wrappedSymmetricKey keyRef:_privateKeyRef];
        
    return [encryptedData decryptedAES256DataUsingKey:key andIV:iv error:nil];
}

#pragma mark -
- (void)releaseSecVars {
    if (_publicKeyRef) CFRelease(_publicKeyRef);
    if (_privateKeyRef) CFRelease(_privateKeyRef);
}

- (void)dealloc {
    [self releaseSecVars];
}

@end
