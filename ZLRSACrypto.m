//
//  ZLRSACrypto.m
//  ZLRSACrypto
//
//  Created by Zebang Liu on 14-02-22.
//  Copyright (c) 2014 Zebang Liu. All rights reserved.
//  Contact: the.great.lzbdd@gmail.com
/*
 This file is part of ZLRSACrypto.
 
 ZLRSACrypto is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.
 
 ZLRSACrypto is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Lesser General Public License for more details.
 
 You should have received a copy of the GNU Lesser General Public License
 along with ZLRSACrypto.  If not, see <http://www.gnu.org/licenses/>.
 */

#import "ZLRSACrypto.h"
#import "RSAESCryptor.h"

const size_t BUFFER_SIZE = 64;
const size_t CIPHER_BUFFER_SIZE = 1024;
const uint32_t PADDING = kSecPaddingNone;
static const UInt8 publicKeyIdentifier[] = "com.zebangliu.ZLRSACrypto.publickey.example";
static const UInt8 privateKeyIdentifier[] = "com.zebangliu.ZLRSACrypto.privatekey.example";

@interface ZLRSACrypto ()

@property (nonatomic) SecKeyRef publicKey;
@property (nonatomic) SecKeyRef privateKey;
@property (nonatomic,strong) NSData *publicTag;
@property (nonatomic,strong) NSData *privateTag;
@property (nonatomic,strong) RSAESCryptor *rsaescryptor;

@end

@implementation ZLRSACrypto

@synthesize publicKey,privateKey,publicTag,privateTag,rsaescryptor;

+ (ZLRSACrypto *)crypto
{
    ZLRSACrypto *crypto = [[ZLRSACrypto alloc]init];
    crypto.rsaescryptor = [RSAESCryptor cryptor];
    crypto.privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    crypto.publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    return crypto;
}

- (void)generateKeyPair
{
    [self generateKeyPair:2048];
    [rsaescryptor loadPublicKey:publicKey];
    [rsaescryptor loadPrivateKey:privateKey];
}

- (void)loadPublicKey:(SecKeyRef)publicKeyRef
{
    publicKey = publicKeyRef;
    [rsaescryptor loadPublicKey:publicKeyRef];
}

- (void)loadPrivateKey:(SecKeyRef)privateKeyRef
{
    privateKey = privateKeyRef;
    [rsaescryptor loadPrivateKey:privateKeyRef];
}

- (void)loadPublicKeyFromData:(NSData *)data
{
    OSStatus sanityCheck = noErr;
    CFArrayRef array;
    SecItemImportExportKeyParameters params;
    
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    // These two values are for import
    params.keyUsage = NULL;
    params.keyAttributes = NULL;
    
    SecExternalFormat format = kSecFormatOpenSSL;
    SecExternalItemType itemtype = kSecItemTypePublicKey;
    
    sanityCheck = SecItemImport((__bridge CFDataRef)data, NULL, &format, &itemtype, kSecItemPemArmour, &params, NULL, &array);
    
    self.publicKey = (__bridge SecKeyRef)([(__bridge NSArray *)array objectAtIndex:0]);
    [rsaescryptor loadPublicKey:self.publicKey];
}

- (NSData *)encryptData:(NSData *)data
{
    return [rsaescryptor encryptData:data];
}

- (NSData *)decryptData:(NSData *)data
{
    return [rsaescryptor decryptData:data];
}

- (NSData *)publicKeyData
{
    OSStatus sanityCheck = noErr;
    CFDataRef data;
    SecItemImportExportKeyParameters params;
    
    params.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    params.flags = 0;
    params.passphrase = NULL;
    params.alertTitle = NULL;
    params.alertPrompt = NULL;
    params.accessRef = NULL;
    // These two values are for import
    params.keyUsage = NULL;
    params.keyAttributes = NULL;
    
    sanityCheck = SecItemExport(publicKey, kSecFormatOpenSSL, kSecItemPemArmour, &params, &data);
    return [NSData dataWithData:(__bridge NSData *)data];
}

- (SecKeyRef)publicKeyRef {
    return publicKey;
}

- (SecKeyRef)privateKeyRef {
    return privateKey;
}

- (void)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    publicKey = NULL;
    privateKey = NULL;
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:@"private"];
    [keyPairAttr setObject:publicKeyAttr forKey:@"public"];
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);

    if(sanityCheck == noErr  && publicKey != NULL && privateKey != NULL)
    {
        //NSLog(@"Successful");
    }
}

@end
