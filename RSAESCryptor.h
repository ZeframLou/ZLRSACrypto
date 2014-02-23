//
//  RSAESCryptor.h
//  RSAESCryptor
//
//  Created by San Chen on 7/15/12.
//  Copyright (c) 2012 Learningtech. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RSAESCryptor : NSObject

+ (RSAESCryptor *)cryptor;

- (void)loadPublicKey:(SecKeyRef)publicKey;
- (NSData *)encryptData:(NSData *)content;

- (void)loadPrivateKey:(SecKeyRef)privateKey;
- (NSData *)decryptData:(NSData *)content;

@end
