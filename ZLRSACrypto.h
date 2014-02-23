//
//  ZLRSACrypto.h
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

#import <Foundation/Foundation.h>
#import <Security/Security.h>

@interface ZLRSACrypto : NSObject

+ (ZLRSACrypto *)crypto;

- (void)generateKeyPair;

- (void)loadPublicKey:(SecKeyRef)publicKeyRef;
- (void)loadPrivateKey:(SecKeyRef)privateKeyRef;
- (void)loadPublicKeyFromData:(NSData *)data;

- (NSData *)encryptData:(NSData *)data;
- (NSData *)decryptData:(NSData *)data;

- (NSData *)publicKeyData;
- (SecKeyRef)publicKeyRef;
- (SecKeyRef)privateKeyRef;

@end
