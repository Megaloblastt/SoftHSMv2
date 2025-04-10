/*
 * Copyright (c) 2010 SURFnet bv
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*****************************************************************************
 OSSLMPCECDSA.cpp

 OpenSSL ECDSA asymmetric algorithm implementation
 *****************************************************************************/

#include "config.h"
#ifdef WITH_ECC
#include "log.h"
#include "OSSLMPCECDSA.h"
#include "CryptoFactory.h"
#include "ECParameters.h"
#include "OSSLECKeyPair.h"
#include "OSSLComp.h"
#include "OSSLUtil.h"
#include <algorithm>
#include <iostream>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#ifdef WITH_FIPS
#include <openssl/fips.h>
#endif
#include <string.h>


#include "OSSLMPCECDSA_mpclib_wrapper.h"

class MPCECDSA_CMP_Handler {
public:

private:

};

// Constructor
OSSLMPCECDSA::OSSLMPCECDSA() {
    // TODO initialize storage for key / signing persistency
}

static players_setup_info players;
char keyid[37] = {0};
elliptic_curve256_point_t pubkey;

// Key factory
bool OSSLMPCECDSA::generateKeyPair(AsymmetricKeyPair** ppKeyPair, AsymmetricParameters* parameters, RNG* /*rng = NULL */)
{
	std::cerr << "*****************************************" << std::endl;
	std::cerr << "*  This is the inner KeyGen function  ! *" << std::endl;
	std::cerr << "*****************************************" << std::endl;
	// Check parameters
	if ((ppKeyPair == NULL) ||
	    (parameters == NULL))
	{
		return false;
	}

	if (!parameters->areOfType(ECParameters::type))
	{
		ERROR_MSG("Invalid parameters supplied for ECDSA key generation");

		return false;
	}

	// MPC generation
	{
		uuid_t uid;
		uuid_generate_random(uid);
		uuid_unparse(uid, keyid);
		players.clear();
		players[1];
		players[2];
		std::cerr << " => Launch of the MPC generation from mpc-lib: " << std::endl;
		// TODO - extract the constant ECDSA_xxx from the AsymmetricParameters* parameters
		create_secret(players, ECDSA_SECP256R1, keyid, pubkey);
		std::cerr << " => Launch of the MPC generation from mpc-lib: DONE" << std::endl;
	}


	ECParameters* params = (ECParameters*) parameters;

	// Generate the key-pair
	EC_KEY* eckey = EC_KEY_new();
	if (eckey == NULL)
	{
		ERROR_MSG("Failed to instantiate OpenSSL ECDSA object");

		return false;
	}

	EC_GROUP* grp = OSSL::byteString2grp(params->getEC());
	EC_KEY_set_group(eckey, grp);
	EC_GROUP_free(grp);

	if (!EC_KEY_oct2key(eckey, pubkey, sizeof(elliptic_curve256_point_t), NULL))
	{
		ERROR_MSG("ECDSA failed to set public key (0x%08X)", ERR_get_error());

		EC_KEY_free(eckey);

		return false;
	}

	if (!EC_KEY_oct2priv(eckey, (uint8_t*) keyid, 31))
	{
		ERROR_MSG("ECDSA failed to set private key (0x%08X)", ERR_get_error());

		EC_KEY_free(eckey);

		return false;
	}

	// Create an asymmetric key-pair object to return
	OSSLECKeyPair* kp = new OSSLECKeyPair();

	((OSSLECPublicKey*) kp->getPublicKey())->setFromOSSL(eckey);
	((OSSLECPrivateKey*) kp->getPrivateKey())->setFromOSSL(eckey);

	*ppKeyPair = kp;

	// Release the key
	EC_KEY_free(eckey);

	return true;
}

// Signing functions
bool OSSLMPCECDSA::sign(PrivateKey* privateKey, const ByteString& dataToSign,
		     ByteString& signature, const AsymMech::Type mechanism,
		     const void* /* param = NULL */, const size_t /* paramLen = 0 */)
{
	if (mechanism != AsymMech::MPCECDSA)
	{
		ERROR_MSG("Invalid mechanism supplied (%i)", mechanism);
		return false;
	}

	// Check if the private key is the right type
	if (!privateKey->isOfType(OSSLECPrivateKey::type))
	{
		ERROR_MSG("Invalid key type supplied");

		return false;
	}

	OSSLECPrivateKey* pk = (OSSLECPrivateKey*) privateKey;

	// Perform the signature operation
	size_t len = pk->getOrderLength();
	if (len == 0)
	{
		ERROR_MSG("Could not get the order length");
		return false;
	}
	signature.resize(2 * len);
	memset(&signature[0], 0, 2 * len);
	ecdsa_sign(players, ECDSA_SECP256R1, dataToSign.const_byte_str(), dataToSign.size(), signature, keyid);

	return true;
}

bool OSSLMPCECDSA::signInit(PrivateKey* /*privateKey*/, const AsymMech::Type /*mechanism*/,
			 const void* /*param*/, const size_t /*paramLen*/)
{
	ERROR_MSG("MPCECDSA does not support multi part signing");

	return false;
}

bool OSSLMPCECDSA::signUpdate(const ByteString& /*dataToSign*/)
{
	ERROR_MSG("MPCECDSA does not support multi part signing");

	return false;
}

bool OSSLMPCECDSA::signFinal(ByteString& /*signature*/)
{
	ERROR_MSG("MPCECDSA does not support multi part signing");

	return false;
}

// Verification functions
bool OSSLMPCECDSA::verify(PublicKey* publicKey, const ByteString& originalData,
		       const ByteString& signature, const AsymMech::Type mechanism,
		       const void* param, const size_t paramLen)
{
	return SuperClass::verify(publicKey, originalData, signature, mechanism, param, paramLen);
}

bool OSSLMPCECDSA::verifyInit(PublicKey* publicKey, const AsymMech::Type mechanism,
			   const void* param, const size_t paramLen)
{
	return SuperClass::verifyInit(publicKey, mechanism, param, paramLen);
}

bool OSSLMPCECDSA::verifyUpdate(const ByteString& originalData)
{
	return SuperClass::verifyUpdate(originalData);
}

bool OSSLMPCECDSA::verifyFinal(const ByteString& signature)
{
	return SuperClass::verifyFinal(signature);
}

// Encryption functions
bool OSSLMPCECDSA::encrypt(PublicKey* publicKey, const ByteString& data,
			ByteString& encryptedData, const AsymMech::Type padding)
{
	return SuperClass::encrypt(publicKey, data, encryptedData, padding);
}

// Decryption functions
bool OSSLMPCECDSA::decrypt(PrivateKey* privateKey, const ByteString& encryptedData,
			ByteString& data, const AsymMech::Type padding)
{
	return SuperClass::decrypt(privateKey, encryptedData, data, padding);
}



unsigned long OSSLMPCECDSA::getMinKeySize()
{
	// Smallest EC group supported by MPC ECDSA is Stark curve
	return 252;
}

unsigned long OSSLMPCECDSA::getMaxKeySize()
{
	// Biggest EC group is secp256r1
	return 256;
}

bool OSSLMPCECDSA::reconstructKeyPair(AsymmetricKeyPair** ppKeyPair, ByteString& serialisedData)
{
	return SuperClass::reconstructKeyPair(ppKeyPair,  serialisedData);
}

bool OSSLMPCECDSA::reconstructPublicKey(PublicKey** ppPublicKey, ByteString& serialisedData)
{
	return SuperClass::reconstructPublicKey(ppPublicKey, serialisedData);
}

bool OSSLMPCECDSA::reconstructPrivateKey(PrivateKey** ppPrivateKey, ByteString& serialisedData)
{
	return SuperClass::reconstructPrivateKey(ppPrivateKey, serialisedData);
}

PublicKey* OSSLMPCECDSA::newPublicKey()
{
	return (PublicKey*) new OSSLECPublicKey();
}

PrivateKey* OSSLMPCECDSA::newPrivateKey()
{
	return (PrivateKey*) new OSSLECPrivateKey();
}

AsymmetricParameters* OSSLMPCECDSA::newParameters()
{
	return (AsymmetricParameters*) new ECParameters();
}

bool OSSLMPCECDSA::reconstructParameters(AsymmetricParameters** ppParams, ByteString& serialisedData)
{
	return SuperClass::reconstructParameters(ppParams, serialisedData);
}
#endif
