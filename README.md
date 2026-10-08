# Cryptod

its a simple library written in D. Its just an abstraction with openssl to be able to achieve the most basic functionality.

It was initially thought to be used for Post quantum algorithms but I considered that It would be a good idea to make it useful for other basic algorithms that I have previously used.

You must have openssl 3.5.1 or more for this project to work.

Here is a simple example

```d

import std.stdio;
import std.digest.sha;
import std.digest : toHexString;
import ranonrat.cryptod;

void main()
{
	// the receiver
	OpenSslKey receiverKey = GenerateMLKemKey(TypeMLkem.ML_KEM_512);
	auto publicPem = receiverKey.publicKeyToPemString();
	// the sender
	OpenSslKey senderKey = GenerateMLKemKey(TypeMLkem.ML_KEM_512);
	senderKey.parsePublicPemString(publicPem); // the sender loads the public key from the
	auto sharedSecretSender = SecureBuffer!ubyte(32, AllocFree.OPENSSL_MALLOC);
	auto cipherText = senderKey.generateSharedSecret(&sharedSecretSender);

	// the receiver gets his cipher text
	auto sharedSecretRec = SecureBuffer!ubyte(32, AllocFree.OPENSSL_MALLOC);
	receiverKey.decryptCipherText(cipherText, &sharedSecretRec);

	writeln("\n\n", toHexString(cipherText), "\n\n");
	// we would be using this with aes
	writeln("sender:   ", toHexString(sharedSecretSender.toBytes()));
	writeln("receiver: ", toHexString(sharedSecretRec.toBytes()));

	string secretMessage = "CONFIDENTIAL very secret information...I watch anime";
	writeln("encrypting the message: \n", secretMessage);
	ubyte[12] iv;
	RAND_bytes(iv.ptr, 12);
	ubyte[16] tag;
	auto encriptedMessage = AESgcmEncrypt(&sharedSecretRec, cast(ubyte[]) secretMessage, null, iv, tag);
	writeln("sending the next package:\n", toHexString(encriptedMessage));
	writeln(encriptedMessage.length);
	auto unencryptedMessage = AESgcmDecrypt(&sharedSecretSender, encriptedMessage, null, iv, tag);

	writeln("decrypted package: \n", toHexString(unencryptedMessage));

	writeln("decrypted message: \n", cast(string)(unencryptedMessage));
}

```

The secure buffer you can define it using 2 different types, depending on what you are trying to do it may be a better idea to use `MALLOC_SECURE` to avoid anyone from scanning the ram in search of any trace.

This may contain some weird bugs, I plan using this library for other projects that I have in mind.
