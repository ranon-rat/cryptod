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
