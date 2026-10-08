module ranonrat.cryptod.openssl;
import ranonrat.cryptod.bindings;
import ranonrat.cryptod.common;
import ranonrat.cryptod.aes;
import std.stdio;

class CreateDestroy(T, alias freer)
{
public:
    T* handle;

    ~this()
    {
        if (handle)
        {
            freer(handle);
            handle = null;
        }
    }
}

void OpenSslReadError()
{

    auto buf = SecureBuffer!char(256, AllocFree.MALLOC);
    ERR_error_string_n(ERR_get_error(), buf.ptr, buf.length);
    if (buf.ptr)
    {
        throw new Exception(cast(string) buf.toBytes());
    }
    throw new Exception("Why was I called?");
}

class OpenSslKey : CreateDestroy!(EVP_PKEY, EVP_PKEY_free)
{

public:
    size_t cipherTextLength = 0;

    // this looks like this for a very simple reason
    // if i am opening the key of another man, I need to have the
    // ciphertextlength to know how big it could be
    // and for that I am managing this
    // if the pem is just opening it I dont want to add extra bs
    this()
    {
    }

    this(TypeMLkem tAlg)
    {
        switch (tAlg)
        {
        case TypeMLkem.ML_KEM_512:
            this.cipherTextLength = 768;
            break;
        case TypeMLkem.ML_KEM_768:
            this.cipherTextLength = 1088;
            break;
        case TypeMLkem.ML_KEM_1024:
            this.cipherTextLength = 1568;
            break;
        default:
            break;
        }
    }

    SecureBuffer!ubyte getParam(string paramName)
    {

        size_t len = 0;
        if (EVP_PKEY_get_octet_string_param(handle, paramName.ptr, null, 0, &len) <= 0)
        {
            throw new Exception("Error getting the size of the parameter: " ~ paramName);
        }

        auto buffer = SecureBuffer!ubyte(len);
        if (EVP_PKEY_get_octet_string_param(handle, paramName.ptr, buffer.ptr, len, &len) <= 0)
        {
            throw new Exception("Error extracting the data from the parameter: " ~ paramName);
        }
        return buffer;
    }
    // this can only occur if the algorithm permits it :)
    // you should send the cipher text
    ubyte[] generateSharedSecret(SecureBuffer!ubyte* key)
    {
        if (this.cipherTextLength == 0)
            throw new Exception("this key does not support encapsulation");
        auto encap_ctx = new OpenSslKeyCtx();
        encap_ctx.handle = EVP_PKEY_CTX_new(this.handle, null);
        if (!encap_ctx.handle)
            OpenSslReadError();
        if (EVP_PKEY_encapsulate_init(encap_ctx.handle, null) <= 0)
            OpenSslReadError();
        auto ciphertext = SecureBuffer!ubyte(this.cipherTextLength, AllocFree.MALLOC);

        auto sharedSecret = SecureBuffer!ubyte(32);
        size_t sharedSecretLen = 32;
        if (EVP_PKEY_encapsulate(encap_ctx.handle,
                ciphertext.ptr, &ciphertext.length,
                sharedSecret.ptr, &sharedSecretLen) <= 0)
            OpenSslReadError();
        // i must return the aes key and the cipher text
        if (HKDFSha256(sharedSecret.ptr, sharedSecretLen, null, "aes-256-gcm key", key))
            return ciphertext.toBytes();
        return null;

    }
    // the shared secret is 32 bytes
    // the key can have any kind of structure From what I know 
    // the garbage collector of d does not necessarely clean the memory completely
    // so for that reason I prefer managing the key through a secure buffer that does not even allow for any copying
    // and when its done it cleans it from the memory.
    void decryptCipherText(ubyte[] ciphertext, SecureBuffer!ubyte* key)
    {
        if (cipherTextLength == 0)
            throw new Exception("this key does not support encapsulation");

        auto decap_ctx = new OpenSslKeyCtx();
        decap_ctx.handle = EVP_PKEY_CTX_new(this.handle, null);
        if (decap_ctx.handle is null)
            OpenSslReadError();

        if (EVP_PKEY_decapsulate_init(decap_ctx.handle, null) <= 0)
            OpenSslReadError();

        auto sharedSecret = SecureBuffer!ubyte(32);
        size_t sharedSecretLen = sharedSecret.length;

        if (EVP_PKEY_decapsulate(decap_ctx.handle,
                sharedSecret.ptr, &sharedSecretLen,
                ciphertext.ptr, ciphertext.length) <= 0)
            OpenSslReadError();
        // why i am doing this?

        HKDFSha256(sharedSecret.ptr, sharedSecretLen, null, "aes-256-gcm key", key);
    }

    ubyte[] signMessage(const(ubyte)[] msg)
    {
        auto mdCtx = new OpenSslMdCTX();

        size_t sig_len = 0;
        mdCtx.handle = EVP_MD_CTX_new();

        if (!mdCtx.handle)
            OpenSslReadError();
        if (EVP_DigestSignInit(mdCtx.handle, null, null, null, this.handle) <= 0)
            OpenSslReadError();
        if (EVP_DigestSign(mdCtx.handle, null, &sig_len, msg.ptr, msg.length) <= 0)
            OpenSslReadError();
        auto sig = SecureBuffer!ubyte(sig_len, AllocFree.OPENSSL_MALLOC);
        if (sig.length == 0)
            OpenSslReadError();
        if (EVP_DigestSign(mdCtx.handle, sig.ptr, &sig_len, msg.ptr, msg.length) <= 0)
            OpenSslReadError();
        return sig.toBytes();

    }

    bool verifyMessage(const(ubyte)[] msg, const(ubyte)[] sig)
    {

        auto mdCtx = new OpenSslMdCTX();
        mdCtx.handle = EVP_MD_CTX_new();
        if (!mdCtx.handle)
            OpenSslReadError();
        if (EVP_DigestVerifyInit(mdCtx.handle, null, null, null, this.handle) <= 0)
            OpenSslReadError();
        auto ret = EVP_DigestVerify(mdCtx.handle, sig.ptr, sig.length, msg.ptr, msg.length);
        if (ret == 1)
            return true;
        return false;

    }

    string publicKeyToPemString()
    {
        auto bio = new OpenSslBio();
        bio.handle = BIO_new(BIO_s_mem());

        if (!bio)
            OpenSslReadError();
        if (PEM_write_bio_PUBKEY(bio.handle, this.handle) != 1)
            OpenSslReadError();
        auto pemData = SecureBuffer!char(0, AllocFree.MALLOC);
        pemData.changeSize(BIO_get_mem_data(bio.handle, &pemData.ptr));
        if (pemData.length <= 0 || !pemData.ptr)
            OpenSslReadError();
        string outstr = cast(string) pemData.toBytes();
        return outstr;

    }

    // the password i guess that it would be cleaned but maybe i should manage this through a secure buffer?
    string privateKeyToPemString(const string password)
    {
        auto bio = new OpenSslBio();
        bio.handle = BIO_new(BIO_s_mem());
        if (!bio)
            OpenSslReadError();
        if (PEM_write_bio_PrivateKey(bio.handle, this.handle, EVP_aes_256_cbc(),
                cast(ubyte*) password.ptr, cast(int) password.length,
                null, null) != 1)
            OpenSslReadError();
        auto pemData = SecureBuffer!char(0, AllocFree.MALLOC);
        pemData.changeSize(BIO_get_mem_data(bio.handle, &pemData.ptr));
        if (pemData.length <= 0 || !pemData.ptr)
            OpenSslReadError();

        string outstr = cast(string) pemData.toBytes();
        return outstr;
    }

    void parsePublicPemString(const string pemString)
    {
        auto bio = new OpenSslBio();
        bio.handle = BIO_new_mem_buf(pemString.ptr, -1);
        if (!bio.handle)
            OpenSslReadError();
        this.handle = PEM_read_bio_PUBKEY(bio.handle, null, null, null);
        if (!this.handle)
            OpenSslReadError();

    }

    void parsePrivatePemString(const string pemString, const string password)
    {
        OpenSslBio bio;
        bio.handle = BIO_new_mem_buf(pemString.ptr, -1);
        if (!bio.handle)
            return;
        this.handle = PEM_read_bio_PrivateKey(bio.handle, null, null, cast(void*) password.ptr);
        if (!this.handle)
            OpenSslReadError();
    }

}

class OpenSslMdCTX : CreateDestroy!(EVP_MD_CTX, EVP_MD_CTX_free)
{

}

class OpenSslCipherCtx : CreateDestroy!(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free)
{
}

class OpenSslKeyCtx : CreateDestroy!(EVP_PKEY_CTX, EVP_PKEY_CTX_free)
{

}

class OpenSslBio : CreateDestroy!(BIO, BIO_free)
{
}
