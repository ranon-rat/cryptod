module ranonrat.cryptod.aes;

import ranonrat.cryptod.openssl;
import ranonrat.cryptod.common;
import ranonrat.cryptod.bindings;

import std.stdio;

ubyte[] AESgcmEncrypt(
    SecureBuffer!(ubyte)* key,
    ubyte[] plaintext,
    SecureBuffer!(ubyte)* aad,
    ref ubyte[12] iv, ref ubyte[16] tag)
{
    // the iv and the tag work for salting this stupid shit and doing the ciphering 
    // i want to kill 908042 people
    auto ciphertext = SecureBuffer!ubyte(plaintext.length, AllocFree.MALLOC_SECURE);
    int ciphertextLen = 0;

    int len = 0;
    auto ctx = new OpenSslCipherCtx();
    ctx.handle = EVP_CIPHER_CTX_new();

    if (!ctx.handle)
        return null;
    if (1 != EVP_EncryptInit_ex(ctx.handle, EVP_aes_256_gcm(), null, null, null))
    {
        OpenSslReadError();
        return null;
    }

    if (1 != EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_SET_IVLEN, 12, null))
    {
        OpenSslReadError();
        return null;
    }

    if (1 != EVP_EncryptInit_ex(ctx.handle, null, null, key.ptr, iv.ptr))
    {
        OpenSslReadError();
        return null;
    }
    if (aad !is null && aad.length > 0)
    {
        if (1 != EVP_EncryptUpdate(ctx.handle, null, &len, aad.ptr, cast(int) aad.length))
        {
            OpenSslReadError();
            return null;
        }

    }
    if (plaintext)
    {
        if (1 != EVP_EncryptUpdate(ctx.handle, ciphertext.ptr, &len,
                plaintext.ptr, cast(int) plaintext.length))
        {
            OpenSslReadError();
            return null;
        }
        ciphertextLen = len;
    }
    if (1 != EVP_EncryptFinal_ex(ctx.handle, ciphertext.ptr + len, &len))
    {

        OpenSslReadError();
        return null;
    }
    ciphertextLen += len;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_GET_TAG, 16, tag.ptr))
    {

        OpenSslReadError();
        return null;
    }

    ciphertext.changeSize(ciphertextLen);

    return ciphertext.toBytes();

}

ubyte[] AESgcmDecrypt(SecureBuffer!(ubyte)* key, ubyte[] ciphertext, ubyte[] aad, ref ubyte[12] iv, ref ubyte[16] tag,)
{
    auto ctx = new OpenSslCipherCtx();
    auto plaintext = SecureBuffer!ubyte(ciphertext.length + 1, AllocFree.MALLOC);
    int total = 0, len = 0, ret;
    ctx.handle = EVP_CIPHER_CTX_new();
    if (!ctx.handle)
    {
        OpenSslReadError();
        return null;
    }
    if (!EVP_DecryptInit_ex(ctx.handle, EVP_aes_256_gcm(), null, null, null))
    {
        OpenSslReadError();
        return null;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_SET_IVLEN, 12, null))
    {
        OpenSslReadError();
        return null;
    }
    if (!EVP_DecryptInit_ex(ctx.handle, null, null, key.ptr, iv.ptr))
    {

        OpenSslReadError();
        return null;
    }

    if (aad.length > 0)
    {
        if (!EVP_DecryptUpdate(ctx.handle, null, &len, aad.ptr, cast(int) aad.length))
        {
            OpenSslReadError();
            return null;
        }
    }

    if (ciphertext)
    {
        if (!EVP_DecryptUpdate(ctx.handle, plaintext.ptr, &len,
                ciphertext.ptr, cast(int) ciphertext.length))
        {
            OpenSslReadError();
            return null;
        }
    }
    total = len;
    if (!EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_SET_TAG, 16, tag.ptr))
    {

        OpenSslReadError();
    }
    ret = EVP_DecryptFinal_ex(ctx.handle, plaintext.ptr + len, &len);
    if (ret <= 0)
    {
        OpenSslReadError();
        return null;
    }
    total += len;
    plaintext.changeSize(total);
    return plaintext.toBytes();

} // here the ikm would be the shared secret, the key is the generated buffer
bool HKDFSha256(ubyte* ikm, size_t ikm_len, ubyte[] salt, string info, SecureBuffer!ubyte* key)
{
    assert(info.length > 0);
    auto pctx = new OpenSslKeyCtx();
    pctx.handle = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);
    if (!pctx)
    {
        OpenSslReadError();
        return false;
    }
    if (EVP_PKEY_derive_init(pctx.handle) <= 0)
    {
        OpenSslReadError();
        return false;
    }
    if (EVP_PKEY_CTX_set_hkdf_md(pctx.handle, EVP_sha256()) <= 0)
    {
        OpenSslReadError();
        return false;
    }
    if (salt.length > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx.handle, salt.ptr, cast(int) salt.length) <= 0)
    {
        OpenSslReadError();
        // i should handle this through exceptions but rn not needed
        return false;
    }
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx.handle, ikm, cast(int) ikm_len) <= 0)
    {
        OpenSslReadError();
        return false;
    }
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx.handle, cast(ubyte*) info.ptr,
            cast(int) info.length) <= 0)
    {
        OpenSslReadError();
        return false;
    }
    size_t len = key.length;
    if (EVP_PKEY_derive(pctx.handle, key.ptr, &len) <= 0)
    {
        OpenSslReadError();
        return false;
    }
    return true;
}
