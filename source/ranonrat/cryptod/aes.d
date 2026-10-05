module ranonrat.cryptod.aes;

import ranonrat.cryptod.openssl;
import ranonrat.cryptod.common;
import ranonrat.cryptod.bindings;

ubyte[] AESgcmEncrypt(
    SecureBuffer!(ubyte)* key,
    ubyte[] plaintext,
    SecureBuffer!(ubyte)* aad,
    ubyte[12] iv, ubyte[16] tag)
{
    // the iv and the tag work for salting this stupid shit and doing the ciphering 
    // i want to kill 908042 people
    auto ciphertext = SecureBuffer!ubyte(0, AllocFree.MALLOC_SECRET);

    int len = 0;
    OpenSslCipherCtx ctx;
    ctx.handle = EVP_CIPHER_CTX_new();
    if (ctx.handle)
        return null;
    if (1 != EVP_EncryptInit_ex(ctx.handle, EVP_aes_256_gcm(), null, null, null))
        return null;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_SET_IVLEN, 16, null))
        return null;
    if (1 != EVP_EncryptInit_ex(ctx.handle, null, null, key.ptr, iv.ptr))
        return null;
    if (aad.length > 0)
    {
        if (1 != EVP_EncryptUpdate(ctx.handle, null, &len, aad.ptr, cast(int) aad.length))
            return null;

    }
    if (plaintext)
    {
        if (1 != EVP_EncryptUpdate(ctx.handle, ciphertext.ptr, &len,
                plaintext.ptr, cast(int) plaintext.length))
            return null;
    }
    if (1 != EVP_EncryptFinal_ex(ctx.handle, ciphertext.ptr + len, &len))
        return null;
    if (1 != EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_GET_TAG, 16, tag.ptr))
        return null;

    ciphertext.changeSize(len);
    return ciphertext.toBytes();

}

ubyte[] decrypt(SecureBuffer!(ubyte)* key, ubyte[] ciphertext, ubyte[] aad, ubyte[16] tag, ubyte[12] iv)
{
    OpenSslCipherCtx ctx;
    auto plaintext = SecureBuffer!ubyte(0, AllocFree.MALLOC);
    int len = 0, ret;
    ctx.handle = EVP_CIPHER_CTX_new();
    if (!ctx.handle)
        return null;
    if (!EVP_DecryptInit_ex(ctx.handle, EVP_aes_256_gcm(), null, null, null))
        return null;
    if (!EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_SET_IVLEN, 16, null))
        return null;
    if (!EVP_DecryptInit_ex(ctx.handle, null, null, key.ptr, iv.ptr))
        return null;

    if (aad.length > 0)
    {
        if (!EVP_DecryptUpdate(ctx.handle, null, &len, aad.ptr, cast(int) aad.length))
            return null;
    }
    if (ciphertext)
    {
        if (!EVP_DecryptUpdate(ctx.handle, plaintext.ptr, &len,
                ciphertext.ptr, cast(int) ciphertext.length))
            return null;
    }
    if (!EVP_CIPHER_CTX_ctrl(ctx.handle, EVP_CTRL_GCM_SET_TAG, 16, tag.ptr))
        return null;
    ret = EVP_DecryptFinal_ex(ctx.handle, plaintext.ptr + len, &len);
    if (ret <= 0)
        return null;
    plaintext.changeSize(len);
    return plaintext.toBytes();

} // here the ikm would be the shared secret, the key is the generated buffer
bool HKDFSha256(ubyte* ikm, size_t ikm_len, ubyte[] salt, string info, SecureBuffer!ubyte* key)
{
    assert(info.length > 0);
    OpenSslKeyCtx pctx;
    pctx.handle = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, null);
    if (!pctx)
        return false;
    if (EVP_PKEY_derive_init(pctx.handle) <= 0)
        return false;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx.handle, EVP_sha256()) <= 0)
        return false;
    if (salt.length > 0 &&
        EVP_PKEY_CTX_set1_hkdf_salt(pctx.handle, salt.ptr, cast(int) salt.length) <= 0)
        return false;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx.handle, ikm, cast(int) ikm_len) <= 0)
        return false;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx.handle, cast(ubyte*) info.ptr,
            cast(int) info.length) <= 0)
        return false;

    size_t len = key.length;
    if (EVP_PKEY_derive(pctx.handle, key.ptr, &len) <= 0)
        return false;

    return true;
}
