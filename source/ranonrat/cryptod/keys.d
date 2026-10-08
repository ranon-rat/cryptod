module ranonrat.cryptod.keys;
import ranonrat.cryptod.bindings;
import ranonrat.cryptod.openssl;
import ranonrat.cryptod.common;
import core.stdc.string : strlen;
import std.stdio;

// here i should specify the kind of keys that can be created
// here you should be able to use any of these algorithms

// rsa bs
OpenSslKey GenerateRSAKey()
{
    auto pkey = new OpenSslKey();
    auto ctx = new OpenSslKeyCtx();
    ctx.handle = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, null);
    if (!ctx.handle)
        OpenSslReadError();
    if (EVP_PKEY_keygen_init(ctx.handle) <= 0)
        OpenSslReadError();
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.handle, 2048) <= 0)
        OpenSslReadError();

    if (EVP_PKEY_keygen(ctx.handle, &pkey.handle) <= 0)
        OpenSslReadError();
    return pkey;
}
// eqdsa bs
OpenSslKey generateEcKey()
{
    auto pkey = new OpenSslKey();
    auto ctx = new OpenSslKeyCtx();
    ctx.handle = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, null);
    if (ctx.handle)
        OpenSslReadError();

    if (EVP_PKEY_keygen_init(ctx.handle) <= 0)
        OpenSslReadError();

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.handle, NID_X9_62_prime256v1) <= 0)
        OpenSslReadError();

    if (EVP_PKEY_keygen(ctx.handle, &pkey.handle) <= 0)
        OpenSslReadError();
    return pkey;
}
// OQS bs
// Requires the OQS provider to be loaded
// but you should be able to use  "ML-DSA-44", "ML-DSA-65", "ML-DSA-87" 
// without any issue
OpenSslKey GenerateOQSProvider(const(string) alg_name)
{
    auto pkey = new OpenSslKey();
    auto ctx = new OpenSslKeyCtx();
    ctx.handle = EVP_PKEY_CTX_new_from_name(null, alg_name.ptr, null);
    if (!ctx)
        OpenSslReadError();

    if (EVP_PKEY_keygen_init(ctx.handle) <= 0)
        OpenSslReadError();

    if (EVP_PKEY_keygen(ctx.handle, &pkey.handle) <= 0)
        OpenSslReadError();

    return pkey;
}

// this is just some basic MLKem bs that i use to process information
OpenSslKey GenerateMLKemKey(TypeMLkem tAlg)
{
    auto pkey = new OpenSslKey();
    switch (tAlg)
    {
    case TypeMLkem.ML_KEM_512:
        pkey.handle = EVP_PKEY_Q_keygen(null, null, cast(char*) "ML-KEM-512".ptr);
        pkey.cipherTextLength = 768;
        break;
    case TypeMLkem.ML_KEM_768:
        pkey.handle = EVP_PKEY_Q_keygen(null, null, cast(char*) "ML-KEM-768".ptr);
        pkey.cipherTextLength = 1088;
        break;
    case TypeMLkem.ML_KEM_1024:
        pkey.handle = EVP_PKEY_Q_keygen(null, null, cast(char*) "ML-KEM-1024".ptr);
        pkey.cipherTextLength = 1568;
        break;
    default:
        break;
    }

    if (pkey.handle is null)
        OpenSslReadError();
    return pkey;

}
