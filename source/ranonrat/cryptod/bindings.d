module ranonrat.cryptod.bindings;
import core.stdc.stdio : FILE;

extern (C)
nothrow:
// aliases?

alias pem_password_cb =
    extern (C) nothrow int function(
        char* buf,
        int size,
        int rwflag,
        void* u
    );

// types
struct EVP_MD;
struct EVP_PKEY_CTX;
struct EVP_PKEY;
struct EVP_CIPHER_CTX;
struct EVP_CIPHER;
struct ENGINE;
struct BIO_METHOD;
struct OSSL_LIB_CTX;
struct BIO;
struct EVP_MD_CTX;
struct OSSL_PARAM;
//
enum int EVP_PKEY_HKDF = 1036;
enum int EVP_CTRL_GCM_SET_IVLEN = 0x9;
enum int EVP_CTRL_GCM_GET_TAG = 0x10;
enum int EVP_PKEY_RSA = 6;
enum int EVP_PKEY_EC = 408;
enum int NID_X9_62_prime256v1 = 415;
enum int EVP_PKEY_NONE = 0;
enum int EVP_CTRL_GCM_SET_TAG = 17; // KEY initialization
enum int BIO_CTRL_INFO = 3;
enum int OPENSSL_LINE = 84;
EVP_MD_CTX* EVP_MD_CTX_new(); // message
int EVP_PKEY_derive_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_derive(EVP_PKEY_CTX* ctx, ubyte* key, size_t* keylen);
EVP_PKEY_CTX* EVP_PKEY_CTX_new_id(int id, ENGINE* e);
EVP_PKEY_CTX* EVP_PKEY_CTX_new(EVP_PKEY* pkey, ENGINE* e);
int EVP_PKEY_keygen_init(EVP_PKEY_CTX* ctx);
int EVP_PKEY_keygen(EVP_PKEY_CTX* ctx, EVP_PKEY** ppkey);
EVP_PKEY_CTX* EVP_PKEY_CTX_new_from_name(OSSL_LIB_CTX* libctx,
    const(char)* name,
    const(char)* propquery);
EVP_PKEY* EVP_PKEY_Q_keygen(OSSL_LIB_CTX* libctx, const(char)* propq,
    const(char)* type, ...);
// encapsulation
int EVP_PKEY_encapsulate_init(EVP_PKEY_CTX* ctx, const(OSSL_PARAM)* params);
int EVP_PKEY_encapsulate(EVP_PKEY_CTX* ctx,
    ubyte* wrappedkey, size_t* wrappedkeylen,
    ubyte* genkey, size_t* genkeylen);

int EVP_PKEY_decapsulate_init(EVP_PKEY_CTX* ctx, const(OSSL_PARAM)* params);
int EVP_PKEY_decapsulate(EVP_PKEY_CTX* ctx,
    ubyte* unwrapped, size_t* unwrappedlen,
    ubyte* wrapped, size_t wrappedlen);
// signing
int EVP_DigestSignInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx,
    const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int EVP_DigestVerifyInit(EVP_MD_CTX* ctx, EVP_PKEY_CTX** pctx,
    const(EVP_MD)* type, ENGINE* e, EVP_PKEY* pkey);
int EVP_DigestSign(EVP_MD_CTX* ctx, ubyte* sig,
    size_t* siglen, const(ubyte)* tbs,
    size_t tbslen);
int EVP_DigestVerify(EVP_MD_CTX* ctx,
    const(ubyte)* sig,
    size_t siglen, const(ubyte)* tbs,
    size_t tbslen);

// eliptic

int EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX* ctx, int nid);

// rsa specific
int EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX* ctx, int mbits);

// PEM
const(BIO_METHOD)* BIO_s_mem();
BIO* BIO_new(const(BIO_METHOD)* type);
int PEM_write_bio_PUBKEY(BIO* bp, const EVP_PKEY* x);

int PEM_write_bio_PrivateKey(BIO* bp, const(EVP_PKEY)* x,
    const(EVP_CIPHER)* enc,
    ubyte* kstr, int klen,
    pem_password_cb cb, void* u);

// fucking shit this is a macro
long BIO_ctrl(BIO* b, int cmd, long larg, void* parg);
long BIO_get_mem_data(BIO* b, char** pp)
{
    return BIO_ctrl(b, BIO_CTRL_INFO, 0, cast(char*)(pp));
}

BIO* BIO_new_mem_buf(const void* buf, int len);

EVP_PKEY* PEM_read_bio_PUBKEY(BIO* pem_string, EVP_PKEY** x,
    pem_password_cb* cb, void* u);
EVP_PKEY* PEM_read_bio_PrivateKey(BIO* bp, EVP_PKEY** x,
    pem_password_cb cb, void* u);

// HKDF specifics
int EVP_PKEY_CTX_set_hkdf_md(EVP_PKEY_CTX* pctx, const(EVP_MD)* md);
int EVP_PKEY_CTX_set1_hkdf_salt(EVP_PKEY_CTX* pctx, ubyte* salt, int saltlen);
int EVP_PKEY_CTX_set1_hkdf_key(EVP_PKEY_CTX* pctx, ubyte* key, int keylen);
int EVP_PKEY_CTX_add1_hkdf_info(EVP_PKEY_CTX* pctx, ubyte* info, int infolen);
// aes
const(EVP_CIPHER)* EVP_aes_256_gcm();
const(EVP_CIPHER)* EVP_aes_256_cbc();
// cypher
EVP_CIPHER_CTX* EVP_CIPHER_CTX_new();
int EVP_EncryptInit_ex(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type, ENGINE* impl,
    const(ubyte)* key, const(ubyte)* iv);

int EVP_DecryptInit_ex(EVP_CIPHER_CTX* ctx, const(EVP_CIPHER)* type,
    ENGINE* impl, const(ubyte)* key, const(ubyte)* iv);
int EVP_CIPHER_CTX_ctrl(EVP_CIPHER_CTX* ctx, int cmd, int p1, void* p2);
int EVP_EncryptUpdate(EVP_CIPHER_CTX* ctx,
    ubyte* out_buf,
    int* outl, const(ubyte)* in_buf, int inl);
int EVP_DecryptUpdate(EVP_CIPHER_CTX* ctx, ubyte* out_buf,
    int* outl, const(ubyte)* in_buf, int inl);

int EVP_EncryptFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* out_buf, int* outl);
int EVP_DecryptFinal_ex(EVP_CIPHER_CTX* ctx, ubyte* outm, int* outl);

// free memory
void EVP_PKEY_CTX_free(EVP_PKEY_CTX* ctx);
void EVP_CIPHER_CTX_free(EVP_CIPHER_CTX* ctx);
void OPENSSL_free(void* addr)
{
    return CRYPTO_free(addr, null, 0);
}

void CRYPTO_free(void* ptr, const char* file, int line);

int BIO_free(BIO* a);
void EVP_MD_CTX_free(EVP_MD_CTX* ctx);
void OPENSSL_cleanse(void* ptr, size_t len);
void EVP_PKEY_free(EVP_PKEY* key);

// alloc 
void* CRYPTO_malloc(size_t num, const char* file, int line);

void* OPENSSL_malloc(size_t num)
{
    return CRYPTO_malloc(num, null, 0);
}

// hashing
const(EVP_MD)* EVP_sha256();

// RAND

int RAND_bytes(ubyte* buf, int num);
// error messaging

void ERR_print_errors_fp(FILE* fp);
char* ERR_error_string(ulong e, char* buf);
void ERR_error_string_n(ulong e, char* buf, size_t len);
ulong ERR_get_error();

// utils

int EVP_PKEY_get_octet_string_param(const(EVP_PKEY)* pkey, const(char)* key_name,
    ubyte* buf, size_t max_buf_sz,
    size_t* out_len);
