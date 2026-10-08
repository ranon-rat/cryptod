module ranonrat.cryptod.common;
import ranonrat.cryptod.bindings;

import core.stdc.stdlib : free, malloc;

struct SecureBuffer(T = ubyte)
{

    T* ptr;
    size_t length;
    AllocFree tAlloc;

    this(size_t size, AllocFree talloc = AllocFree.MALLOC, bool allocNow = false)
    {

        this.length = size;
        this.tAlloc = talloc;
        if (size > 0 || allocNow)
        {
            if (this.tAlloc == AllocFree.OPENSSL_MALLOC)
                this.ptr = cast(T*) OPENSSL_malloc(size);
            else
                this.ptr = cast(T*) malloc(size);
        }
    }

    void changeSize(size_t new_size)
    {
        this.length = new_size;
    }
    // there is some buffer which i must handle it in this specific way
    // its because of the message scanning, this is just an abstraction that saves me time
    T[] toBytes()
    {
        T[] output = this.ptr[0 .. this.length].dup;
        return output;
    }

    @disable this(this);
    ~this()
    {
        if (ptr is null)
        {
            if (this.tAlloc != AllocFree.MALLOC)
                OPENSSL_cleanse(ptr, length);
            free(ptr); // siempre free, porque siempre reservaste con malloc
            ptr = null;
            length = 0;

        }
    }

}

enum AllocFree
{

    OPENSSL_MALLOC,
    MALLOC_SECURE,
    MALLOC

}

enum TypeMLkem
{
    ML_KEM_768,
    ML_KEM_512,
    ML_KEM_1024,

}
