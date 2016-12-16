
// License: MIT License
// http://www.opensource.org/licenses/mit-license.php

// SMHasher code is from SMHasher project, authored by Austin Appleby, et al.
// http://code.google.com/p/smhasher/

// Python extension code by Patrick Hensley


#include <Python.h>
#include "MurmurHash3.h"
#include "PMurHash.h"
#include "PMurHash128.h"


#if PY_VERSION_HEX < 0x02050000
typedef int Py_ssize_t;
#define PY_SSIZE_T_MAX INT_MAX
#define PY_SSIZE_T_MIN INT_MIN
#endif

#if defined(_MSC_VER)
  #define FORCE_INLINE  __forceinline
#else
  #define FORCE_INLINE inline __attribute__((always_inline))
#endif
const union {
  uint8_t u8[2];
  uint16_t u16;
} EndianMix = {{ 1, 0 }};
FORCE_INLINE bool IsBigEndian()
{
  // Constant-folded by the compiler.
  return EndianMix.u16 != 1;
}

static PyObject *
_py_murmur3_128(PyObject *self, PyObject *args, int x86, int size)
{
    const char *key;
    Py_ssize_t len;
    uint32_t seed = 0;
    unsigned char out[16];

    if (!PyArg_ParseTuple(args, "s#|I", &key, &len, &seed)) {
        return NULL;
    }

    if (x86) {
        MurmurHash3_x86_128((void *)key, len, seed, &out);
    } else {
        MurmurHash3_x64_128((void *)key, len, seed, &out);
    }

    return _PyLong_FromByteArray((const unsigned char *)&out, size, 0, 0);
}


static PyObject *
py_murmur3_x86_64(PyObject *self, PyObject *args)
{
    return _py_murmur3_128(self, args, 1, 8);
}


static PyObject *
py_murmur3_x64_64(PyObject *self, PyObject *args)
{
    return _py_murmur3_128(self, args, 0, 8);
}


static PyObject *
py_murmur3_x86_128(PyObject *self, PyObject *args)
{
    return _py_murmur3_128(self, args, 1, 16);
}


static PyObject *
py_murmur3_x64_128(PyObject *self, PyObject *args)
{
    return _py_murmur3_128(self, args, 0, 16);
}

static PyObject *
py_pmurhash32_process(PyObject *self, PyObject *args)
{
    const char *key;
    Py_ssize_t len;
    uint32_t seed = 0;
    uint32_t carry = 0;
    if (!PyArg_ParseTuple(args, "IIs#", &seed, &carry, &key, &len)) {
        return NULL;
    }
    PMurHash32_Process(&seed, &carry, key, len);
    return PyTuple_Pack(
        2,
        PyLong_FromLong(seed),
        PyLong_FromLong(carry)
    );
}

static PyObject *
py_pmurhash32_result(PyObject *self, PyObject *args)
{
    uint32_t seed, carry, len;
    if (!PyArg_ParseTuple(args, "III", &seed, &carry, &len)) {
        return NULL;
    }
    return PyLong_FromLong(PMurHash32_Result(seed, carry, len));
}

static PyObject *
py_pmurhash128_process(PyObject *self, PyObject *args)
{
    const char *key;
    Py_ssize_t len;
    PyObject *seed_obj, *carry_obj;

    if (!PyArg_ParseTuple(args, "OOs#", &seed_obj, &carry_obj, &key, &len)) {
        return NULL;
    }

    uint64_t carry[2];
    uint64_t seed[2];
    int err;

#if PY_MAJOR_VERSION <= 2
    if (PyInt_Check(seed_obj)) {
        seed[0] = PyInt_AsUnsignedLongLongMask(seed_obj);
        seed[1] = 0;
    } else if (PyLong_Check(seed_obj)) {
        err = _PyLong_AsByteArray((PyLongObject*)seed_obj, (unsigned char *)seed, sizeof(seed), !IsBigEndian(), 0);
        if (err) return NULL;
    } else {
        return NULL;
    }

    if (PyInt_Check(carry_obj)) {
        carry[0] = PyInt_AsUnsignedLongLongMask(carry_obj);
        carry[1] = 0;
    } else if (PyLong_Check(carry_obj)) {
        err = _PyLong_AsByteArray((PyLongObject*)carry_obj, (unsigned char *)carry, sizeof(carry), !IsBigEndian(), 0);
        if (err) return NULL;
    } else {
        return NULL;
    }
#else
    if (!PyLong_Check(seed_obj) || !PyLong_Check(carry_obj)) {
        return NULL;
    }
    err = _PyLong_AsByteArray((PyLongObject*)seed_obj, (unsigned char *)seed, sizeof(seed), !IsBigEndian(), 0);
    if (err) return NULL;
    err = _PyLong_AsByteArray((PyLongObject*)carry_obj, (unsigned char *)carry, sizeof(carry), !IsBigEndian(), 0);
    if (err) return NULL;
#endif

    PMurHash128_Process(seed, carry, key, len);

    return PyTuple_Pack(
        2,
        _PyLong_FromByteArray((unsigned char *)seed, sizeof(seed), !IsBigEndian(), 0),
        _PyLong_FromByteArray((unsigned char *)carry, sizeof(carry), !IsBigEndian(), 0)
    );
}

static PyObject *
py_pmurhash128_result(PyObject *self, PyObject *args)
{
    const char *key;
    uint32_t len;
    PyObject *seed_obj, *carry_obj;

    if (!PyArg_ParseTuple(args, "OOI", &seed_obj, &carry_obj, &key, &len)) {
        return NULL;
    }
    if (!PyLong_Check(seed_obj) || !PyLong_Check(carry_obj)) {
        return NULL;
    }

    uint64_t carry[2];
    uint64_t seed[2];
    uint64_t out[2];
    int err;

    err = _PyLong_AsByteArray((PyLongObject*)seed_obj, (unsigned char *)seed, sizeof(seed), !IsBigEndian(), 0);
    if (err) return NULL;

    err = _PyLong_AsByteArray((PyLongObject*)carry_obj, (unsigned char *)carry, sizeof(carry), !IsBigEndian(), 0);
    if (err) return NULL;

    PMurHash128_Result(seed, carry, len, out);

    return _PyLong_FromByteArray((unsigned char *)out, sizeof(out), !IsBigEndian(), 0);
}


PyDoc_STRVAR(module_doc, "Python wrapper for the SMHasher routines.");

static PyMethodDef smhasher_methods[] = {
    {"murmur3_x86_64", py_murmur3_x86_64, METH_VARARGS,
        "Make an x86 murmur3 64-bit hash value"},
    {"murmur3_x64_64", py_murmur3_x64_64, METH_VARARGS,
        "Make an x64 murmur3 64-bit hash value"},

    {"murmur3_x86_128", py_murmur3_x86_128, METH_VARARGS,
        "Make an x86 murmur3 128-bit hash value"},
    {"murmur3_x64_128", py_murmur3_x64_128, METH_VARARGS,
        "Make an x64 murmur3 128-bit hash value"},

    {"pmurhash32_process", py_pmurhash32_process, METH_VARARGS,
        "Incrementally process some data in pmurhash32"},
    {"pmurhash32_result", py_pmurhash32_result, METH_VARARGS,
        "Return the pmurhash32 result given seed, carry and total length"},

    {"pmurhash128_process", py_pmurhash128_process, METH_VARARGS,
        "Incrementally process some data in pmurhash128"},
    {"pmurhash128_result", py_pmurhash128_result, METH_VARARGS,
        "Return the pmurhash128 result given seed, carry and total length"},

    {NULL, NULL, 0, NULL}
};


#if PY_MAJOR_VERSION <= 2

extern "C" PyMODINIT_FUNC
initsmhasher(void)
{
    PyObject *m;

    m = Py_InitModule3("smhasher", smhasher_methods, module_doc);

    if (m == NULL)
        return;
    PyModule_AddStringConstant(m, "__version__", MODULE_VERSION);
}

#else

/* Python 3.x */

static PyModuleDef smhasher_module = {
    PyModuleDef_HEAD_INIT,
    "smhasher",
    module_doc,
    -1,
    smhasher_methods,
    NULL,
    NULL,
    NULL,
    NULL
};

extern "C" PyMODINIT_FUNC
PyInit_smhasher(void)
{
    PyObject *m;

    m = PyModule_Create(&smhasher_module);
    if (m == NULL)
        goto finally;
    PyModule_AddStringConstant(m, "__version__", MODULE_VERSION);

finally:
    return m;
}

#endif

