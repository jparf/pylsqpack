#define PY_SSIZE_T_CLEAN

#include <assert.h>

#include <Python.h>
#include "lsqpack.h"
#include "lsxpack_header.h"

#define MODULE_NAME "pylsqpack._binding"

/*
 * Internal struct definitions copied from lsqpack.c for dynamic table
 * inspection. These are stable internal types used by the ls-qpack library.
 */
#define DYNAMIC_ENTRY_OVERHEAD 32u

struct lsqpack_dec_table_entry {
    unsigned    dte_name_len;
    unsigned    dte_val_len;
    unsigned    dte_refcnt;
    unsigned    dte_name_hash;
    unsigned    dte_nameval_hash;
    unsigned    dte_name_idx;
    enum {
        DTEF_NAME_HASH      = 1 << 0,
        DTEF_NAMEVAL_HASH   = 1 << 1,
        DTEF_NAME_IDX       = 1 << 2,
    }           dte_flags;
    char        dte_buf[0];
};

#define DTE_NAME(dte) ((dte)->dte_buf)
#define DTE_VALUE(dte) (&(dte)->dte_buf[(dte)->dte_name_len])

struct lsqpack_enc_table_entry {
    STAILQ_ENTRY(lsqpack_enc_table_entry)
                                    ete_next_nameval,
                                    ete_next_name,
                                    ete_next_all;
    lsqpack_abs_id_t                ete_id;
    unsigned                        ete_when_added_used;
    unsigned                        ete_when_added_dropped;
    unsigned                        ete_n_reffd;
    unsigned                        ete_nameval_hash;
    unsigned                        ete_name_hash;
    unsigned                        ete_name_len;
    unsigned                        ete_val_len;
    char                            ete_buf[0];
};

#define ETE_NAME(ete) ((ete)->ete_buf)
#define ETE_VALUE(ete) (&(ete)->ete_buf[(ete)->ete_name_len])

#define DEC_BUF_SZ 4096
#define ENC_BUF_SZ 4096
#define HDR_BUF_SZ 4096
#define XHDR_BUF_SZ 4096
#define PREFIX_MAX_SIZE 16

static PyObject *DecompressionFailed;
static PyObject *DecoderStreamError;
static PyObject *DecoderType;
static PyObject *EncoderStreamError;
static PyObject *EncoderType;
static PyObject *StreamBlocked;

struct header_block {
    STAILQ_ENTRY(header_block) entries;

    int blocked:1;
    unsigned char *data;
    size_t data_len;
    const unsigned char *data_ptr;
    struct lsxpack_header xhdr;
    // This buffer is owned by the header_block and is reused internally by xhdr.
    char *header_buffer;
    uint64_t stream_id;
    PyObject *headers;
};

static struct header_block *header_block_new(size_t stream_id, const unsigned char *data, size_t data_len)
{
    struct header_block *hblock = malloc(sizeof(struct header_block));
    memset(hblock, 0, sizeof(*hblock));
    hblock->data = malloc(data_len);
    hblock->data_len = data_len;
    hblock->data_ptr = hblock->data;
    memcpy(hblock->data, data, data_len);
    hblock->stream_id = stream_id;
    hblock->headers = PyList_New(0);
    return hblock;
}

static void header_block_free(struct header_block *hblock)
{
    free(hblock->data);
    hblock->data = 0;
    hblock->data_ptr = 0;
    free(hblock->header_buffer);
    Py_DECREF(hblock->headers);
    free(hblock);
}

static void header_block_unblocked(void *opaque) {
    struct header_block *hblock = opaque;
    hblock->blocked = 0;
}

/**
 * Prepare to decode a header by allocating the requested memory.
 */
static struct lsxpack_header *header_block_prepare_decode(void *opaque, struct lsxpack_header *xhdr, size_t space) {
    struct header_block *hblock = opaque;
    char *buf = realloc(hblock->header_buffer, space);
    if (!buf) return NULL;
    hblock->header_buffer = buf;

    if (xhdr) {
        assert(&hblock->xhdr == xhdr);
        assert(space > xhdr->val_len);

        xhdr->buf = buf;
        xhdr->val_len = space;
    } else {
        xhdr = &hblock->xhdr;
        lsxpack_header_prepare_decode(xhdr, buf, 0, space);
    }
    return xhdr;
}

/**
 * Process a decoded header by appending it to the list of headers.
 */
static int header_block_process_header(void *opaque, struct lsxpack_header *xhdr) {
    struct header_block *hblock = opaque;
    PyObject *tuple, *name, *value;

    name = PyBytes_FromStringAndSize(lsxpack_header_get_name(xhdr), xhdr->name_len);
    value = PyBytes_FromStringAndSize(lsxpack_header_get_value(xhdr), xhdr->val_len);
    tuple = PyTuple_Pack(2, name, value);
    Py_DECREF(name);
    Py_DECREF(value);

    PyList_Append(hblock->headers, tuple);
    Py_DECREF(tuple);

    return 0;
}

static const struct lsqpack_dec_hset_if header_block_if = {
    .dhi_unblocked = header_block_unblocked,
    .dhi_prepare_decode = header_block_prepare_decode,
    .dhi_process_header = header_block_process_header,
};

// DECODER

typedef struct {
    PyObject_HEAD
    struct lsqpack_dec dec;
    unsigned char dec_buf[DEC_BUF_SZ];
    STAILQ_HEAD(, header_block) pending_blocks;
} DecoderObject;

static int
Decoder_init(DecoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"max_table_capacity", "blocked_streams", NULL};
    unsigned max_table_capacity, blocked_streams;
    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "II", kwlist, &max_table_capacity, &blocked_streams))
        return -1;

    lsqpack_dec_init(&self->dec, NULL, max_table_capacity, blocked_streams, &header_block_if, 0);

    STAILQ_INIT(&self->pending_blocks);

    return 0;
}

static void
Decoder_dealloc(DecoderObject *self)
{
    struct header_block *hblock;

    lsqpack_dec_cleanup(&self->dec);

    while (!STAILQ_EMPTY(&self->pending_blocks)) {
        hblock = STAILQ_FIRST(&self->pending_blocks);
        STAILQ_REMOVE_HEAD(&self->pending_blocks, entries);
        header_block_free(hblock);
    }

    PyTypeObject *tp = Py_TYPE(self);
    freefunc free = PyType_GetSlot(tp, Py_tp_free);
    free(self);
    Py_DECREF(tp);
}

PyDoc_STRVAR(Decoder_feed_encoder__doc__,
    "feed_encoder(data: bytes) -> List[int]\n\n"
    "Feed data from the encoder stream.\n\n"
    "If processing the data unblocked any streams, their IDs are returned, "
    "and :meth:`resume_header()` must be called for each stream ID.\n\n"
    "If the data cannot be processed, :class:`EncoderStreamError` is raised.\n\n"
    ":param data: the encoder stream data\n");

static PyObject*
Decoder_feed_encoder(DecoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"data", NULL};
    const unsigned char *data;
    Py_ssize_t data_len;
    PyObject *list, *value;
    struct header_block *hblock;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#", kwlist, &data, &data_len))
        return NULL;

    if (lsqpack_dec_enc_in(&self->dec, data, data_len) < 0) {
        PyErr_SetString(EncoderStreamError, "lsqpack_dec_enc_in failed");
        return NULL;
    }

    list = PyList_New(0);
    STAILQ_FOREACH(hblock, &self->pending_blocks, entries) {
        if (!hblock->blocked) {
            value = PyLong_FromUnsignedLongLong(hblock->stream_id);
            PyList_Append(list, value);
            Py_DECREF(value);
        }
    }
    return list;
}

PyDoc_STRVAR(Decoder_feed_header__doc__,
    "feed_header(stream_id: int, data: bytes) -> Tuple[bytes, List[Tuple[bytes, bytes]]]\n\n"
    "Decode a header block and return control data and headers.\n\n"
    "If the stream is blocked, :class:`StreamBlocked` is raised.\n\n"
    "If the data cannot be processed, :class:`DecompressionFailed` is raised.\n\n"
    ":param stream_id: the ID of the stream\n"
    ":param data: the header block data\n");

static PyObject*
Decoder_feed_header(DecoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"stream_id", "data", NULL};
    uint64_t stream_id;
    const unsigned char *data;
    Py_ssize_t data_len;
    PyObject *control, *tuple;
    size_t dec_len = DEC_BUF_SZ;
    enum lsqpack_read_header_status status;
    struct header_block *hblock;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "Ky#", kwlist, &stream_id, &data, &data_len))
        return NULL;

    // check there is no header block for the stream
    STAILQ_FOREACH(hblock, &self->pending_blocks, entries) {
        if (hblock->stream_id == stream_id) {
            PyErr_Format(PyExc_ValueError, "a header block for stream %d already exists", stream_id);
            return NULL;
        }
    }
    hblock = header_block_new(stream_id, data, data_len);

    status = lsqpack_dec_header_in(
        &self->dec,
        hblock,
        stream_id,
        hblock->data_len,
        &hblock->data_ptr,
        hblock->data_len,
        self->dec_buf,
        &dec_len
    );

    if (status == LQRHS_BLOCKED || status == LQRHS_NEED) {
        hblock->blocked = 1;
        STAILQ_INSERT_TAIL(&self->pending_blocks, hblock, entries);
        PyErr_Format(StreamBlocked, "stream %d is blocked", stream_id);
        return NULL;
    } else if (status != LQRHS_DONE) {
        PyErr_Format(DecompressionFailed, "lsqpack_dec_header_in for stream %d failed", stream_id);
        header_block_free(hblock);
        return NULL;
    }

    control = PyBytes_FromStringAndSize((const char*)self->dec_buf, dec_len);
    tuple = PyTuple_Pack(2, control, hblock->headers);
    Py_DECREF(control);

    header_block_free(hblock);

    return tuple;
}

PyDoc_STRVAR(Decoder_resume_header__doc__,
    "resume_header(stream_id: int) -> Tuple[bytes, List[Tuple[bytes, bytes]]]\n\n"
    "Continue decoding a header block and return control data and headers.\n\n"
    "This method should be called only when :meth:`feed_encoder` indicates "
    "that a stream has become unblocked\n\n"
    ":param stream_id: the ID of the stream\n");

static PyObject*
Decoder_resume_header(DecoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"stream_id", NULL};
    uint64_t stream_id;
    PyObject *control, *tuple;
    size_t dec_len = DEC_BUF_SZ;
    enum lsqpack_read_header_status status;
    struct header_block *hblock;
    int found = 0;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "K", kwlist, &stream_id))
        return NULL;

    // find the header block for the stream
    STAILQ_FOREACH(hblock, &self->pending_blocks, entries) {
        if (hblock->stream_id == stream_id) {
            found = 1;
            break;
        }
    }
    if (!found) {
        PyErr_Format(PyExc_ValueError, "no pending header block for stream %d", stream_id);
        return NULL;
    }

    if (hblock->blocked) {
        status = LQRHS_BLOCKED;
    } else {
        status = lsqpack_dec_header_read(
            &self->dec,
            hblock,
            &hblock->data_ptr,
            hblock->data_len - (hblock->data_ptr - hblock->data),
            self->dec_buf,
            &dec_len
        );
    }

    if (status == LQRHS_BLOCKED || status == LQRHS_NEED) {
        hblock->blocked = 1;
        PyErr_Format(StreamBlocked, "stream %d is blocked", stream_id);
        return NULL;
    } else if (status != LQRHS_DONE) {
        PyErr_Format(DecompressionFailed, "lsqpack_dec_header_read for stream %d failed (%d)", stream_id, status);
        STAILQ_REMOVE(&self->pending_blocks, hblock, header_block, entries);
        header_block_free(hblock);
        return NULL;
    }

    control = PyBytes_FromStringAndSize((const char*)self->dec_buf, dec_len);
    tuple = PyTuple_Pack(2, control, hblock->headers);
    Py_DECREF(control);

    STAILQ_REMOVE(&self->pending_blocks, hblock, header_block, entries);
    header_block_free(hblock);

    return tuple;
}

PyDoc_STRVAR(Decoder_get_dynamic_table__doc__,
    "get_dynamic_table() -> dict\n\n"
    "Return the current state of the QPACK dynamic table.\n\n"
    "The returned dict contains:\n"
    "  - ``max_capacity``: the maximum table capacity in bytes\n"
    "  - ``current_capacity``: the current table size in bytes\n"
    "  - ``entries``: a list of ``(name, value)`` byte-string tuples\n");

static PyObject*
Decoder_get_dynamic_table(DecoderObject *self, PyObject *Py_UNUSED(args))
{
    PyObject *entries, *entry_tuple, *name, *value, *result;
    const struct lsqpack_ringbuf *rbuf = &self->dec.qpd_dyn_table;
    const struct lsqpack_dec_table_entry *entry;
    unsigned idx;

    entries = PyList_New(0);
    if (!entries)
        return NULL;

    /* Iterate ring buffer from tail (oldest) to head (newest) */
    if (rbuf->rb_nalloc && rbuf->rb_head != rbuf->rb_tail) {
        idx = rbuf->rb_tail;
        while (idx != rbuf->rb_head) {
            entry = (const struct lsqpack_dec_table_entry *)rbuf->rb_els[idx];
            name = PyBytes_FromStringAndSize(DTE_NAME(entry), entry->dte_name_len);
            value = PyBytes_FromStringAndSize(DTE_VALUE(entry), entry->dte_val_len);
            entry_tuple = PyTuple_Pack(2, name, value);
            Py_DECREF(name);
            Py_DECREF(value);
            if (PyList_Append(entries, entry_tuple) < 0) {
                Py_DECREF(entry_tuple);
                Py_DECREF(entries);
                return NULL;
            }
            Py_DECREF(entry_tuple);
            idx = (idx + 1) % rbuf->rb_nalloc;
        }
    }

    result = PyDict_New();
    if (!result) {
        Py_DECREF(entries);
        return NULL;
    }
    value = PyLong_FromUnsignedLong(self->dec.qpd_cur_max_capacity);
    PyDict_SetItemString(result, "max_capacity", value);
    Py_DECREF(value);
    value = PyLong_FromUnsignedLong(self->dec.qpd_cur_capacity);
    PyDict_SetItemString(result, "current_capacity", value);
    Py_DECREF(value);
    PyDict_SetItemString(result, "entries", entries);
    Py_DECREF(entries);

    return result;
}

static PyMethodDef Decoder_methods[] = {
    {"feed_encoder", (PyCFunction)Decoder_feed_encoder, METH_VARARGS | METH_KEYWORDS, Decoder_feed_encoder__doc__},
    {"feed_header", (PyCFunction)Decoder_feed_header, METH_VARARGS | METH_KEYWORDS, Decoder_feed_header__doc__},
    {"resume_header", (PyCFunction)Decoder_resume_header, METH_VARARGS | METH_KEYWORDS, Decoder_resume_header__doc__},
    {"get_dynamic_table", (PyCFunction)Decoder_get_dynamic_table, METH_NOARGS, Decoder_get_dynamic_table__doc__},
    {NULL}
};

PyDoc_STRVAR(Decoder__doc__,
    "Decoder(max_table_capacity: int, blocked_streams: int)\n\n"
    "QPACK decoder.\n\n"
    ":param max_table_capacity: the maximum size in bytes of the dynamic table\n"
    ":param blocked_streams: the maximum number of streams that could be blocked\n");

static PyType_Slot DecoderType_slots[] = {
    {Py_tp_dealloc, Decoder_dealloc},
    {Py_tp_methods, Decoder_methods},
    {Py_tp_doc, (char *)Decoder__doc__},
    {Py_tp_init, Decoder_init},
    {0, 0},
};

static PyType_Spec DecoderType_spec = {
    MODULE_NAME ".Decoder",
    sizeof(DecoderObject),
    0,
    Py_TPFLAGS_DEFAULT,
    DecoderType_slots
};

// ENCODER

typedef struct {
    PyObject_HEAD
    struct lsqpack_enc enc;
    unsigned char hdr_buf[HDR_BUF_SZ];
    unsigned char enc_buf[ENC_BUF_SZ];
    unsigned char pfx_buf[PREFIX_MAX_SIZE];
    char xhdr_buf[XHDR_BUF_SZ];
} EncoderObject;

static int
Encoder_init(EncoderObject *self, PyObject *args, PyObject *kwargs)
{
    lsqpack_enc_preinit(&self->enc, NULL);
    return 0;
}

static void
Encoder_dealloc(EncoderObject *self)
{
    lsqpack_enc_cleanup(&self->enc);

    PyTypeObject *tp = Py_TYPE(self);
    freefunc free = PyType_GetSlot(tp, Py_tp_free);
    free(self);
    Py_DECREF(tp);
}

PyDoc_STRVAR(Encoder_apply_settings__doc__,
    "apply_settings(max_table_capacity: int, blocked_streams: int) -> bytes\n\n"
    "Apply the settings received from the encoder.\n\n"
    ":param max_table_capacity: the maximum size in bytes of the dynamic table\n"
    ":param blocked_streams: the maximum number of streams that could be blocked\n");

static PyObject*
Encoder_apply_settings(EncoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"max_table_capacity", "blocked_streams", NULL};
    unsigned max_table_capacity, blocked_streams;
    unsigned char tsu_buf[LSQPACK_LONGEST_SDTC];
    size_t tsu_len = sizeof(tsu_buf);

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "II", kwlist, &max_table_capacity, &blocked_streams))
        return NULL;

    if (lsqpack_enc_init(&self->enc, NULL, max_table_capacity, max_table_capacity, blocked_streams,
                         LSQPACK_ENC_OPT_STAGE_2, tsu_buf, &tsu_len) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "lsqpack_enc_init failed");
        return NULL;
    }

    return PyBytes_FromStringAndSize((const char*)tsu_buf, tsu_len);
}

PyDoc_STRVAR(Encoder_encode__doc__,
    "encode(stream_id: int, headers: List[Tuple[bytes, bytes]]) -> Tuple[bytes, bytes]\n\n"
    "Encode a list of headers.\n\n"
    "A tuple is returned containing two bytestrings: the encoder stream data "
    " and the encoded header block.\n\n"
    ":param stream_id: the stream ID\n"
    ":param headers: a list of header tuples\n");

static PyObject*
Encoder_encode(EncoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"stream_id", "headers", NULL};
    uint64_t stream_id;
    unsigned seqno = 0;
    PyObject *list, *tuple, *name, *value;
    size_t enc_len, hdr_len, pfx_len;
    size_t enc_off = 0, hdr_off = PREFIX_MAX_SIZE, pfx_off = 0;
    struct lsxpack_header xhdr;
    size_t name_len, value_len;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "KO", kwlist, &stream_id, &list))
        return NULL;

    if (!PyList_Check(list)) {
        PyErr_SetString(PyExc_ValueError, "headers must be a list");
        return NULL;
    }

    if (lsqpack_enc_start_header(&self->enc, stream_id, seqno) != 0) {
        PyErr_SetString(PyExc_RuntimeError, "lsqpack_enc_start_header failed");
        return NULL;
    }

    for (Py_ssize_t i = 0; i < PyList_Size(list); ++i) {
        tuple = PyList_GetItem(list, i);
        if (!PyTuple_Check(tuple) || PyTuple_Size(tuple) != 2) {
            PyErr_SetString(PyExc_ValueError, "the header must be a two-tuple");
            return NULL;
        }
        name = PyTuple_GetItem(tuple, 0);
        value = PyTuple_GetItem(tuple, 1);
        if (!PyBytes_Check(name) || !PyBytes_Check(value)) {
            PyErr_SetString(PyExc_ValueError, "the header's name and value must be bytes");
            return NULL;
        }
        name_len = PyBytes_Size(name);
        value_len = PyBytes_Size(value);
        if (name_len + value_len > XHDR_BUF_SZ) {
            PyErr_SetString(PyExc_ValueError, "the header's name and value are too long");
            return NULL;
        }

        // Copy the header name and value into the xhdr buffer.
        memcpy(self->xhdr_buf, PyBytes_AsString(name), name_len);
        memcpy(self->xhdr_buf + name_len, PyBytes_AsString(value), value_len);
        lsxpack_header_set_offset2(&xhdr, self->xhdr_buf, 0, name_len, name_len, value_len);

        enc_len = ENC_BUF_SZ - enc_off;
        hdr_len = HDR_BUF_SZ - hdr_off;
        if (lsqpack_enc_encode(&self->enc,
                               self->enc_buf + enc_off, &enc_len,
                               self->hdr_buf + hdr_off, &hdr_len,
                               &xhdr,
                               0) != LQES_OK) {
            PyErr_SetString(PyExc_RuntimeError, "lsqpack_enc_encode failed");
            return NULL;
        }
        enc_off += enc_len;
        hdr_off += hdr_len;
    }

    pfx_len = lsqpack_enc_end_header(&self->enc, self->pfx_buf, PREFIX_MAX_SIZE, NULL);
    if (pfx_len <= 0) {
        PyErr_SetString(PyExc_RuntimeError, "lsqpack_enc_start_header failed");
        return NULL;
    }
    pfx_off = PREFIX_MAX_SIZE - pfx_len;
    memcpy(self->hdr_buf + pfx_off, self->pfx_buf, pfx_len);

    name = PyBytes_FromStringAndSize((const char*)self->enc_buf, enc_off);
    value = PyBytes_FromStringAndSize((const char*)self->hdr_buf + pfx_off, hdr_off - pfx_off);
    tuple = PyTuple_Pack(2, name, value);
    Py_DECREF(name);
    Py_DECREF(value);

    return tuple;
}

PyDoc_STRVAR(Encoder_feed_decoder__doc__,
    "feed_decoder(data: bytes) -> None\n\n"
    "Feed data from the decoder stream.\n\n"
    "If the data cannot be processed, :class:`DecoderStreamError` is raised.\n\n"
    ":param data: the decoder stream data\n");

static PyObject*
Encoder_feed_decoder(EncoderObject *self, PyObject *args, PyObject *kwargs)
{
    char *kwlist[] = {"data", NULL};
    const unsigned char *data;
    Py_ssize_t data_len;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "y#", kwlist, &data, &data_len))
        return NULL;

    if (lsqpack_enc_decoder_in(&self->enc, data, data_len) < 0) {
        PyErr_SetString(DecoderStreamError, "lsqpack_enc_decoder_in failed");
        return NULL;
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(Encoder_get_dynamic_table__doc__,
    "get_dynamic_table() -> dict\n\n"
    "Return the current state of the QPACK dynamic table.\n\n"
    "The returned dict contains:\n"
    "  - ``max_capacity``: the maximum table capacity in bytes\n"
    "  - ``current_capacity``: the current table size in bytes\n"
    "  - ``entries``: a list of ``(name, value)`` byte-string tuples\n");

static PyObject*
Encoder_get_dynamic_table(EncoderObject *self, PyObject *Py_UNUSED(args))
{
    PyObject *entries, *entry_tuple, *name, *value, *result;
    struct lsqpack_enc_table_entry *entry;

    entries = PyList_New(0);
    if (!entries)
        return NULL;

    STAILQ_FOREACH(entry, &self->enc.qpe_all_entries, ete_next_all) {
        name = PyBytes_FromStringAndSize(ETE_NAME(entry), entry->ete_name_len);
        value = PyBytes_FromStringAndSize(ETE_VALUE(entry), entry->ete_val_len);
        entry_tuple = PyTuple_Pack(2, name, value);
        Py_DECREF(name);
        Py_DECREF(value);
        if (PyList_Append(entries, entry_tuple) < 0) {
            Py_DECREF(entry_tuple);
            Py_DECREF(entries);
            return NULL;
        }
        Py_DECREF(entry_tuple);
    }

    result = PyDict_New();
    if (!result) {
        Py_DECREF(entries);
        return NULL;
    }
    value = PyLong_FromUnsignedLong(self->enc.qpe_cur_max_capacity);
    PyDict_SetItemString(result, "max_capacity", value);
    Py_DECREF(value);
    value = PyLong_FromUnsignedLong(self->enc.qpe_cur_bytes_used);
    PyDict_SetItemString(result, "current_capacity", value);
    Py_DECREF(value);
    PyDict_SetItemString(result, "entries", entries);
    Py_DECREF(entries);

    return result;
}

static PyMethodDef Encoder_methods[] = {
    {"apply_settings", (PyCFunction)Encoder_apply_settings, METH_VARARGS | METH_KEYWORDS, Encoder_apply_settings__doc__},
    {"encode", (PyCFunction)Encoder_encode, METH_VARARGS | METH_KEYWORDS, Encoder_encode__doc__},
    {"feed_decoder", (PyCFunction)Encoder_feed_decoder, METH_VARARGS | METH_KEYWORDS, Encoder_feed_decoder__doc__},
    {"get_dynamic_table", (PyCFunction)Encoder_get_dynamic_table, METH_NOARGS, Encoder_get_dynamic_table__doc__},
    {NULL}
};

PyDoc_STRVAR(Encoder__doc__,
    "Encoder()\n\n"
    "QPACK encoder.\n");

static PyType_Slot EncoderType_slots[] = {
    {Py_tp_dealloc, Encoder_dealloc},
    {Py_tp_methods, Encoder_methods},
    {Py_tp_doc, (char *)Encoder__doc__},
    {Py_tp_init, Encoder_init},
    {0, 0},
};

static PyType_Spec EncoderType_spec = {
    MODULE_NAME ".Encoder",
    sizeof(EncoderObject),
    0,
    Py_TPFLAGS_DEFAULT,
    EncoderType_slots
};

// MODULE

static struct PyModuleDef moduledef = {
    PyModuleDef_HEAD_INIT,
    MODULE_NAME,                        /* m_name */
    "Bindings for ls-qpack.",           /* m_doc */
    -1,                                 /* m_size */
    NULL,                               /* m_methods */
    NULL,                               /* m_reload */
    NULL,                               /* m_traverse */
    NULL,                               /* m_clear */
    NULL,                               /* m_free */
};

PyMODINIT_FUNC
PyInit__binding(void)
{
    PyObject* m;

    m = PyModule_Create(&moduledef);
    if (m == NULL)
        return NULL;

    DecompressionFailed = PyErr_NewException(MODULE_NAME ".DecompressionFailed", PyExc_ValueError, NULL);
    Py_INCREF(DecompressionFailed);
    PyModule_AddObject(m, "DecompressionFailed", DecompressionFailed);

    DecoderStreamError = PyErr_NewException(MODULE_NAME ".DecoderStreamError", PyExc_ValueError, NULL);
    Py_INCREF(DecoderStreamError);
    PyModule_AddObject(m, "DecoderStreamError", DecoderStreamError);

    EncoderStreamError = PyErr_NewException(MODULE_NAME ".EncoderStreamError", PyExc_ValueError, NULL);
    Py_INCREF(EncoderStreamError);
    PyModule_AddObject(m, "EncoderStreamError", EncoderStreamError);

    StreamBlocked = PyErr_NewException(MODULE_NAME ".StreamBlocked", PyExc_ValueError, NULL);
    Py_INCREF(StreamBlocked);
    PyModule_AddObject(m, "StreamBlocked", StreamBlocked);

    DecoderType = PyType_FromSpec(&DecoderType_spec);
    if (DecoderType == NULL)
        return NULL;
    PyModule_AddObject(m, "Decoder", DecoderType);

    EncoderType = PyType_FromSpec(&EncoderType_spec);
    if (EncoderType == NULL)
        return NULL;
    PyModule_AddObject(m, "Encoder", EncoderType);

    return m;
}
