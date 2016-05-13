#include <signal.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/ptrace.h>

#include "libbluebird.h"

/* The read would segfault the bird.  Check the input extra inspection. */
        
#define WORD __WORDSIZE / CHAR_BIT

#define WORD_ALIGNED(data_length) data_length + (WORD - (data_length % WORD))

static void handle_error(void)
{
    char *exception, *message = strerror(errno);

    switch (errno) {

        case (EBUSY): 
            exception = "EBUSY";
            break;
        case (EFAULT):
            exception = "EFAULT";
            break;
        case (EINVAL):
            exception = "EINVAL";
            break;
        case (EIO):
            exception = "EIO";
            break;
        case (EPERM):
            exception = "EPERM";
            break;
        case (ESRCH):
            exception = "ESRCH";
            break;
        case (ECHILD):
            exception = "ECHILD";
            break;
        case (EINTR):
            exception = "EINTR";
            break;
    }

    PyObject *error = Py_BuildValue("s", exception);
    PyErr_SetString(error, message);
}

static int ptrace_wait(pid_t pid)
{
    int status;

    if (waitpid(pid, &status, __WALL) < 0) {
        handle_error();
        return -1;
    }

    // handle status...
    if (!WIFSTOPPED(status)) 
        return -1;

    return 0;
}

long bluebird_ptrace_call(enum __ptrace_request req, pid_t pid, 
                          unsigned long addr, long data)
{
    long ptrace_ret = ptrace(req, pid, addr, data);
    if (ptrace_ret < 0) {
        handle_error();
        return -1;
    }

    return ptrace_ret;
}

static long bluebird_read(pid_t pid, unsigned const long addr)
{
    long peek_data = bluebird_ptrace_call(PTRACE_PEEKDATA, pid, addr, 0);

    if (peek_data < 0)
        return -1;

    return peek_data;
}

static PyObject *libbluebird_readstring(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned long addr;
    unsigned int words_to_read;

    if (!PyArg_ParseTuple(args, "iki", &pid, &addr, &words_to_read)) 
        return NULL;

    char *words = malloc(sizeof(char) * (WORD * words_to_read) + 1);

    for (int i=0; i < words_to_read; i++) {

        long read_string = bluebird_read(pid, addr); 
        
        if (read_string < 0)
            return NULL;

        memcpy(words + (i * WORD), (char *) &read_string, WORD);

        addr += WORD;
    }
 
    words[WORD * words_to_read] = '\0';

    return Py_BuildValue("s", words);
}

static PyObject *libbluebird_readint(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;

    if (!PyArg_ParseTuple(args, "ik", &pid, &addr))
        return NULL;

    long read_int = bluebird_read(pid, addr);

    if (read_int < 0)
        return NULL;

    return Py_BuildValue("i", read_int);
}

// POKE_USER
// PEEK_USER

static long *create_wordsize_array(char *data)
{
    size_t data_length = strlen(data);
    
    int num_of_words = (data_length / WORD);

    if (data_length % WORD != 0)
        num_of_words += 1;

    int word_aligned = WORD_ALIGNED(data_length);
    char *word_buffer = malloc(sizeof(char) * word_aligned);
    memset(word_buffer, '\0', word_aligned);

    long *words = malloc(sizeof *words * num_of_words + 1);

    for (int i=0; i < num_of_words; i++) {
        strcpy(word_buffer, data + (WORD * i));
        word_buffer[WORD] = '\0';
        words[i] = *(long *) word_buffer;
    }

    free(word_buffer);
    words[num_of_words] = 0;

    return words;
}

static long bluebird_write(pid_t pid, unsigned const long addr, 
                                      unsigned const long data)
{
    long write_ret = bluebird_ptrace_call(PTRACE_POKEDATA, pid, addr, data); 

    if (write_ret < 0)
        return -1;

    return write_ret;
}

static PyObject *libbluebird_writeint(PyObject *self, PyObject *args)
{
    // go through bluebird_write....
    pid_t pid;
    unsigned const long addr;
    const long wr_data;

    if (!PyArg_ParseTuple(args, "ikl", &pid, &addr, &wr_data))
        return NULL;

    if (bluebird_ptrace_call(PTRACE_POKETEXT, pid, addr, wr_data) < 0)
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *libbluebird_writestring(PyObject *self, PyObject *args)
{
    // go through bluebird_write....
    pid_t pid;
    unsigned long addr;
    char *wr_data;

    if (!PyArg_ParseTuple(args, "iks", &pid, &addr, &wr_data)) 
        return NULL;

    long *words = create_wordsize_array(wr_data);

    /*
    XXX debug
    for (int i=0; words[i]; i++) {
        PyObject *str = PyUnicode_FromString(words[i]);
        PyObject_Print(str, stdout, Py_PRINT_RAW);

    }
    */
    
    for (int i=0; words[i] != 0; i++) {
        if (bluebird_ptrace_call(PTRACE_POKETEXT, pid, addr, words[i]) < 0)
            return NULL;
        addr += WORD;
    }

    Py_RETURN_NONE;
}

static PyObject *libbluebird_signal(PyObject *self, PyObject *args)
{
    int ptrace_signal; 
    pid_t pid;

    if (!PyArg_ParseTuple(args, "ii", &pid, &ptrace_signal)) 
        return NULL;

    if (bluebird_ptrace_call(PTRACE_CONT, pid, 0, ptrace_signal) < 0) 
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *libbluebird_attach(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i", &pid)) 
        return NULL;

    if (bluebird_ptrace_call(PTRACE_ATTACH, pid, 0, 0) < 0) 
        return NULL;

    ptrace_wait(pid);
    // SIGCONT --> not responding?
    // use separate mechanism for signals (i.e. make available as user func)

    Py_RETURN_NONE;
}

static PyObject *libbluebird_detach(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i", &pid)) 
        return NULL;

    if (bluebird_ptrace_call(PTRACE_DETACH, pid, 0, 0) < 0)
        return NULL;

    Py_RETURN_NONE;
}

static PyMethodDef libbluebirdmethods[] = {
    {"attach", libbluebird_attach, METH_VARARGS,
     "attaches a trace on a running process"},
    {"detach", libbluebird_detach, METH_VARARGS,
     "detaches a currently traced process"},
    {"readint", libbluebird_readint, METH_VARARGS,
     "reads an int from process address"},
    {"readstring", libbluebird_readstring, METH_VARARGS,
     "reads a string from process address"},
    {"writeint", libbluebird_writeint, METH_VARARGS,
     "writes int to process address"},
    {"writestring", libbluebird_writestring, METH_VARARGS,
     "writes string to process address"},
    {"signal", libbluebird_signal, METH_VARARGS,
     "allows for signal sending to attached process"},
    {NULL, NULL, 0, NULL}
};

PyMODINIT_FUNC initlibbluebird(void)
{
    PyObject *bluebirdmod = Py_InitModule("libbluebird", libbluebirdmethods);
}
