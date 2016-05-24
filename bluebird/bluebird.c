#include <Python.h>

#include <signal.h>
#include <unistd.h>
#include <sys/reg.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/select.h>
#include <sys/ptrace.h>


/* The read would segfault the bird.  Check the input extra inspection. */
        
#define WAIT_SLEEP 5000

#define WORD (__WORDSIZE / CHAR_BIT)

#define WORD_ALIGNED(data_length) data_length + (WORD - (data_length % WORD))

static void bluebird_handle_error(void)
{
    PyObject *error = NULL, *exception = NULL;
    char *message_str = NULL;
    char *message = strerror(errno);

    switch (errno) {

        case (EBUSY): 
            message_str = "EBUSY";
            break;
        case (EFAULT):
            message_str = "EFAULT";
            break;
        case (EINVAL):
            message_str = "EINVAL";
            break;
        case (EIO):
            message_str = "EIO";
            break;
        case (EPERM):
            exception = PyExc_PermissionError; 
            break;
        case (ESRCH):
            exception = PyExc_ProcessLookupError;
            break;
        case (ECHILD):
            exception = PyExc_ChildProcessError;
            break;
        case (EINTR):
            exception = PyExc_InterruptedError;
            break;
        case (EAGAIN):
            exception = PyExc_BlockingIOError;
            break;
    }

    if (!exception) {
        error = Py_BuildValue("s", message_str);
        PyErr_SetString(error, message);
    } else 
        PyErr_SetFromErrno(exception);
}

static void bluebird_sleep(void)
{
    struct timeval tm = { .tv_usec=WAIT_SLEEP, .tv_sec = 0 };

    select(0, NULL, NULL, NULL, &tm);
}

static int bluebird_ptrace_wait(pid_t pid)
{
    int status;

    for (int i=0; i < 2; i++) {

        if (waitpid(pid, &status, __WALL | WNOHANG) < 0) {
            bluebird_handle_error();
            return -1;
        }

        if (WIFSTOPPED(status)) 
            return 0;

        bluebird_sleep();
    }

    errno = ESRCH;
    bluebird_handle_error();

    return -1;
}

static int bluebird_ptrace_stop(pid_t pid)
{
    if (sigqueue(pid, SIGSTOP, (union sigval) 0) < 0) {
        bluebird_handle_error();
        return -1;
    }

    bluebird_sleep();

    if (bluebird_ptrace_wait(pid) < 0) {
        errno = ESRCH;
        bluebird_handle_error();
        return -1;
    }

    return 0;
}

static bool is_stopped(pid_t pid)
{
    char proc_pid_path[PATH_MAX + 1];
    snprintf(proc_pid_path, PATH_MAX, "/proc/%d/status", pid);

    FILE *fobj = fopen(proc_pid_path, "r");
    if (!fobj) {
        bluebird_handle_error();
        return false;
    }

    size_t n_bytes = 0;
    char *fobj_ln = NULL;
    char *field = "State";
    char *state = "\tt ";
    bool pid_state = false;

    while (getline(&fobj_ln, &n_bytes, fobj) != -1) {
        if (strstr(fobj_ln, field) &&
            strstr(fobj_ln, state)) {
            pid_state = true;
            break;
        }
    }
    
    fclose(fobj);

    return pid_state;
}

long bluebird_ptrace_call(enum __ptrace_request req, pid_t pid, 
                          unsigned long addr, long data)
{
    int stopped = 0;

    if (req != PTRACE_ATTACH && !is_stopped(pid))
        stopped = bluebird_ptrace_stop(pid);

    if (stopped < 0) 
        return -1;

    long ptrace_ret = ptrace(req, pid, addr, data);

    if (ptrace_ret < 0) {
        bluebird_handle_error();
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

static PyObject *bluebird_readstring(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned long addr;
    int words_to_read;

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
 
    ptrace(PTRACE_CONT, pid, 0, 0);

    words[WORD * words_to_read] = '\0';

    return Py_BuildValue("s", words);
}

static PyObject *bluebird_readint(PyObject *self, PyObject *args)
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

static inline void set_syscall(pid_t pid)
{
    bluebird_ptrace_call(PTRACE_SYSCALL, pid, 0, 0);

    int status;

    waitpid(pid, &status, __WALL);
}

static int *get_syscalls(pid_t pid, int nsyscalls)
{
    struct user_regs_struct rgs;
    int *calls = malloc(sizeof(int) * nsyscalls);
    int syscalls_made = 0;

    if (!calls)
        return NULL;

    while (syscalls_made < nsyscalls) {

        set_syscall(pid);

        if (ptrace(PTRACE_GETREGS, pid, 0, &rgs) < 0) 
            goto error;

        if (rgs.orig_rax == 219 || rgs.rax == -ENOSYS)
            continue;

        calls[syscalls_made++] = rgs.orig_rax;
    }

    if (bluebird_ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)
        goto error;

    return calls;

    error:
        bluebird_handle_error();

    return NULL;
}

static PyObject *bluebird_get_syscall(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    int *call = get_syscalls(pid, 1);

    if (!call)
        return NULL;

    PyObject *pycall = PyLong_FromLong(*call);

    free(call);

    return pycall;
}

static PyObject *bluebird_get_syscalls(PyObject *self, PyObject *args)
{
    pid_t pid;
    int nsyscalls;

    if (!PyArg_ParseTuple(args, "ii", &pid, &nsyscalls))
        return NULL;

    int *syscalls = get_syscalls(pid, nsyscalls);

    if (!syscalls)
        return NULL;

    PyObject *call_list = PyList_New(nsyscalls);

    for (int i=0; i < nsyscalls; i++) {

        PyObject *pycall = PyLong_FromLong(syscalls[i]);
        PyList_SetItem(call_list, i, pycall);
    }

    free(syscalls);

    return call_list;
}

static PyObject *bluebird_resume(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i", &pid))
        return NULL;

    int status;
    if (waitpid(pid, &status, __WALL | WNOHANG) < 0) {
        bluebird_handle_error();
        return NULL;
    }
    
    if (!WIFSTOPPED(status))
        Py_RETURN_NONE;

    if (bluebird_ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)
        return NULL;

    Py_RETURN_NONE;
}

static long *create_wordsize_array(char *data)
{
    size_t data_length = strlen(data);
    
    int num_of_words = (data_length / WORD);

    if (data_length % WORD != 0)
        num_of_words += 1;

    int word_aligned = WORD_ALIGNED(data_length);
    char *word_buffer = malloc(sizeof(char) * word_aligned + 1);
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

static PyObject *bluebird_writeint(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;
    const long wr_data;

    if (!PyArg_ParseTuple(args, "ikl", &pid, &addr, &wr_data))
        return NULL;

    long writeint = bluebird_write(pid, addr, wr_data);

    if (writeint < 0)
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *bluebird_writestring(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned long addr;
    char *wr_data;

    if (!PyArg_ParseTuple(args, "iks", &pid, &addr, &wr_data)) 
        return NULL;

    long *words = create_wordsize_array(wr_data);

    for (int i=0; words[i] != 0; i++) {
        if (bluebird_write(pid, addr, words[i]) < 0)
            return NULL;
        addr += WORD;
    }

    free(words);

    ptrace(PTRACE_CONT, pid, 0, 0);

    Py_RETURN_NONE;
}

static bool is_yama_enabled(void)
{
    char *yama_path = "/proc/sys/kernel/yama/ptrace_scope";
    FILE *yama = fopen(yama_path, "r");

    if (!yama)
        return false;

    fclose(yama);

    return fgetc(yama) == '1' ? true : false;
}

static bool is_traceable(void)
{
    uid_t uid = getuid();
    if (uid == 0) return true;
    
    return is_yama_enabled();
}

static PyObject *bluebird_signal(PyObject *self, PyObject *args)
{
    int ptrace_signal; 
    pid_t pid;

    if (!PyArg_ParseTuple(args, "ii", &pid, &ptrace_signal)) 
        return NULL;

    if (bluebird_ptrace_call(PTRACE_CONT, pid, 0, ptrace_signal) < 0) 
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *bluebird_attach(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!is_traceable()) {
        errno = EPERM;
        bluebird_handle_error();
        return NULL;
    }

    if (!PyArg_ParseTuple(args, "i", &pid)) 
        return NULL;

    if (bluebird_ptrace_call(PTRACE_ATTACH, pid, 0, 0) < 0) {
        bluebird_handle_error();
        return NULL;
    }

    if (bluebird_ptrace_call(PTRACE_CONT, pid, 0, 0) < 0) 
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *bluebird_detach(PyObject *self, PyObject *args)
{
    pid_t pid;
        
    if (!PyArg_ParseTuple(args, "i", &pid)) 
        return NULL;

    if (bluebird_ptrace_call(PTRACE_DETACH, pid, 0, 0) < 0)
        return NULL;

    Py_RETURN_NONE;
}

static PyMethodDef bluebirdmethods[] = {
    {"attach", bluebird_attach, METH_VARARGS,
     "attaches a trace on a running process"},
    {"detach", bluebird_detach, METH_VARARGS,
     "detaches a currently traced process"},
    {"resume", bluebird_resume, METH_VARARGS,
     "resumes a traced process currently stopped."},
    {"get_syscall", bluebird_get_syscall, METH_VARARGS,
     "returns the current system call being made by process"},
    {"get_syscalls", bluebird_get_syscalls, METH_VARARGS,
     "return a list of the last N system calls made by process"},
    {"readint", bluebird_readint, METH_VARARGS,
     "reads an int from process address"},
    {"readstring", bluebird_readstring, METH_VARARGS,
     "reads a string from process address"},
    {"writeint", bluebird_writeint, METH_VARARGS,
     "writes int to process address"},
    {"writestring", bluebird_writestring, METH_VARARGS,
     "writes string to process address"},
    {"signal", bluebird_signal, METH_VARARGS,
     "allows for signal sending to attached process"},
    {NULL, NULL, 0, NULL}
};

PyModuleDef bluebird_module = {
    PyModuleDef_HEAD_INIT,
    "bluebird",
    NULL,
    -1,
    bluebirdmethods
};

PyMODINIT_FUNC PyInit_bluebird(void) { return PyModule_Create(&bluebird_module); }

