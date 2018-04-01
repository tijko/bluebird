// Python header file must be included first
#include <Python.h>

#include <asm/unistd_64.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>


/* The read would segfault the bird.  Check the input extra inspection. */
        
#define WAIT_SLEEP 5000

#define WORD (__WORDSIZE / CHAR_BIT)

#define WORD_ALIGNED(data_length) data_length + (WORD - (data_length % WORD))

static void bluebird_cext_handle_error(void)
{
    PyObject *error = NULL, *exception = NULL;
    char *message_str = NULL;
    char *message = strerror(errno);

    switch (errno) {

        case (EACCES):
            message_str = "EACCES";
            break;
        case (EBADF):
            message_str = "EBADF";
            break;
        case (EMFILE):
            message_str = "EMFILE";
            break;
        case (ENODEV):
            message_str = "ENODEV";
            break;
        case (ENOMEM):
            message_str = "ENOMEM";
            break;
        case (ENOTSUP):
            message_str = "ENOTSUP";
            break;
        case (ENXIO):
            message_str = "ENXIO";
            break;
        case (EOVERFLOW):
            message_str = "EOVERFLOW";
            break;    
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
        default:
            message_str = "UNKNOWN";
    }

    if (!exception) {
        error = Py_BuildValue("s", message_str);
        PyErr_SetString(error, message);
    } else 
        PyErr_SetFromErrno(exception);
}

static void bluebird_cext_sleep(void)
{
    struct timeval tm = { .tv_usec=WAIT_SLEEP, .tv_sec = 0 };

    select(0, NULL, NULL, NULL, &tm);
}

static int bluebird_cext_ptrace_wait(pid_t pid)
{
    int status;

    for (int i=0; i < 2; i++) {

        if (waitpid(pid, &status, __WALL | WNOHANG) < 0) 
            return -1;

        if (WIFSTOPPED(status)) 
            return 0;

        bluebird_cext_sleep();
    }

    errno = ESRCH;

    return -1;
}

static int bluebird_cext_ptrace_stop(pid_t pid)
{
    if (sigqueue(pid, SIGSTOP, (union sigval) 0) < 0) 
        return -1;

    bluebird_cext_sleep();

    if (bluebird_cext_ptrace_wait(pid) < 0) {
        errno = ESRCH;
        return -1;
    }

    return 0;
}

static bool is_stopped(pid_t pid)
{
    char proc_pid_path[PATH_MAX + 1];
    snprintf(proc_pid_path, PATH_MAX, "/proc/%d/status", pid);

    FILE *fobj = fopen(proc_pid_path, "r");

    if (!fobj) 
        return false;

    size_t n_bytes = 0;
    char *fobj_ln = NULL;
    bool pid_state = false;

    while (getline(&fobj_ln, &n_bytes, fobj) != -1) {
        if (strstr(fobj_ln, "State") &&
            strstr(fobj_ln, "\tt")) {
            pid_state = true;
            break;
        }
    }
    
    fclose(fobj);

    return pid_state;
}

long ptrace_call(enum __ptrace_request req, pid_t pid, 
                          unsigned long addr, long data)
{
    int stopped = 0;

    if (req != PTRACE_ATTACH && !is_stopped(pid)) 
        stopped = bluebird_cext_ptrace_stop(pid);

    if (stopped < 0) 
        return -1;

    long ptrace_ret = ptrace(req, pid, addr, data);

    /* corner case brought up on uber-pyflame: 
     * ptrace_ret was a peek and the data at addr was -1 */

    if (ptrace_ret < 0) 
        return -1;

    /* XXX debug
    PyObject *str = NULL;
    if (req == PTRACE_ATTACH)
        str = PyUnicode_FromString("attach\n");
    else if (req == PTRACE_SYSCALL)
        str = PyUnicode_FromString("syscall\n");
    else if (req == PTRACE_GETREGS)
        str = PyUnicode_FromString("getregs\n");
    else if (req == PTRACE_CONT)
        str = PyUnicode_FromString("cont\n");
    PyObject_Print(str, stdout, Py_PRINT_RAW);
    */

    return ptrace_ret;
}

static long bluebird_cext_read(pid_t pid, unsigned const long addr)
{
    long peek_data = ptrace_call(PTRACE_PEEKDATA, pid, addr, 0);

    if (peek_data < 0)
        return -1;

    return peek_data;
}

static PyObject *bluebird_cext_continue_trace(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i:continue_trace", &pid))
        return NULL;

    ptrace_call(PTRACE_CONT, pid, 0, 0);
    
    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_readstring(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned long addr;
    int words_to_read;

    if (!PyArg_ParseTuple(args, "iki:readstring", &pid, &addr, &words_to_read)) 
        return NULL;

    char *words = malloc(sizeof(char) * (WORD * words_to_read) + 1);

    for (int i=0; i < words_to_read; i++) {

        long read_string = bluebird_cext_read(pid, addr); 
        
        if (read_string < 0)
            return NULL;

        memcpy(words + (i * WORD), (char *) &read_string, WORD);

        addr += WORD;
    }
 
    ptrace(PTRACE_CONT, pid, 0, 0);

    for (int i=0; i < WORD * words_to_read; i++)
        if (words[i] == '\0')
            words[i] = '\n';

    words[WORD * words_to_read] = '\0';

    return Py_BuildValue("s", words);
}

static PyObject *bluebird_cext_readint(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;

    if (!PyArg_ParseTuple(args, "ik:readint", &pid, &addr))
        return NULL;

    long read_int = bluebird_cext_read(pid, addr);

    if (read_int < 0)
        return NULL;

    return Py_BuildValue("i", read_int);
}

static int set_sys_step(pid_t pid, enum __ptrace_request step)
{
    if (ptrace_call(step, pid, 0, 0) < 0)
        return -1;

    int status;

    waitpid(pid, &status, __WALL);

    return 0;
}

static int *get_syscalls(pid_t pid, int nsyscalls, int enter, bool signal_cont)
{
    struct user_regs_struct rgs;
    int *calls = malloc(sizeof(int) * nsyscalls);
    int syscalls_made = 0;

    if (!calls)
        return NULL;

    while (syscalls_made < nsyscalls) {
        if (set_sys_step(pid, PTRACE_SYSCALL) < 0)
            goto error;

        if (ptrace(PTRACE_GETREGS, pid, 0, &rgs) < 0) 
            goto error;

        //  checking the restart_call kernel syscall after SIGSTP
        //  orig_rax mask against 0x80 SIGTRAP for info on entry/exit?
        if ((rgs.orig_rax == 219 && enter) || (signed) rgs.rax == -ENOSYS)
            continue;

        calls[syscalls_made++] = rgs.orig_rax;
    }

    if (signal_cont && ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)
        goto error;

    return calls;

error:
    free(calls);

    return NULL;
}

static int *find_call(pid_t pid, int call, int enter, int timeout)
{
    int *current_call = NULL;
    int *find_exit_status = malloc(sizeof(int));
    *find_exit_status = 0;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    clock_t start = ts.tv_sec;

    while (!current_call || *current_call != call) {

        current_call = get_syscalls(pid, 1, enter, false);

        if (!current_call && ptrace_call(PTRACE_CONT, pid, 0, 0) < 0) {
            *find_exit_status = errno;
            return find_exit_status;
        }

        if (timeout > 0) {
            clock_gettime(CLOCK_REALTIME, &ts);
            if ((ts.tv_sec - start) > timeout)
                break;
        }
    }

    return find_exit_status;
}

static PyObject *bluebird_cext_find_syscall(PyObject *self, PyObject *args)
{
    pid_t pid;
    int call, timeout;

    if (!PyArg_ParseTuple(args, "iii:find_syscall", &pid, &call, &timeout))
        return NULL;

    find_call(pid, call, 1, timeout);
        
    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_get_syscall(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i:get_syscall", &pid))
        return NULL;

    int *call = get_syscalls(pid, 1, 1, true);

    if (!call)
        return NULL;

    PyObject *pycall = PyLong_FromLong(*call);

    free(call);

    return pycall;
}
// XXX alloc the mem in each individual call passing along OR
//     alloc in the call returning then freeing 
static PyObject *bluebird_cext_get_syscalls(PyObject *self, PyObject *args)
{
    pid_t pid;
    int nsyscalls;

    if (!PyArg_ParseTuple(args, "ii:get_syscalls", &pid, &nsyscalls))
        return NULL;

    int *syscalls = get_syscalls(pid, nsyscalls, 1, true);

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

static PyObject *bluebird_cext_collect_io_data(PyObject *self, PyObject *args)
{
    pid_t pid;
    int call;

    if (!PyArg_ParseTuple(args, "ii:collect_wr_data", &pid, &call))
        return NULL;

    int enter = call == __NR_write ? 1 : 0;

    find_call(pid, call, enter, 0);

    /*
     * Write -> rdi:fd, rsi:buf, rdx:bytes
     * Read  -> rdi:fd, rsi:buf, rdx:bytes
     */

    struct user_regs_struct rgs;

    if (ptrace(PTRACE_GETREGS, pid, 0, &rgs) < 0) 
        return NULL;

    int fd_key = rgs.rdi;
    long addr = rgs.rsi;

    int word_block = (rgs.rdx & ~(WORD - 1)) + WORD;
    int words_to_read = word_block / WORD;
    char *words = malloc(word_block);

    for (int i=0; i < words_to_read; i++) {

        long read_string = bluebird_cext_read(pid, addr); 
        
        if (read_string < 0)
            return NULL;

        memcpy(words + (i * WORD), (char *) &read_string, WORD);

        addr += WORD;
    }
 
    words[rgs.rdx] = '\0';

    PyObject *io = PyDict_New();
    PyDict_SetItem(io, PyLong_FromLong(fd_key),
                       PyUnicode_FromString(words));

    return io;
}

static PyObject *bluebird_cext_resume(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i:resume", &pid))
        return NULL;

    int status;
    if (waitpid(pid, &status, __WALL | WNOHANG) < 0) {
        bluebird_cext_handle_error();
        return NULL;
    }
    
    if (!WIFSTOPPED(status))
        Py_RETURN_NONE;

    if (ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)
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

static int reset_ip(pid_t pid, struct user_regs_struct *rg)
{
    if (ptrace(PTRACE_SETREGS, pid, 0, rg) < 0 ||
        ptrace_call(PTRACE_CONT, pid, 0, 0) < 0) {
        return -1;
    }

    return 0;
}

static PyObject *bluebird_cext_goinit(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;

    if (!PyArg_ParseTuple(args, "ik:goinit", &pid, &addr))
        return NULL;

    struct user_regs_struct rg = { .rip=addr };

    reset_ip(pid, &rg);

    Py_RETURN_NONE;
}

static long bluebird_cext_write(pid_t pid, unsigned const long addr, 
                                           unsigned const long data)
{
    long write_ret = ptrace_call(PTRACE_POKEDATA, pid, addr, data); 

    if (write_ret < 0)
        return -1;

    return write_ret;
}

static PyObject *bluebird_cext_writeint(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;
    const long wr_data;

    if (!PyArg_ParseTuple(args, "ikl:writeint", &pid, &addr, &wr_data))
        return NULL;

    long writeint = bluebird_cext_write(pid, addr, wr_data);

    if (writeint < 0) {
        bluebird_cext_handle_error();
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_writestring(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned long addr;
    char *wr_data;

    if (!PyArg_ParseTuple(args, "iks:writestring", &pid, &addr, &wr_data))
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
        if (bluebird_cext_write(pid, addr, words[i]) < 0) {
            bluebird_cext_handle_error();
            return NULL;
        }

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

    bool yama_enabled = fgetc(yama) == '1' ? true : false;
    fclose(yama);

    return yama_enabled;
}

static bool is_traceable(void)
{
    uid_t uid = getuid();
    if (uid == 0) return true;
    
    return is_yama_enabled();
}

static PyObject *bluebird_cext_signal(PyObject *self, PyObject *args)
{
    int ptrace_signal; 
    pid_t pid;

    if (!PyArg_ParseTuple(args, "ii:signal", &pid, &ptrace_signal)) 
        return NULL;

    if (ptrace_call(PTRACE_CONT, pid, 0, ptrace_signal) < 0) { 
        bluebird_cext_handle_error();
        return NULL;
    }

    Py_RETURN_NONE;
}

static int find_syscall_exit(pid_t pid)
{
    struct user_regs_struct rg;

    while ( 1 ) {

        if (set_sys_step(pid, PTRACE_SYSCALL) < 0 ||
            ptrace(PTRACE_GETREGS, pid, 0, &rg) < 0)
            return -1;
        else if (rg.orig_rax == 219)
            break;
    }

    return 0;
}

static struct user_regs_struct *set_rip_local(pid_t pid, long heap_addr)
{
    struct user_regs_struct *rg = malloc(sizeof *rg);

    while ( 1 ) {

        if (set_sys_step(pid, PTRACE_SINGLESTEP) < 0 ||
            ptrace(PTRACE_GETREGS, pid, 0, rg) < 0)
            return NULL;
        else if ((signed) rg->rip < heap_addr)
            break;
    }

    return rg;
}

static int find_syscall_entrance(pid_t pid)
{
    struct user_regs_struct rg;

    while ( 1 ) {

        if (set_sys_step(pid, PTRACE_SYSCALL) < 0 ||
            ptrace(PTRACE_GETREGS, pid, 0, &rg) < 0) 
            break;

        if (rg.orig_rax == 219) continue;

        return 0;
    }

    return -1;
}

static unsigned long long insert_call(pid_t pid, long *args, int *offsets, 
                                      int narg, long heap_addr)
{
    struct user_regs_struct *orig_regs = NULL;

    if (find_syscall_exit(pid) < 0)
        return -1;

    orig_regs = set_rip_local(pid, heap_addr);

    if (orig_regs == NULL)
        goto error;

    if (find_syscall_entrance(pid) < 0)
        goto error;

    for (int i=0; i < narg; i++)
        if (ptrace(PTRACE_POKEUSER, pid, offsets[i] * WORD, args[i]) < 0)
            goto error;


    if (set_sys_step(pid, PTRACE_SYSCALL) < 0)
        goto error;

    struct user_regs_struct rg;

    ptrace(PTRACE_GETREGS, pid, 0, &rg);
    if (rg.rax < 0 || reset_ip(pid, orig_regs) < 0)
        goto error;

    free(orig_regs);

    return rg.rax;

error:

    if (orig_regs != NULL)
        free(orig_regs);

    bluebird_cext_handle_error();

    return -1;
}

static PyObject *bluebird_cext_bbrk(PyObject *self, PyObject *args)
{
    int pid;

    long brk_addr, heap_addr;

    if (!PyArg_ParseTuple(args, "ill:bbrk", &pid, &brk_addr, &heap_addr)) 
        return NULL;

    long _args[] = { SYS_brk, brk_addr };
    int offsets[] = { ORIG_RAX, RDI };

    insert_call(pid, _args, offsets, 2, heap_addr);

    Py_RETURN_NONE;
}

static int open_file(pid_t pid, long heap_addr, int mode)
{
    long args[] = { SYS_open, heap_addr, mode }; 
    int offsets[] = { ORIG_RAX, RDI, RSI, RDX };
    int fd = insert_call(pid, args, offsets, 4, heap_addr);

    return fd;
}

static PyObject *bluebird_cext_openfd(PyObject *self, PyObject *args)
{
    int pid, mode;
    long addr;

    if (!PyArg_ParseTuple(args, "iik:openfd", &pid, &mode, &addr))
        return NULL;

    int fd = open_file(pid, addr, mode);

    return PyLong_FromLong(fd);
}

static PyObject *bluebird_cext_redirect_fd(PyObject *self, PyObject *args)
{
    int pid, dupfd, mode;
    long addr, heap;

    if (!PyArg_ParseTuple(args, "iikik:redirect_fd", 
                          &pid, &dupfd, &addr, &mode, &heap))
        return NULL;

    int fd = open_file(pid, addr, mode);

    long call_args[] = { SYS_dup2, fd, dupfd };
    int offsets[] = { ORIG_RAX, RDI, RSI };

    insert_call(pid, call_args, offsets, 3, heap); 

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_bmmap(PyObject *self, PyObject *args)
{
    long mmap_addr, length, heap_addr;
    int pid, prot, flags, offset, fd;

    if (!PyArg_ParseTuple(args, "illiiili:bmmap", &pid, &mmap_addr, &length, 
                                                  &prot, &flags, &offset, 
                                                  &heap_addr, &fd))
        return NULL;

    long _args[] = { SYS_mmap, mmap_addr, length, prot, fd, offset, flags };
    int offsets[] = { ORIG_RAX, RDI, RSI, RDX, R8, R9, R10 };

    insert_call(pid, _args, offsets, 7, heap_addr);

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_bgetcwd(PyObject *self, PyObject *args)
{
    int pid, length;
    long addr, heap_addr;

    if (!PyArg_ParseTuple(args, "ilil:bgetcwd", &pid, &addr, 
                                             &length, &heap_addr))
        return NULL;

    long _args[] = { SYS_getcwd, addr, length };
    int offsets[] = { ORIG_RAX, RDI, RSI };

    insert_call(pid, _args, offsets, 3, heap_addr); 

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_attach(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!is_traceable()) {
        errno = EPERM;
        goto fallout;
    }

    if (!PyArg_ParseTuple(args, "i:attach", &pid)) 
        return NULL;

    if (ptrace_call(PTRACE_ATTACH, pid, 0, 0) < 0)
        goto fallout;

    if (ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)  
        goto fallout;

    Py_RETURN_NONE;

fallout:
    bluebird_cext_handle_error();
    return NULL;
}

static PyObject *bluebird_cext_detach(PyObject *self, PyObject *args)
{
    pid_t pid;
        
    if (!PyArg_ParseTuple(args, "i:detach", &pid)) 
        return NULL;

    if (ptrace_call(PTRACE_DETACH, pid, 0, 0) < 0) {
        bluebird_cext_handle_error();
        return NULL;
    }

    Py_RETURN_NONE;
}

static PyMethodDef bluebird_cextmethods[] = {
    {"attach", bluebird_cext_attach, METH_VARARGS,
     "attaches a trace on a running process"},
    {"detach", bluebird_cext_detach, METH_VARARGS,
     "detaches a currently traced process"},
    {"resume", bluebird_cext_resume, METH_VARARGS,
     "resumes a traced process currently stopped."},
    {"get_syscall", bluebird_cext_get_syscall, METH_VARARGS,
     "returns the current system call being made by process"},
    {"find_syscall", bluebird_cext_find_syscall, METH_VARARGS,
     "checks process on each system call stopping on call provided"},
    {"get_syscalls", bluebird_cext_get_syscalls, METH_VARARGS,
     "return a list of the last N system calls made by process"},
    {"readint", bluebird_cext_readint, METH_VARARGS,
     "reads an int from process address"},
    {"readstring", bluebird_cext_readstring, METH_VARARGS,
     "reads a string from process address"},
    {"writeint", bluebird_cext_writeint, METH_VARARGS,
     "writes int to process address"},
    {"writestring", bluebird_cext_writestring, METH_VARARGS,
     "writes string to process address"},
    {"signal", bluebird_cext_signal, METH_VARARGS,
     "allows for signal sending to attached process"},
    {"bbrk", bluebird_cext_bbrk, METH_VARARGS,
     "allows for bluebird_cext to extend the heap by means of brk"},
    {"bmmap", bluebird_cext_bmmap, METH_VARARGS,
     "creates a memory map for the traced process"},
    {"bgetcwd", bluebird_cext_bgetcwd, METH_VARARGS,
     "finds the current directory for the traced process"},
    {"redirect_fd", bluebird_cext_redirect_fd, METH_VARARGS,
     "redirects the pass a file-descriptor with another passed"},
    {"goinit", bluebird_cext_goinit, METH_VARARGS,
     "calls the process _init"},
    {"openfd", bluebird_cext_openfd, METH_VARARGS,
     "open and returns file descriptor"},
    {"continue_trace", bluebird_cext_continue_trace, METH_VARARGS,
     "sends a continue signal to a stopped traced process"},
    {"collect_io_data", bluebird_cext_collect_io_data, METH_VARARGS,
     "returns the data that is being written or read"}, 
    {NULL, NULL, 0, NULL}
};

PyModuleDef bluebird_cext_module = {
    PyModuleDef_HEAD_INIT,
    "bluebird_cext",
    NULL,
    -1,
    bluebird_cextmethods
};

PyMODINIT_FUNC PyInit_bluebird_cext(void) 
{ 
    return  PyModule_Create(&bluebird_cext_module); 
}

