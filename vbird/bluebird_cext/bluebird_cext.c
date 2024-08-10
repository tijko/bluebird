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

        
#define WAIT_SLEEP 5000

#define WORD (__WORDSIZE / CHAR_BIT)

#define WORD_ALIGNED(data_length) data_length + (WORD - (data_length % WORD))

#define EWAITBLK 0x100

static void handle_error(void)
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
        // Locally defined errnos
        case (EWAITBLK):
            message_str = "WAITPID-BLKD";
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

static void ptrace_sleep(void)
{
    struct timeval tm = { .tv_usec=WAIT_SLEEP, .tv_sec = 0 };

    select(0, NULL, NULL, NULL, &tm);
}

static int ptrace_wait(pid_t pid)
{
    int status;

    for (int i=0; i < 2; i++) {

        if (waitpid(pid, &status, __WALL | WNOHANG) < 0) {
            handle_error(); 
            return -1;
        }

        if (WIFSTOPPED(status)) 
            return 0;

        ptrace_sleep();
    }

    errno = EWAITBLK;

    return -1;
}

static int ptrace_stop(pid_t pid)
{
    if (sigqueue(pid, SIGSTOP, (union sigval) 0) < 0) {
        handle_error(); 
        return -1;
    }

    ptrace_sleep();

    if (ptrace_wait(pid) < 0) 
        return -1;

    return 0;
}

static bool is_stopped(pid_t pid)
{
    char proc_pid_path[PATH_MAX + 1];
    snprintf(proc_pid_path, PATH_MAX, "/proc/%d/stat", pid);

    FILE *fobj = fopen(proc_pid_path, "r");

    if (!fobj) 
        goto error;

    char state;
    if (fscanf(fobj, "%d%s %c", &pid, proc_pid_path, &state) < 0)
        goto error;

    fclose(fobj);

    bool pid_state = state == 't' ? true : false;

    return pid_state;

error:
    handle_error();
    return false;
}

long ptrace_call(enum __ptrace_request req, pid_t pid, 
                 unsigned long addr, long data)
{
    // 1st check if the request is attach if it is there is no need to sigstop
    // 2nd check if process is already if it is there is no need to stop
    // if the first two conditions aren't meet send a sigstop 
    if (req != PTRACE_ATTACH && !is_stopped(pid) && ptrace_stop(pid) < 0)
        return -1;

    // set errno to zero in case there was a peekdata that was holding -1
    errno = 0;
    long ptrace_ret = ptrace(req, pid, addr, data);

    if (ptrace_ret < 0 && errno != 0) {
        handle_error(); 
        return -1;
    }

    return ptrace_ret;
}

static int reset_ip(pid_t pid, struct user_regs_struct *rg)
{
    long ret = 0;

    ptrace(PTRACE_SETREGS, pid, 0, rg);

    ret = ptrace(PTRACE_CONT, pid, 0, 0);

    return ret;
}

static int set_sys_step(pid_t pid, enum __ptrace_request step)
{
    long ret = 0;

    ret = ptrace_call(step, pid, 0, 0);

    if ((ret = waitpid(pid, NULL, __WALL)) < 0)
        handle_error();

    return ret;
}

static int get_callnum(pid_t pid)
{
    struct user_regs_struct rgs;
    long ret = 0;

    if ((ret = set_sys_step(pid, PTRACE_SYSCALL)) < 0)
        return ret;

    if ((ret = ptrace(PTRACE_GETREGS, pid, 0, &rgs)) < 0) {
        handle_error();
        return -1;
    }    

    return rgs.orig_rax;
}

static int ptrace_syscall(pid_t pid, int enter, bool signal_cont)
{
    int call = -ENOSYS;

    while (call == -ENOSYS || call == 219) {
        if ((call = get_callnum(pid)) < 0)
            return -1;
    }

    if (!enter && (call = get_callnum(pid)) < 0) 
        return -1;

    if (signal_cont == true && ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)
        return -1;

    return call;
}

static int find_call(pid_t pid, int call, int enter, int timeout)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    clock_t start = ts.tv_sec;

    long ret = 0;

    while ((ret = ptrace_syscall(pid, enter, true)) != call) {

        if (ret < 0)
            break;

        if (timeout > 0) {
            clock_gettime(CLOCK_REALTIME, &ts);
            if ((ts.tv_sec - start) > timeout)
                break;
        }
    }

    return ret;
}

static long *create_wordsize_array(char *data)
{
    size_t data_length = strlen(data);
    
    int num_of_words = (data_length / WORD);

    if (data_length % WORD != 0)
        num_of_words += 1;

    char word_buffer[WORD + 1] = { '\0' };
    long *words = malloc(sizeof *words * num_of_words + 1);

    for (int i=0; i < num_of_words; i++) {
        memcpy(word_buffer, data + (WORD * i), WORD);
        words[i] = *(long *) word_buffer;
    }

    words[num_of_words] = 0;

    return words;
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

static struct user_regs_struct *set_rip_local(pid_t pid, long heap_addr)
{
    struct user_regs_struct *rg = malloc(sizeof *rg);
    rg->rip = heap_addr;
    while (rg->rip >= heap_addr) {

        if (set_sys_step(pid, PTRACE_SINGLESTEP) < 0 ||
            ptrace(PTRACE_GETREGS, pid, 0, rg) < 0)
            return NULL;
    }

    return rg;
}

static unsigned long long insert_call(pid_t pid, long *args, int *offsets, 
                                      int narg, long heap_addr)
{
    struct user_regs_struct *orig_regs = NULL;

    if (ptrace_syscall(pid, 0, false) < 0)
        return -1;

    orig_regs = set_rip_local(pid, heap_addr);

    if (orig_regs == NULL)
        goto error;

    if (ptrace_syscall(pid, 1, false) < 0)
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

    handle_error();

    return -1;
}

static int open_file(pid_t pid, long heap_addr, int mode)
{
    long args[] = { SYS_open, heap_addr, mode }; 
    int offsets[] = { ORIG_RAX, RDI, RSI, RDX };
    int fd = insert_call(pid, args, offsets, 4, heap_addr);

    return fd;
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

        long read_string = ptrace_call(PTRACE_PEEKDATA, pid, addr, 0);
        
        if (read_string < 0)
            goto error;

        memcpy(words + (i * WORD), (char *) &read_string, WORD);

        addr += WORD;
    }
 
    ptrace(PTRACE_CONT, pid, 0, 0);

    for (int i=0; i < WORD * words_to_read; i++)
        if (words[i] == '\0')
            words[i] = '\n';

    words[WORD * words_to_read] = '\0';

    return Py_BuildValue("s", words);

error:
    free(words);
    handle_error();
    return NULL;
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

static PyObject *bluebird_cext_readint(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;

    if (!PyArg_ParseTuple(args, "ik:readint", &pid, &addr))
        return NULL;

    long read_int = ptrace_call(PTRACE_PEEKDATA, pid, addr, 0);

    if (read_int < 0) {
        handle_error();
        return NULL;
    }

    return Py_BuildValue("i", read_int);
}

static PyObject *bluebird_cext_get_syscall(PyObject *self, PyObject *args)
{
    pid_t pid;

    if (!PyArg_ParseTuple(args, "i:get_syscall", &pid))
        return NULL;

    int call = ptrace_syscall(pid, 1, true);

    PyObject *pycall = PyLong_FromLong(call);

    return pycall;
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
    ptrace_stop(pid);
    ptrace(PTRACE_GETREGS, pid, 0, &rgs);

    int fd_key = rgs.rdi;
    long addr = rgs.rsi;

    int word_block = (rgs.rdx & ~(WORD - 1)) + WORD;
    int words_to_read = word_block / WORD;
    char *words = malloc(word_block);

    for (int i=0; i < words_to_read; i++) {

        long read_string = ptrace_call(PTRACE_PEEKDATA, pid, addr, 0);
        
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
        handle_error();
        return NULL;
    }
    
    if (!WIFSTOPPED(status))
        Py_RETURN_NONE;

    if (ptrace_call(PTRACE_CONT, pid, 0, 0) < 0)
        return NULL;

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_get_syscalls(PyObject *self, PyObject *args)
{
    pid_t pid;
    int nsyscalls;

    if (!PyArg_ParseTuple(args, "ii:get_syscalls", &pid, &nsyscalls))
        return NULL;

    PyObject *call_list = PyList_New(nsyscalls);


    for (int i=0; i < nsyscalls; i++) {
        int call = ptrace_syscall(pid, 1, true);
        PyObject *pycall = PyLong_FromLong(call);
        PyList_SetItem(call_list, i, pycall);
    }

    return call_list;
}

static PyObject *bluebird_cext_goinit(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;

    if (!PyArg_ParseTuple(args, "ik:goinit", &pid, &addr))
        return NULL;

    struct user_regs_struct *rg = calloc(1, sizeof *rg);
    rg->rip = addr;
    
    if (!is_stopped(pid))
        ptrace_stop(pid);

    reset_ip(pid, rg);
    free(rg);

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_writeint(PyObject *self, PyObject *args)
{
    pid_t pid;
    unsigned const long addr;
    const long wr_data;

    if (!PyArg_ParseTuple(args, "ikl:writeint", &pid, &addr, &wr_data))
        return NULL;

    long writeint = ptrace_call(PTRACE_POKEDATA, pid, addr, wr_data);

    if (writeint < 0) {
        handle_error();
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

    for (int i=0; words[i] != 0; i++) {
        if (ptrace_call(PTRACE_POKEDATA, pid, addr, words[i]) < 0) 
            return NULL;

        addr += WORD;
    }

    free(words);

    ptrace(PTRACE_CONT, pid, 0, 0);

    Py_RETURN_NONE;
}

static PyObject *bluebird_cext_signal(PyObject *self, PyObject *args)
{
    int ptrace_signal; 
    pid_t pid;

    if (!PyArg_ParseTuple(args, "ii:signal", &pid, &ptrace_signal)) 
        return NULL;

    if (ptrace_call(PTRACE_CONT, pid, 0, ptrace_signal) < 0) { 
        handle_error();
        return NULL;
    }

    Py_RETURN_NONE;
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

static PyObject *bluebird_cext_callmap(PyObject *self, PyObject *args)
{
    pid_t pid;
    long addr;

    /* Start with generic set-call (ie syscall and args default)
     * Use the address of created mmap, or call mprotect on heap
     * write the opcodes to the address
     * save the old registers
     * set the IP to address, set other args (eg rax, rcx, rdx, ...)
     * setup a ptrace syscall
     * once the call is complete, write the old registers back
     *
     * Write -> rdi:fd, rsi:buf, rdx:bytes
     * Read  -> rdi:fd, rsi:buf, rdx:bytes
     *
     * syscall opcode -> 0f 05
     *
     */

    if (!PyArg_ParseTuple(args, "il:callmap", &pid, &addr))
        return NULL;

    int narg = 3;
    //long _args[] = { SYS_exit, 0, addr };
    //int offsets[] = { ORIG_RAX, RDI, RIP };
    //long _args[] = { SYS_reboot, 0x4321fedc, addr };
    //int offsets[] = { ORIG_RAX, RDI, RIP };

    //if (ptrace_stop(pid) < 0)
    //    return NULL;
    //
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    int status;
    waitpid(pid, &status, __WALL);
    if (!WIFSTOPPED(status)) {
        errno = EBADF;
        return NULL;
    }

    struct user_regs_struct *rg = calloc(1, sizeof *rg);
    rg->rip = addr;
    rg->orig_rax = SYS_reboot;
    rg->rdi = 0x4321fedc;
    ptrace(PTRACE_SETREGS, pid, rg, 0);
    ptrace(PTRACE_SYSCALL, pid, 0, 0);
    waitpid(pid, &status, __WALL);
    if (!WIFSTOPPED(status)) {
        errno = EBADF;
        return NULL;
    }

    /*
    for (int i=0; i < narg; i++)
        if (ptrace(PTRACE_POKEUSER, pid, offsets[i] * WORD, args[i]) < 0)
    */

    ptrace(PTRACE_CONT, pid, 0, 0);

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
    handle_error();
    return NULL;
}

static PyObject *bluebird_cext_detach(PyObject *self, PyObject *args)
{
    pid_t pid;
        
    if (!PyArg_ParseTuple(args, "i:detach", &pid)) 
        return NULL;

    if (ptrace_call(PTRACE_DETACH, pid, 0, 0) < 0) {
        handle_error();
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
    {"callmap", bluebird_cext_callmap, METH_VARARGS,
     "callmap"},
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

