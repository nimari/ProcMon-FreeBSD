/* SPDX-License-Identifier: MIT */
/* Already-execed owned fixture: loopback network, process and concurrent calls. */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <pthread_np.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
static int output;
static void *writes(void *argument)
{
    unsigned index = (uintptr_t)argument;
    unsigned char bytes[8] = {'T', (unsigned char)index, 0, 255, '"', '\\', 10, 127};
    int tid = pthread_getthreadid_np(), failed = 0;
    for (unsigned count = 0; count < 20; ++count) failed |= write(output,bytes,sizeof(bytes)) != sizeof(bytes);
    printf("THREAD\t%d\t%u\t%d\t20\t%d\n",tid,index,output,failed);
    return (void *)(uintptr_t)failed;
}
int main(int argc, char **argv)
{
    if (argc != 8 || !getuid() || getuid() != strtoul(argv[2],NULL,10) || getgid() != strtoul(argv[3],NULL,10)) return 2;
    alarm(90);
    printf("TARGET_READY\t%d\t%d\t%u\t%u\n",getpid(),pthread_getthreadid_np(),getuid(),getgid()); fflush(stdout);
    char byte; if (read(atoi(argv[4]),&byte,1) != 1) return 2; close(atoi(argv[4]));
    int failures = 0;
    output = open("/dev/null",O_WRONLY); if (output < 0) return 2;
    pthread_t threads[3];
    for (unsigned index = 0; index < 3; ++index) if (pthread_create(&threads[index],NULL,writes,(void *)(uintptr_t)index)) return 2;
    for (unsigned index = 0; index < 3; ++index) { void *result; if (pthread_join(threads[index],&result)) return 2; failures += (uintptr_t)result; }
    close(output);
    int server = socket(AF_INET,SOCK_STREAM,0), client = socket(AF_INET,SOCK_STREAM,0);
    struct sockaddr_in address = {.sin_len = sizeof(address), .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t length = sizeof(address);
    if (server < 0 || client < 0 || bind(server,(struct sockaddr *)&address,sizeof(address)) ||
        getsockname(server,(struct sockaddr *)&address,&length) || listen(server,1) ||
        connect(client,(struct sockaddr *)&address,sizeof(address))) return 2;
    int peer = accept(server,NULL,NULL); if (peer < 0) return 2;
    const unsigned char payload[] = {'N',0,255,'"','\\',10,127,'Z'};
    unsigned char buffer[8];
    errno = 0; ssize_t sent = sendto(client,payload,sizeof(payload),0,NULL,0); int sentError = errno;
    errno = 0; ssize_t received = read(peer,buffer,sizeof(buffer)); int receiveError = errno;
    failures += sent != 8 || received != 8 || sentError || receiveError || memcmp(buffer,payload,8);
    printf("NETWORK\t%d\t%d\t%zd\t%d\t%zd\t%d\n",client,peer,sent,sentError,received,receiveError);
    off_t written = -1; const off_t offset = INT64_C(0x1122334455667788);
    errno = 0;
    long result = syscall(SYS_sendfile,-1,client,offset,(size_t)1,NULL,&written,0x40); int error = errno;
    failures += result != -1 || error != EBADF;
    printf("SENDFILE\t%d\t%" PRId64 "\t%zu\t%" PRIuPTR "\t%ld\t%d\n",client,offset,(size_t)1,(uintptr_t)&written,result,error);
    close(peer); close(client); close(server);
    void *map = mmap(NULL,4096,PROT_READ | PROT_WRITE,MAP_PRIVATE | MAP_ANON,-1,0);
    failures += map == MAP_FAILED; if (map != MAP_FAILED) { memset(map,1,4096); failures += munmap(map,4096) != 0; }
    pid_t child = fork(); if (child == 0) _exit(7);
    int status = 0; failures += child < 0 || waitpid(child,&status,0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 7;
    printf("PROCESS\t%d\t%d\n",child,status);
    printf("ADVANCED\t%d\t%d\n",getpid(),failures);
    return failures ? 1 : 0;
}
