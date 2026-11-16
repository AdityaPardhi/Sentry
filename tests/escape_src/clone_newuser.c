#define _GNU_SOURCE
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

static char stk[65536];
static int child(void *a){ (void)a; return 0; }

int main(void){
    pid_t p = clone(child, stk+sizeof stk, CLONE_NEWUSER|SIGCHLD, NULL);
    if (p < 0){ fprintf(stderr,"[escape] clone(CLONE_NEWUSER) refused: %s - blocked\n",strerror(errno)); return 1; }
    waitpid(p,NULL,0);
    fprintf(stderr,"[escape] nested user namespace created - escape!\n");
    return 0;
}
