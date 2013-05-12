#include <signal.h>
#include <stdlib.h>
int main (int argc, char** argv) {
 if (signal(SIGCHLD,SIG_IGN)==SIG_ERR) exit(255);
 execv(argv[1],argv+1);
}
