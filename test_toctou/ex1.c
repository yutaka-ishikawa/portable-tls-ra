#include <stdio.h>
#include <unistd.h>

char buf[128];
int
main()
{
    int	pid = getpid();
    printf("#This process ID is %d\n", pid);
    printf("#Please issues the following commands from another window:\n");
    printf("$ ls -l /proc/%d/exe\n", pid);
    printf("$ stat /proc/%d/exe\n", pid);
    printf("$ sha256sum /proc/%d/exe\n", pid);
    printf("$ cp ex2 ex1\n");
    printf("# this copy fails because the file is busy. But remove is allowed:\n");
    printf("$ rm ex1\n");
    printf("$ cp ex2 ex1\n");
    printf("# Look at the exe path!!\n");
    printf("$ ls -l /proc/%d/exe\n", pid);
    printf("$ stat /proc/%d/exe\n", pid);
    printf("$ sha256sum /proc/%d/exe\n", pid);
    printf("You will see the exe path still follows the original ex1 binary. The same hash value is obtained.\n");
    printf("That is, TOCTOU attacks on binary measurement are prevented by measuring via the /proc/<pid>/exe symlink.\n");
    
    fgets(buf, sizeof(buf), stdin);
    return 0;
}
