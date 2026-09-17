#include <stdio.h>
#include <unistd.h>

char buf[128];
int
main()
{
    int	pid = getpid();
    printf("This is ex2 program\n");
    fgets(buf, sizeof(buf), stdin);
    return 0;
}
