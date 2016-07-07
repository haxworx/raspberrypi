#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD_LEN 1024
#define MAX_ARG_LEN 128

#define MAX_ARGS 12

int main(int argc, char **argv, char **envp)
{
	envp = 0;
	int i = 0;
	ssize_t len = 0;

	char buf[8192] = { 0 };
	char cmd[MAX_CMD_LEN] = { 0 };

	for (i = 1; i < argc && i <= MAX_ARGS; i++) {
		strncat(strncat(buf, " ", MAX_ARG_LEN -1) , argv[i], MAX_ARG_LEN);
		len = strlen(buf);
		if (len < MAX_CMD_LEN) {
			// ok
		} else 
			exit(1 << 8);	
	}

	if (!len) exit (1 << 7);

	snprintf(cmd, sizeof(cmd), "%s", buf);

	return system(cmd);
}
