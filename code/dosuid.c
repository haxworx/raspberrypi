#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CMD_LEN 1024
#define MAX_ARG_LEN 128
#define MAX_ARGS 12


char *commands_available[] = {
	"ls",
	"pwd",
	NULL,
};

int command_is_ok = 0;

int main(int argc, char **argv, char **envp)
{
	envp = 0;
	int i = 0;
	ssize_t len = 0;

	char buf[8192] = { 0 };
	char cmd[MAX_CMD_LEN] = { 0 };

	if (argc < 2) exit(1 << 5);

	for (i = 0; commands_available[i] != NULL; i++) {
		if (!strcmp(argv[1], commands_available[i])) {
			command_is_ok = 1;
			break;
		}
	}
	
	if (!command_is_ok) exit(1 << 6);
	
	for (i = 1; i < argc && i <= MAX_ARGS; i++) {
		strncat(strncat(buf, " ", MAX_ARG_LEN -1) , argv[i], MAX_ARG_LEN);
		len = strlen(buf);
		if (len < MAX_CMD_LEN) {
			// ok
		} else 
			exit(1 << 7);	
	}

	if (!len) exit (1 << 8);

	snprintf(cmd, sizeof(cmd), "%s", buf);

	return system(cmd);
}
