#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static void usage(const char *cmd)
{
	fprintf(stderr, "Usage: %s <inf|nr> [ns]\n", cmd);
	exit(1);
}

#define NS 1000000000

int main(int argc, char *argv[])
{
	if (argc < 2)
		usage(argv[0]);

	char *arg = argv[1];

	if (strcmp("inf", arg) != 0) {
		char s[256];
		char *endptr;
		long n;

		n = strtol(arg, &endptr, 10);
		if (*endptr != '\0')
			usage(argv[0]);

		if (n <= 0)
			return 0;

		n--;
		snprintf(s, sizeof(s), "%lu", n);
		arg = s;
	}

	char *ns_str = argv[2];

	if (argc == 3) {
		char *endptr;
		long ns;

		ns = strtol(ns_str, &endptr, 10);
		if (*endptr != '\0')
			usage(argv[0]);

		if (ns <= 0)
			return 0;

		struct timespec request = { ns / NS , ns % NS };

		nanosleep(&request, NULL);
	}

	char *newargv[] = {argv[0], arg, argv[2], NULL};

	if (!execve(argv[0], newargv, NULL)) {
		perror("execve failed");
		exit(1);
	}

	return 0;
}
