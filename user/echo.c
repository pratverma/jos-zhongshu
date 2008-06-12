#include <inc/lib.h>

void
umain(int argc, char **argv)
{
	int i, nflag,length;

	nflag = 0;
	length = 0;
	if (argc > 1 && strcmp(argv[1], "-n") == 0) {
		nflag = 1;
		argc--;
		argv++;
	}
	for (i = 1; i < argc; i++) {
		if (i > 1)
			write(1, " ", 1);
		write(1, argv[i], strlen(argv[i]));
		length += strlen(argv[i]);
	}
	if (!nflag)
	{
		write(1, "\n", 1);
		length += 1;
	}
	//ftruncate(1,length);
	
}
