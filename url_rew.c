#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

/* length of url + method + ident + src_address */
#define mbfsiz 800

/* global vars */
char default_urlfile[] = "/usr/local/asqredir/urls.txt";
char root_dir[] = "/";

char url[256];
char method[32];
char ident[256];
char src_address[256];
char line[mbfsiz];

struct up *block;
struct up *cur;
struct ul *allow;
struct ul *ruc;

FILE *logfile;


/* struct used as list element for keeping a block pattern and a url */
struct up {
	regex_t url;
	char redir[256];
	int line;
	struct up *next;
};

/* struct used as list element for keeping allow url pattern */
struct ul {
	regex_t url;
	int line;
	struct ul *next;
};


/* append url pattern and redirect url to up list 
	ourl: pattern 
	nurl: redirect url
*/
int add_blockurl(char *ourl, char *nurl, int no)
{
	struct up *cur;

	if (block == NULL) {
		if ((block = malloc(sizeof(*block))) != NULL) {
			if (regcomp(&block->url, ourl, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n",ourl);
				return EXIT_FAILURE;
			}
			strcpy(block->redir, nurl);
			block->line = no;
			block->next = NULL;
		} else {
			fprintf(stderr, "unable to allocate memory\n%s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		cur = block;
		while (cur->next != NULL) {
			cur = cur->next;
		}
		if ((cur->next = malloc(sizeof(*cur))) != NULL) {
			cur = cur->next;
			if (regcomp(&cur->url, ourl, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n",ourl);
				return EXIT_FAILURE;
			}
			strcpy(cur->redir, nurl);
			cur->line = no;
			cur->next = NULL;
		} else {
			fprintf(stderr, "unable to allocate memory\n%s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

/* append url pattern to ul list */
int add_allowurl(char *ourl, int no)
{
	struct ul *ruc;

	if (allow == NULL) {
		if ((allow = malloc(sizeof(*allow))) != NULL) {
			if (regcomp(&allow->url, ourl, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n",ourl);
				return EXIT_FAILURE;
			}
			allow->line = no;
			allow->next = NULL;
		} else {
			fprintf(stderr, "unable to allocate memory\n%s", strerror(errno));
			return EXIT_FAILURE;
		}
	} else {
		ruc = allow;
		while (ruc->next != NULL) {
			ruc = ruc->next;
		}
		if ((ruc->next = malloc(sizeof(*ruc))) != NULL) {
			ruc = ruc->next;
			if (regcomp(&ruc->url, ourl, REG_NOSUB|REG_EXTENDED|REG_ICASE)) {
				fprintf(stderr, "regcomp failed for %s\n",ourl);
				return EXIT_FAILURE;
			}
			ruc->line = no;
			ruc->next = NULL;
		} else {
			fprintf(stderr, "unable to allocate memory\n%s\n", strerror(errno));
			return EXIT_FAILURE;
		}
	}
	return EXIT_SUCCESS;
}

/* tests the http request and returns the redirect information if necessary
	line: the original http request as passed by squid
	return: empty string if unmatched, redirect information else
*/
char *matchurl()
{
	sscanf(line, "%255s %255s %255s %31s", url, src_address, ident, method);

	/* check allow rules first, return empty string if matched */
	ruc = allow;
	while (ruc != NULL) {
		if(!regexec(&ruc->url, url, (size_t) 0, NULL, 0)) {
			return("");
		}
		ruc = ruc->next;
	}

	/* check block rules, return redirect line or empty string */
	cur = block;
	while (cur != NULL) {
		if(!regexec(&cur->url, url, (size_t) 0, NULL, 0)) {
			sprintf(line, "%s %s %s %s", cur->redir, 
			  src_address, ident, method);
			return line;
		}
		cur = cur->next;
	}
	return("");
}

/* same as matchurl() but with logging 
   overhead of redundant code chosen for better performance (loglevel checking)
*/
char *matchurl_log()
{
	sscanf(line, "%255s %255s %255s %31s", url, src_address, ident, method);

	/* check allow rules first, return empty string if matched */
	ruc = allow;
	while (ruc != NULL) {
		if(!regexec(&ruc->url, url, (size_t) 0, NULL, 0)) {
			fprintf(logfile, "pass %d %s\n", ruc->line, url);
			return("");
		}
		ruc = ruc->next;
	}

	/* check block rules, return redirect line or empty string */
	cur = block;
	while (cur != NULL) {
		if(!regexec(&cur->url, url, (size_t) 0, NULL, 0)) {
			sprintf(line, "%s %s %s %s", cur->redir,
			  src_address, ident, method);
			fprintf(logfile, "deny %d %s\n", cur->line, url);
			return line;
		}
		cur = cur->next;
	}
	return("");
}

/* free memory used for all up and ul structs kept in list */
void freeurls()
{
	while (block != NULL) {
		cur = block->next;
		regfree(&block->url);
		free(block);
		block = cur;
	}
	while (allow != NULL) {
		ruc = allow->next;
		regfree(&allow->url);
		free(allow);
		allow = ruc;
	}
}


/* reads content of config file
	filename: name of config file including path
	recognizes lines starting with '#' as comments
*/
void readfile(char *filename)
{
	char comment = '#';
	char pass = '~';
	char ourl[256];
	char nurl [256];
	int i;
	FILE *urlfile;

	if ((urlfile = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "unable to open config file %s\n%s\n",
		  filename, strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		freeurls();
		for (i=1; fgets(line, mbfsiz, urlfile) != NULL; i++) {

			/* ignore empty lines */
			if (strlen(line) <= 1) {
				continue;
			}

			/* ignore comments */
			if (line[0] == comment) {
				continue;
			}

			/* handle pass rules */
			if (line[0] == pass) {
				if (sscanf(line, "%1s%255s", nurl, ourl) != 2) {
					fprintf(stderr, "invalid format in %s, line %d: %s\n",
					  filename, i, line);
					fclose(urlfile);
					freeurls();
					exit(EXIT_FAILURE);
				}

				/* call add_allowurl() */
				if (add_allowurl(ourl, i) != EXIT_SUCCESS) {
					fclose(urlfile);
					freeurls();
					exit(EXIT_FAILURE);
				}
				continue;
			}

			/* must be a deny rule */
			if (sscanf(line, "%255s %255s", ourl, nurl) != 2) {
				fprintf(stderr, "invalid format in %s, line %d: %s\n", 
				  filename, i, line);
				fclose(urlfile);
				freeurls();
				exit(EXIT_FAILURE);
			} 

			/* call add_blockurl() */
			if (add_blockurl(ourl, nurl, i) != EXIT_SUCCESS) {
				fclose(urlfile);
				freeurls();
				exit(EXIT_FAILURE);
			}
		}
	}
	fclose(urlfile);
}

/* helpmsg() prints help message whit usage options */
void helpmsg(char *arg0)
{
	fprintf(stderr, "\nusage: %s <urlfile> <logfile>\nboth arguments ", arg0);
	fprintf(stderr, "are optional, except that you need to\nspecify both of ");
	fprintf(stderr, "them in order to use the logging feature.\n\n");
}


/* main function
	argv[1]: urlfile (optional, default set to default_urlfile)
	argv[2]: logfile (optional, no default, requires argv[1])
*/
int main(int argc, char **argv)
{
	int loglevel = 0;
	char filename[256];
	char logfilename[256];

	/* handle command line args: assign filenames, set loglevel */
	if (argc > 3) {
		fprintf(stderr, "wrong number of arguments! %s -h for help\n", argv[0]);
		exit(EXIT_FAILURE);
	} else if (argc == 3) {
		loglevel = 2;
		strncpy(logfilename, argv[2], 255);
		strncpy(filename, argv[1], 255);
	} else if (argc == 2) {
		if (strcmp(argv[1], "-h")==0 || strcmp(argv[1], "--help")==0) {
			helpmsg(argv[0]);
			exit(EXIT_FAILURE);
		} else {
			strncpy(filename, argv[1], 255);
		}
	} else {
		strncpy(filename, default_urlfile, 255);
	}

	/* read config file into up/ul lists */
	readfile(filename);

	/* make standard output line buffered */
	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
		fprintf(stderr, "unable to configure stdout buffer\n");
		exit(EXIT_FAILURE);
	}

	/* check loglevel, then loop until EOF from stdin */
	if (loglevel > 1) {

		/* open logfile for appending in line buffered mode */
		if ((logfile = fopen(logfilename, "a")) == NULL) {
			fprintf(stderr, "unable to open log file %s\n%s\n",
			  logfilename, strerror(errno));
			exit(EXIT_FAILURE);
		 } else {
			if (setvbuf(logfile, NULL, _IOLBF, 0) != 0) {
				fprintf(stderr, "unable to configure logfile buffer\n");
				exit(EXIT_FAILURE);
			}
		}

		/* change working dir to "/" to prevent problems with umount */
		if (chdir(root_dir) != 0) {
			fprintf(stderr, "unable to change working dir to %s\n", root_dir);
			exit(EXIT_FAILURE);
		}

		while(fgets(line, mbfsiz, stdin) != NULL) {
			fprintf(stdout, "%s\n", matchurl_log());
		}

		/* close logfile after EOF */
		fclose(logfile);

	} else {

		/* change working dir to "/" to prevent problems with umount */
		if (chdir(root_dir) != 0) {
			fprintf(stderr, "unable to change working dir to %s\n", root_dir);
			exit(EXIT_FAILURE);
		}

		while(fgets(line, mbfsiz, stdin) != NULL) {
			fprintf(stdout, "%s\n", matchurl());
		}
	}

	/* EOF, after 'squid -k reconfigure' or shutdown */
	freeurls();
	exit(EXIT_SUCCESS);
}
