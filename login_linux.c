/* $Header: https://svn.ita.chalmers.se/repos/security/edu/course/computer_security/trunk/lab/login_linux/login_linux.c 585 2013-01-19 10:31:04Z pk@CHALMERS.SE $ */

/* gcc -std=gnu99 -Wall -g -o mylogin login_linux.c -lcrypt */

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <string.h>
#include <signal.h>
#include <pwd.h>
#include <sys/types.h>
#include <crypt.h>
/* Uncomment next line in step 2 */
 #include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define PASS_AGE 10
#define MAX_FAILED 5

void sighandler() {

	/* add signalhandling routines here */
	/* see 'man 2 signal' */
}

void alert_user() {
    printf("\033[1;31mWarning:\033[0m Change your password!\n");
}

int main(int argc, char *argv[]) {

	/*struct passwd *passwddata; [> this has to be redefined in step 2 <]*/
	/* see pwent.h */
    mypwent *passwddata;

	char important1[LENGTH] = "**IMPORTANT 1**";

	char user[LENGTH];

	char important2[LENGTH] = "**IMPORTANT 2**";

	//char   *c_pass; //you might want to use this variable later...
	char prompt[] = "password: ";
	char *user_pass;

	sighandler();

	while (TRUE) {
		/* check what important variable contains - do not remove, part of buffer overflow test */
		printf("Value of variable 'important1' before input of login name: %s\n",
				important1);
		printf("Value of variable 'important2' before input of login name: %s\n",
				important2);

		printf("login: ");
		fflush(NULL); /* Flush all  output buffers */
		__fpurge(stdin); /* Purge any data in stdin buffer */

		if (fgets(user, LENGTH, stdin) == NULL) /* gets() is vulnerable to buffer */
			exit(0); /*  overflow attacks.  */

        char *ch = user;
        while (*ch != '\n') ch++; 
        *ch = '\0';


		/* check to see if important variable is intact after input of login name - do not remove */
		printf("Value of variable 'important 1' after input of login name: %*.*s\n",
				LENGTH - 1, LENGTH - 1, important1);
		printf("Value of variable 'important 2' after input of login name: %*.*s\n",
		 		LENGTH - 1, LENGTH - 1, important2);

		user_pass = getpass(prompt);
		passwddata = mygetpwnam(user);
        
		if (passwddata != NULL) {

            if (passwddata->pwfailed > MAX_FAILED) {
                printf("Max incorrect attempts reached \n");
                continue;
            }

			/* You have to encrypt user_pass for this to work */
			/* Don't forget to include the salt */

            // crypt function takes first two char out of true password as salt. 
            // True password also has those two chars in the password before the real password begins.
            char *hashed_pass = crypt(user_pass, passwddata->passwd_salt);
            if (!hashed_pass)
                return 2;

            printf("entered: %s vs true: %s\n", hashed_pass, passwddata->passwd);
			if (!strcmp(hashed_pass, passwddata->passwd)) {

                passwddata->pwage++;
                passwddata->pwfailed = 0;
                mysetpwent(user, passwddata);

                if (passwddata->pwage >= PASS_AGE)
                    alert_user();

				printf(" You're in !\n");

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */

                return 0;

			} else {
                sleep(2);
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
            }
		}

		printf("Login Incorrect \n");
	}
	return 0;
}
