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
#include <wait.h>
/* Uncomment next line in step 2 */
 #include "pwent.h" 

#define TRUE 1
#define FALSE 0
#define LENGTH 16
#define PASS_AGE 10
#define MAX_FAILED 5

void sighandler() {

    // Iterating through all signals (apparently we have 32 different signals in linux) and ignore them.
    for (int i = 0 ; i < 32; i++)
        signal(i, SIG_IGN);
        
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

    // Just having a new line char at the end in order to hand the case of password with the size of LENGTH.
	char user[LENGTH + 1];
    user[LENGTH] = '\n';

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

		if (fgets(user, LENGTH, stdin) == NULL) {
            exit(0);
        }

        char *ch = user;
        while (*ch != '\n') ch++; // finding the new line char to replace it with terminator char. 
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
            // However, here we have the passwd salt so there isnt any need to pass the true password.
            char *hashed_pass = crypt(user_pass, passwddata->passwd_salt);
            if (!hashed_pass)
                return 2;

            /*printf("entered: %s vs true: %s\n", hashed_pass, passwddata->passwd);*/
			if (!strcmp(hashed_pass, passwddata->passwd)) {

                passwddata->pwage++;
                passwddata->pwfailed = 0;
                mysetpwent(user, passwddata);

                if (passwddata->pwage >= PASS_AGE) // alert the user in the case of coming to the password age time.
                    alert_user();

				printf(" You're in !\n");

				/*  check UID, see setuid(2) */
				/*  start a shell, use execve(2) */
                
                char* args[] = {NULL};
                char* env[] = {NULL};

                // We are forking a shell.
                pid_t pid = fork();
                switch (pid)
                {
                case 0:
                    // We are in child, lets set uid.
                    if (setuid(passwddata->uid) == -1) {
                        printf("Error assigning user permissions");
                        exit(1);
                    }
                    
                    // Execute bin sh.
                    if (execve("/bin/sh", args, env) == -1) {
                        printf("Could now execute login shell");
                        exit(1);
                    }

                    break;
                case -1:
                    // Fork failed
                    printf("fork error");
                    continue;

                default: {
                        int status;
                        // we should wait on the child process.
                        waitpid(pid, &status, 0);
                        break;
                    }
                }

			} else {
                sleep(2); // sleep in the case of wrong password.
                passwddata->pwfailed++;
                mysetpwent(user, passwddata);
            }
		}

		printf("Login Incorrect \n");
	}
	return 0;
}
