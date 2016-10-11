#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <errno.h>
#include <time.h>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

//MACROS
//STUDENT_ID is the Student ID on the system
//SHELL is the Shell environment to be passed into execve()
//KRB5CCNAME is the KRB environment to be passed into execve()
//PATH is the PATH environment to be passed into execve()
//FILEPATH is the path to sniff that is used in various functions.

//HOME MACROS
//#define STUDENT_ID 501
//#define SHELL "SHELL=/pkg/bin/tcsh"
//#define KRB5CCNAME NULL
//#define PATH "PATH=/usr/local/ant/bin:/Users/dehowefeng/ant/bin:/Library/Frameworks/Python.framework/Versions/2.7/bin:/Library/Frameworks/Python.framework/Versions/3.4/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin:/Library/TeX/texbin"
//#define FILEPATH "/Users/dehowefeng/Documents/Programs/ECS153/HW4/sniff"

//CSIF MACROS
#define STUDENT_ID 7005824
#define SHELL "SHELL=/bin/bash"
#define KRB5CCNAME "KRB5CCNAME=KEYRING:persistent:7005824"
#define PATH "PATH=/usr/lib64/qt-3.3/bin:/usr/lib64/ccache:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/pkg/bin:/usr/local/bin:/opt/altera9.1/quartus/bin:.:/usr/java/latest"
#define FILEPATH "/home/dehowef/ECS153/HW4/sniff"

using namespace std;

int main(int argc, char *argv[]){

	if(argc > 1){
		cerr << "too many arguments. quitting now." << endl;
		exit(-1);
	}
//Check that the student is running the program by comparing the real UID 
//of the process with that of the student.

	if(getuid() != STUDENT_ID){

		cerr << "Error: You are not authorized to run this program. Exiting now."<< endl; 
		exit(-1);
	}

	pid_t childPID = fork();

	if(childPID < 0) {
    	perror("fork");
   		exit(1);
	}

	if(childPID == 0) { //CHILD PROCESS

//Run kinit for authentication.
		
		char  *parmList[] ={ (char*)"kinit", NULL};

		char *envParms[4] = { (char*)SHELL, (char*)PATH, (char*)KRB5CCNAME, NULL};

		//cout << "PATH is: " << getenv("PATH") << endl; 
		//cout << "KRB5CCNAME is: " << getenv("KRB5CCNAME") << endl;
		//cout << "SHELL is: " << getenv("SHELL") << endl;

		execve("/usr/bin/kinit", parmList, envParms);

   		exit(0);

	} else { //PARENT PROCESSS

    	int returnStatus;

    	waitpid(childPID, &returnStatus, 0);

    	if(returnStatus != 0){
    		cerr << "Error: Incorrect Password. Program will now quit." << endl;
    		exit(-1);
		}

//If the current working directory does not contain a file called sniff,
//print an error message and exit.

		if(access("sniff", F_OK) == -1 ){
			cerr << "Error: sniff does not exist!" << endl;
			exit(-1);
		}

//If sniff is not owned by the student, or is not executable by the owner of 
//the file, or can be read, written, or executed by anyone else (except, of
//course, root), print an error message and exit.

		struct stat file;
		if(stat(FILEPATH, &file) == -1){
		cerr << "Error: sniff does not exist!" << endl;
		}
		//cout << "sniff's UID is: " << file.st_uid << endl;
		int permissions = file.st_mode % 64; //non user permissions to be checked.
		//mod by 64 to get the last 2 digits of permissions
		//cout << "sniff's non-user persimmons is: " << oct << permissions << endl;

		if(file.st_uid != STUDENT_ID || access("sniff", X_OK ) == -1 || permissions != 00) {
			cerr << "Error: you are not the owner of sniff, or there may be excess rights to sniff." << endl;
			exit(-1);
		}

//If sniff was created or modified over 1 minute ago, print an error 
//message and exit.

		time_t currenttime;

		//cout << "File last modified at: " << file.st_mtime << endl;
		//cout << "Current time is: " << time(&currenttime) << endl;

		if(time(&currenttime) - file.st_mtime > 60) {
			cerr << "Error: sniff was created/modified over a minute ago." << endl;
			exit(-1);
		}

//Change the ownership of sniff to root (UID 0), its group to proj (GID 
//95), and its protection mode to 4550.

		char *parmListchown[] = {(char*)"/bin/chown", (char*)"root:proj", (char*)FILEPATH ,NULL};

		char *envParmschown[4] = { (char*)SHELL, (char*)PATH, (char*)KRB5CCNAME, NULL};

		execvpe("chown", parmListchown, envParmschown);

		if(chmod(FILEPATH, 04550) == -1){
			cerr << "Error: File permissions could not be changed." << endl;
		exit(-1);
		}

	}


}
