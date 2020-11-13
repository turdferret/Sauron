About Sauron

A Linux Based Automated Program Launcher.

    This is a Linux based python3.8 program that will automate the process of your python programs running. It will take any 
python based program that has to stay running and will monitor that process id. Will detect if the process died off and will automatically 
spin that program back up in Screen. If your program takes user input at start up for ex: username password file place. Well just 
read the Credentials_Start.txt and add the following code to your code and Sauron will handle the rest. By finding a random directory that 
the user is allowed to write to and pass that argument to your program at the start. Then the code you added will then create a FIFO to 
where Sauron will pass the credentials. Then the FIFO is deleted and your program continues on as normal. If your program requires system 
arguments. Sauron can handle that too. It will also detect if the code has been up dated and will restart the program. Now keep in mind
that it only knows the main run file. When running for the very first time you will have to create and confirm a password. After that you 
will have to type the password once. The password is only used for encrypting the credentials part of the sqlite database that Sauron
creates and stores all the information you give it about the program. Keep in mind that since I'm using Screen to run the programs it will
spin up a new python interpreter for each program. Also have only ran it on Debian-based Linux Distrobutions. The test folder holds 3
different python programs. Each starts up differently and are there for you to play around with and see how Sauron works. It's primary use
is to keep you from having to transfer your code to server/computer. Then having to log into the server/computer restart your program 
again. With Sauron all you have to do is transfer your code and your done. Future updates will have more features like modifying the 
database and better ways of detecting failures of programs.

Requirements:

    Python3.8.3 +

    Screen
        To install Screen.
            sudo apt-get install screen

        Then follow instructions if errors or type y.

    getpass
        To install getpass.
            python3.8 -m pip install getpass
        
        Then follow instructions if errors or type y.

    pycrypto
        to install pycrypto.
            python3.8 -m pip install pycrypto
        
        Then follow instructions if errors or type y.

To Start Sauron:

    python3.8 /{path to directory}/Sauron/Sauron/Sauron.py

    or

    screen -dm -S {name} python3.8 /{path to directory}/Sauron/Sauron/Sauron.py

Default Options:

    q/Q Quit at any time

    l/L Log Out and return to the Log In Menu.

    m/M Return to the Main Menu.

Once started first thing will be done is either creating/confirming password.
![First_Run](https://user-images.githubusercontent.com/74060559/99044754-2e72fd80-2588-11eb-8fa0-1ee63bcba699.png)

At the Main Menu you can select from 1 of the 4 Modes.


1: Add File
    Here is where you will give Sauron the information that is required for your program to run.
    

    Things that Sauron Requires.
        1: File Path
        2: Name of the program
        3: Python version to run the program. Works with any python.
    
    Optional Things that Sauron Needs but does not Require.
        1: Credentials if your program at start up require the user to input some information.
        2: System Arguments

2: Remove File
    Use this option to have Sauron stop monitoring our program.
    

3: Stop Program
    Use this option to have Sauron to stop the program and not let it run till you call for it to be restarted.
    

4: Start/Restart Program
    Use this option to have Sauron either Restart or Start a program.
    

If at any time an error occurs. The boarder will start blinking Red. The log file is stored /{path to directory}/Sauron/Sauron/Logs/.

