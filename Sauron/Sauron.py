#!/usr/bin/python3
# Copyright (c) 2020 Paul M.
# Sauron is under the MIT license. See the LICENSE file at the root of the project for the detailed license terms.

import datetime
import hashlib
import os
import random
import re
import select
import signal
import sqlite3
import subprocess
import sys
import threading
import time
import uuid

from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from getpass import getpass
from queue import Queue as TQ
from pathlib import Path

tacs = '----------'
color_lst = [1, 9, 52, 88, 124, 160, 196, 202, 203]
global color_lst_indx
color_lst_indx = 0


def logger(message):
    """
    Creates a Log File.
    :param message: String
    :return: None
    """
    a = open(f"{os.path.dirname(__file__)}/Logs/SauronLogs.txt", 'a')
    a.write(message)
    a.close()
    return


def start_up():
    """
    Creates a FIFO and reads one line from it and then deletes it.
    :param fileplace: String
    :return: String
    """
    data = None

    if len(sys.argv) == 2:
        fileplace = sys.argv[1]

        try:
            os.mkfifo(fileplace)

            with open(fileplace, "r") as fifo:
                data = fifo.read()

        except:
            data = None

        os.remove(fileplace)

    if data == "None":
        data = None

    return data


def padding(info):
    """
    Makes sure that password is a Modulus of 16. If Not add padding.
    :param info: String
    :return: String
    """
    info += ((16 - (len(info) % 16)) * '}')
    return info


def terminal_size():
    """
    Gets the Height and with of the Terminal.
    :return: Tuple of a Integer and Integer
    """
    return os.get_terminal_size()


def hashing_file(file):
    """
    Creates a Hash of the File so Hash can be checked to see if the file was updated.
    :param file: String
    :return: String
    """
    if os.path.exists(file) is False:
        return "None"

    size = 65536
    file_hash = hashlib.sha256()

    with open(file, 'rb') as f:
        file_bytes = f.read(size)

        while len(file_bytes) > 0:
            file_hash.update(file_bytes)
            file_bytes = f.read(size)

    return str(file_hash.hexdigest()).strip()


def create_connection(file):
    """
    Creating a Database Connection to a SQLite Database.
    :param file: String
    :return: SQLite Connection
    """

    if os.path.exists(file) is False:
        make_db_file(file)

    conn = sqlite3.connect(file)
    return conn


def is_pid_running(pid):
    """
    Checks to see if the pid is Running.
    :param pid: string
    :return: Boolean
    """
    return os.path.isdir(f'/proc/{pid}')


def find_random_path():
    """
    Finds a random direcotry path in the user's home directory.
    :returns: String
    """
    location = str(Path.home())
    count = random.randint(0, 30)

    while count > 0:
        scan = os.scandir(location)
        rand_dir_list = []

        for i in scan:

            if i.is_dir():
                rand_dir_list.append(i.name)

        if len(rand_dir_list) == 0:
            count = 0
            continue

        location += f"/{random.choice(rand_dir_list)}"
        count -= 1
        
    return location + '/'


def find_directory(file):
    """
    Finds the Directory of the File.
    :param file: String
    :return: String
    """
    answer = os.path.dirname(file)
    return answer if answer not in [None, ''] else os.path.realpath(__file__).strip(f"/{file}")


def get_sys_info(cmd):
    """
    Gets output from a system command.
    :param cmd: List of Strings
    :return: Bytes
    """
    a = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )

    return a.stdout.readlines()


def make_db_file(file):
    """
    Creates the SQLite Database
    :param file: String
    :return: None
    """

    if os.path.exists(file) is False and os.path.exists(f"{Path.home()}/.giblets") is False:
        conn = sqlite3.connect(file)

        # Defining the Table and Row Items and their Properties and Creating the Tables and Rows.
        paths = '''CREATE TABLE IF NOT EXISTS Minions ([path] text,
                                                       [alias] text,
                                                       [type] text,
                                                       [credentials] text,
                                                       [pargs] text)'''

        conn.cursor().execute(paths)
        paths = '''CREATE TABLE IF NOT EXISTS Main ([First] text)'''
        conn.cursor().execute(paths)
        conn.close()

        os.system(f"cp {file} {Path.home()}/.giblets")
    
    elif os.path.exists(file) is False and os.path.exists(f"{Path.home()}/.giblets") is True:
        os.system(f"cp {Path.home()}/.giblets {file}")

    elif  os.path.exists(file) is True and os.path.exists(f"{Path.home()}/.giblets") is False:
        os.system(f"cp {file} {Path.home()}/.giblets")

    elif hashing_file(file) != hashing_file(f"{Path.home()}/.giblets"):
        os.remove(f"{Path.home()}/.giblets")
        os.system(f"cp {file} {Path.home()}/.giblets")

    return


def pid_killers(pid, err_event):
    """
    Sends the PID a SIGINT. If Program is Still Running after 3 times. A SIGTERM is sent to the PID.
    :param pid: String
    :param err_event: Threading Event
    :return: None
    """
    count = 0

    while True:
        count += 1

        if count == 4 or is_pid_running(pid) is False:
            break

        else:

            try:
                os.kill(int(pid), signal.SIGTERM) if count == 3 else os.kill(int(pid), signal.SIGINT)

            except Exception as e:
                err_event.set()
                err = f"{tacs}Stop Programs{tacs}\n\tLine #: {e.__traceback__.tb_lineno}\n\tError: {e}\n\tTime: " \
                        f"{datetime.datetime.now()}\n{tacs}Stop Programs{tacs}\n"
                logger(err)
        
        time.sleep(1)

    return


def pid_helper(file_path, err_event):
    """
    Creates a dictionary of all running process id's. {Main PID: [PID, PID]}
    :param file_path: String
    :param err_event: Threading Event
    :return: Dictionary
    """
    fl_bd = file_path.split('/')
    fl_name = fl_bd[len(fl_bd)-1]
    answer = get_sys_info("ps aux".split())
    helper = {}

    for line in answer:

        if line.find(fl_name.encode()) >= 0:
            pid = re.sub(" +", "|", line.decode()).split('|')[1].strip()
            answer1 = get_sys_info(f"cat /proc/{pid}/status".split())

            for i in answer1:

                if i.find(b"PPid:") >= 0:
                    a = re.sub("\t+", "|", i.decode()).split('|')[1].strip()

                    if a == '1':
                        helper[pid] = []

                    elif a not in helper:
                        helper[a] = [pid]

                    else:
                        helper[a].append(pid)

                    break

    pids_to_join = {}
    pids = {}

    for i in helper:

        for i1 in helper:

            if i1 == i:
                continue

            elif i in helper[i1]:
                pids_to_join[i] = i1

                if i1 not in pids:
                    pids[i1] = [i]
                
                else:
                    pid[i1].append(i)

    for i in helper:

        if i in pids:
            continue
    
        elif i in pids_to_join:

            for i1 in helper[i]:
                pids[pids_to_join[i]].append(i1)

        else:
            pids[i] = helper[i]

    if len(pids) == 0:
        pids[None] = []

    return pids

def pid_getter(file_path, err_event):
    """
    Checks to see if File is Running. If so return pid for program. Else return None.
    :param file_path: String
    :return: Dictionary
    """
    pid = pid_helper(file_path, err_event)

    if len(pid) > 1:

        for i in pid:

            for i1 in pid[i]:
                pid_killers(i1, err_event)

            pid_killers(i, err_event)

        pid = {None: []}

    return pid


def starting_files(creds, alias, ptype, pargs, pword, file, err_event):
    """
    Starts the Python program file in Screen.
    :param creds: String
    :param alias: String
    :param pword: String or None
    :param file: String
    :param err_event: Threading Event
    :return: None
    """

    if creds == "None" and pargs == "None":
        command = f'screen -dm -S {alias} {ptype} {file}'
        os.system(command)
        time.sleep(1)

    elif creds != "None":

        if pword is not None:
            fifo_path = f"{find_random_path()}{uuid.uuid4()}"
            command = f'screen -dm -S {alias} {ptype} {file} {fifo_path}'
            os.system(command)
            time.sleep(1)
            message = decrypt(pword, creds, err_event)

            if pipe_writer(fifo_path, message) is False:
                err_event.set()
                err = f"{tacs}Pipe Writer{tacs}\n\tFile Name: {fifo_path}\n{tacs}Pipe Writer{tacs}\n"
                logger(err)
    
    elif pargs != "None":
        command = f'screen -dm -S {alias} {ptype} {file} {pargs}'
        os.system(command)
        time.sleep(1)

    return


def write_to_database(query, file, info=None):
    """
    Writting Information to the Database.
    :param query: String
    :param file: String
    :param info: Tuple
    :return: None
    """
    conn = create_connection(file)
    conn.cursor().execute(query) if info is None else conn.cursor().execute(query, info)
    conn.commit()
    conn.close()
    return


def check_dbpassword(dbpassword, file):
    """
    Checks the Database Password to see if will Decrypt the information. Returns True or False.
    :param dbpassword: String
    :param file: String
    :return: Boolean
    """
    answer = False
    
    try:
        results = read_from_database('''SELECT First FROM Main''', file)
        cipher = AES.new(dbpassword.encode("utf-8"), AES.MODE_ECB)
        cipher.decrypt(b64decode(bytes(results[0][0].encode()))).decode()
        answer = True

    except:
        answer = False
    
    finally:
        return answer


def decrypt(pword, info, err, mode=0):
    """
    Encrypts/Decrypts the information.
    :param pword: String
    :param info: String
    :param mode: Integer Default is 0.
    :return: String
    """
    answer = None


    try:
        cipher = AES.new(pword.encode("utf-8"), AES.MODE_ECB)
        answer = cipher.decrypt(b64decode(info.encode())).decode().strip('}') if mode == 0 else \
                b64encode(cipher.encrypt(padding(info).encode("utf-8"))).decode().strip()

    except:
        answer = None

    finally:
        return answer


def read_from_database(query, file, info=None):
    """
    Reading Information from the Database.
    :param query: String
    :param file: String
    :param info: List of Strings. Default is None
    :return: Tuple of Lists or None.
    """
    answer = None
    conn = create_connection(file)
    curs = conn.cursor()
    curs.execute(query) if info is None else curs.execute(query, info)
    answer = curs.fetchall()
    curs.close()
    conn.close()
    return answer


def get_directories(file, err_event):
    """
    Creates a Dictionary of all the Directories in the Database.
    :param file: String
    :return: Dictionary
    """
    answer = {}
    results = read_from_database('''SELECT * FROM Minions''', file)

    if results:

        for i in results:
            answer[i[0]] = {
                "ALIAS": i[1],
                "TYPE": i[2],
                "CREDS": i[3],
                "PARGS": i[4],
                "PID": pid_getter(i[0], err_event),
                "HASH": hashing_file(i[0]),
                "STRTTIME": datetime.datetime.now()
            }

    return answer


def db_list_maker(info):
    """
    Creates a list from a tuple of lists.
    :param info: Tuple of Lists
    :return: List
    """
    answer = []

    for i in info:
        answer.append(i[0])
    
    return answer


def running_programs(info, err_event):
    """
    Checks a list to see what programs are running.
    :param info: List of Strings
    :return: List
    """
    answer = []

    for i in info:
        a = pid_helper(i, err_event)

        for i1 in a:

            if i1 is not None:
                answer.append(i)

    return answer


def stop_program(file, pid, err_event):
    """
    Kills of the process.
    :param file: String
    :param pid: Dictionary
    :param err_event: Threading Event
    :return: None
    """
    new_pid = pid_helper(file, err_event)

    for i in pid:
        
        if i is not None and len(pid[i]) > 0:

            for i1 in pid[i]:
                pid_killers(i1, err_event)

            pid_killers(i, err_event)

    if new_pid != pid:
        
        for i in pid:
        
            if i is not None and len(pid[i]) > 0:

                for i1 in pid[i]:
                    pid_killers(i1, err_event)

                pid_killers(i, err_event)

    return


def pipe_writer(filename, message):
    """
    Writes to a fifo to pass credentials.
    :param filename: String
    :param message: String
    :return: Boolean
    """
    count = 0

    while os.path.exists(filename) is False:
        count += 1

        if count == 4:
            return False

        time.sleep(.5)

    a = open(filename, 'w')
    a.write(message)
    a.flush()
    a.close()
    return True


def dicionary_compare(old_dict, new_dict, pword, err_event, stopped_programs):
    """
    Compares two dictionaries.
    :param old_dict: Dictionary
    :param new_dict: Dictionary
    :param pword: String
    :returns: Dictionary
    """
    try:

        for i in old_dict:

            if i not in new_dict or old_dict[i]["HASH"] != new_dict[i]["HASH"] or old_dict[i]["ALIAS"] !=  \
                    new_dict[i]["ALIAS"] or old_dict[i]["PARGS"] !=  new_dict[i]["PARGS"]:
                stop_program(i, old_dict[i]["PID"], err_event)

        for i in new_dict:
            new_main_pid = None

            for i1 in new_dict[i]["PID"]:
                new_main_pid = i1

            if new_main_pid is None and i not in stopped_programs:
                starting_files(
                    new_dict[i]["CREDS"],
                    new_dict[i]["ALIAS"],
                    new_dict[i]["TYPE"],
                    new_dict[i]["PARGS"],
                    pword,
                    i,
                    err_event
                )

                new_dict[i]["PID"] = pid_getter(i, err_event)
                new_dict[i]["STRTTIME"] = datetime.datetime.now()

    except Exception as e:
        err_event.set()
        error = f"{tacs}Dictionary Compare{tacs}\n\tLine #: {e.__traceback__.tb_lineno}\n\tError: {e}\n\tTime: " \
                f"{datetime.datetime.now()}\n{tacs}Dictionary Compare{tacs}\n"
        logger(error)

    finally:
        return new_dict


def adding_extra_color(msg, extra_spaces=False):
    """
    Add the extra color for terminal print after all whitespaces and special chars have been stripped.
    :param msg: String
    :return: String
    """ 
    answer = f"\033[48;5;232m"

    if extra_spaces:
        ending = msg.split("    ")[len(msg.split("    ")) - 1]

        if ending == "RUNNING":
            answer += f"{message_color1(msg.strip(ending))}\033[48;5;232m\033[38;5;2m{ending}\033[0m"

        elif ending == "NOT RUNNING":
            answer += f"{message_color1(msg.strip(ending))}\033[48;5;232m    \033[5m\033[91m{ending}\033[0m"

    else:
        msg_splt = msg.split("  ")

        for i in msg_splt:

            if i == "OPTIONS":
                answer += f"{message_color1('OPTIONS')}"

            elif i == "q-QUIT":
                answer += f"  {message_color1('q-')}\033[48;5;232m\033[38;5;1mQUIT\033[0m"

            elif i == "m-MAIN MENU":
                answer += f"  {message_color1('m-')}\033[48;5;232m\033[38;5;191mMENU\033[0m"
            
            elif i == "l-LOG OUT":
                answer += f"  {message_color1('l-')}\033[48;5;232m\033[38;5;27mLOG OUT\033[0m"

    return answer


def message_color(msg):
    """
    Sets the ANSI Termanal Color for each letter in a msg.
    :param msg: String
    :returns: String
    """
    global color_lst_indx
    answer = ""

    for i in range(len(msg)):

        if color_lst_indx >= len(color_lst):
            color_lst_indx = 0
        
        answer += f"\033[48;5;232m\033[38;5;{color_lst[color_lst_indx]}m{msg[i]}\033[0m"
        color_lst_indx += 1

    return answer


def message_color1(msg):
    """
    Sets the ANSI Termanal Color for each letter in a msg.
    :param msg: String
    :returns:  String
    """
    return f"\033[48;5;232m\033[38;5;12m{msg}\033[0m"



def no_white_spaces(msg):
    """
    Message is to long for the Termainl size and has no spaces so spliting on special charactes.
    :param msg: String
    :return: Tuple of String and Integer 
    """
    ending = len(msg)

    for i in range(len(msg)):

        if msg[ending-1] == '/':
            break

        else:
            ending -= 1

    return msg[:ending], ending

def check_single_space(msg):
    """
    Checks and make's sure the lengthening of the message did not cut off a word.
    :param msg: String
    :return: Tuple of String and Integer
    """
    msg = msg.replace('\n', ' ').replace('\t', ' ')

    if ord(msg[0]) == 32:
        msg = msg[1:]
    
    ending = len(msg)
    single_space = False

    for i in range(len(msg)):

        if ord(msg[ending-1]) == 32:
            ending -= 1
            single_space = True

        elif not single_space:
            ending -= 1
        
        else:
            break

    if ending == 0:
        msg, ending = no_white_spaces(msg)

    else:
        msg = msg[:ending]

    return msg, ending + 1


def check_double_space(msg):
    """
    Checks and make's sure the lengthening of the message did not cut off a word.
    :param msg: String
    :return: Tuple of String and Integer
    """
    msg = msg.replace('\n', ' ').replace('\t', ' ')
    strt_point = 0

    for i in range(10):

        if ord(msg[0]) == 32:
            strt_point -= 1
        
        else:
            break
    
    msg = msg[strt_point:]
    ending = len(msg)
    dobule_space = False

    for i in range(len(msg)):

        if ord(msg[ending-1]) == 32:
            ending -= 1

            if dobule_space:
                break

            dobule_space = True

        else:
            ending -= 1
            dobule_space = False

    msg = msg[:ending]
    return msg, ending


def check_message_length(msg, columns, double_space):
    """
    Checks the message to make sure it fits centered in the Terminal with 10 or more spaces on each side.
    :param msg: String
    :param columns: Integer
    :param doube_space: Boolean
    :return: List of Strings 
    """
    answer = []
    length = int(columns - 20)

    while len(msg) > length:

        if not double_space:
            new_msg, strt_point = check_single_space(msg[:length])
            answer.append(new_msg)
            msg = msg[strt_point:]

        else:
            new_msg, strt_point = check_double_space(msg[:length])
            answer.append(new_msg)
            msg = msg[strt_point:]

    answer.append(msg)
    return answer


def main_header(title, modes, options, err, double_space):
    """
    Clears the terminal and prints the title mode and options.
    :param title: String
    :param modes: String
    :param options: String
    :param err: Boolean
    :param double_space: Boolean
    :return: None
    """
    os.system("clear")
    columns, lines = terminal_size()

    for i in range(lines):

        if i in [0, 9]:
            boarder = message_color(''.join("@" for i in range(columns))) if not err else \
                    ''.join("\33[5m\033[91m@\033[0m" for i in range(columns))
            print(boarder)

        elif i in [2, 4, 6, 8]:
            boarder =  message_color('@') if not err else "\33[5m\033[91m@\033[0m"
            print(f"{boarder}\033[{columns}G{boarder}")

        elif i == 3:
            boarder =  message_color('@') if not err else "\33[5m\033[91m@\033[0m"
            msg_lines = check_message_length(title, columns, False)

            for line in msg_lines:
                strt_point = int(((columns - len(line))/2)-2)
                print(f"{boarder}\033[{strt_point}G\033[48;5;232m{message_color1(line)}\033[0m\033[{columns}G{boarder}")            

        elif i == 5:
            boarder =  message_color('@') if not err else "\33[5m\033[91m@\033[0m"
            msg_lines = check_message_length(modes, columns, double_space)

            for line in msg_lines:
                strt_point = int(((columns - len(line))/2)-2)
                print(f"{boarder}\033[{strt_point}G{message_color1(line)}\033[{columns}G{boarder}")

        elif i == 7:
            boarder =  message_color('@') if not err else "\33[5m\033[91m@\033[0m"
            msg_lines = check_message_length(options, columns, True)

            for line in msg_lines:
                strt_point = int(((columns - len(line))/2)-2)
                print(f"{boarder}\033[{strt_point}G\033[48;5;232m{adding_extra_color(line)}\033[0m\033[{columns}G{boarder}")

        elif i > 9:
            break

    return


def input_with_timeout(prompt, timeout):
    """
    Getting user input from the terminal and setting timeout in seconds.
    :param prompt: String
    :param timeout: Integer
    :return: String or None if timeout has occured
    """
    sys.stdout.write(prompt)
    sys.stdout.flush()
    ready, _, _ = select.select([sys.stdin], [],[], timeout)
    if ready:
        return sys.stdin.readline().rstrip('\n') # expect stdin to be line-buffered
    return None


def gui(event, queue, lock, file, err_event, first_time):
    """
    Main Terminal GUI. Takes User Input and Updates the Database.
    :param event: Threading Event
    :param queue: Threading Queue
    :param lock:  Threading Lock
    :param file: String
    :param err_event: Threding Event
    :param first_time: Boolean
    :return: None
    """
    title = "Sauron's All Seeing Eye Version 1.0"

    while event.is_set() is False:
        pword_finished = False
        pword = None
        dbase_size = True if len(read_from_database('''SELECT First FROM Main''', file)) > 0 else False
        count = 0

        while pword_finished is False:

            # Getting the Password for Decrypting the Information from the Database.
            modes = "Create a Password Used for Encrypting and Decrypting info in the Database." if first_time is False else \
                    "Type Password Used for Encrypting and Decrypting info in the Database."

            options = "OPTIONS  q-QUIT"
            main_header(title, modes, options, err_event.is_set(), False)

            if err_event.is_set() is True:
                err_event.clear()

            pword = getpass(f"\n\t{message_color1('Type Password -->')} ").strip()

            if pword.lower() == 'q':
                event.set()
                pword_finished = True
                continue

            elif len(pword) < 8:
                count += 1

                if count == 3:
                    err_event.set()
                    error = f"{tacs}User Authencation{tacs}\n\tMessage: Password Entered In Wrong Too Many Times" \
                            f"\n\tTime: {datetime.datetime.now()}\n{tacs}User Authencation{tacs}\n"
                    logger(error)
                    count = 0

                columns = terminal_size()[0]
                msg = "Password Length Is Too Short!!!!"
                msg1 = "Must be 8-25 Characters Long!!!!"
                msg_strt_pnt = int((columns - len(msg))/2)
                msg1_strt_pnt = int((columns - len(msg))/2)
                msg_color = message_color1(msg)
                msg1_color = message_color1(msg1)
                print(f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}")
                time.sleep(2)
                continue

            elif len(pword) > 25:
                count += 1

                if count == 3:
                    err_event.set()
                    error = f"{tacs}User Authencation{tacs}\n\tMessage: Password Entered In Wrong Too Many Times" \
                            f"\n\tTime: {datetime.datetime.now()}\n{tacs}User Authencation{tacs}\n"
                    logger(error)
                    count = 0

                columns = terminal_size()[0]
                msg = "Password Length Is Too Long!!!!"
                msg1 = "Must be 8-25 Characters Long!!!!"
                msg_strt_pnt = int((columns - len(msg))/2)
                msg1_strt_pnt = int((columns - len(msg))/2)
                msg_color = message_color1(msg)
                msg1_color = message_color1(msg1)
                print(f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}")
                time.sleep(2)
                continue

            elif dbase_size <= False:
                cpword = getpass(f"\t{message_color1('Confirm Password -->')} ")

                if cpword.lower() == 'q':
                    event.set()
                    pword_finished = True
                    continue

                elif cpword == pword:
                    pword_finished = True
                    pword = padding(pword)
                    message = decrypt(pword, "Sauron", err_event, 1)
                    
                    if message is None:
                        continue
                    
                    q = """INSERT INTO MAIN(First) VALUES(?)"""
                    write_to_database(q, file, (message,))
                    continue

                else:
                    msg = "Passwords Did Not Match!!!!"
                    msg_strt_pnt = int((terminal_size()[0]-len(msg))/2)
                    print(f"\n\n\033[{msg_strt_pnt}G{message_color1(msg)}")
                    time.sleep(2)
                    continue

            else:
                count += 1
                pword = padding(pword)
                
                if check_dbpassword(pword, file) is True:
                    pword_finished = True
                    continue

                else:

                    if count == 3:
                        err_event.set()
                        error = f"{tacs}User Authencation{tacs}\n\tMessage: Password Entered In Wrong Too Many Times" \
                                f"\n\tTime: {datetime.datetime.now()}\n{tacs}User Authencation{tacs}\n"
                        logger(error)
                        count = 0

                    msg = "Passwords Did Not Match!!!!"
                    msg_strt_pnt = int((terminal_size()[0]-len(msg))/2)
                    print(f"\n\n\033[{msg_strt_pnt}G{message_color1(msg)}")
                    time.sleep(2)
                    continue

        if event.is_set() is True:
            continue

        main_run = True
        dataq.put(f"PW|{pword}")

        while main_run is True:
            # Main Loop of the GUI.
            main_menu = False
            modes = "1-Add File  2-Remove File  3-Stop Program  4-Start/Restart Program"
            options = "OPTIONS  q-QUIT  l-LOG OUT"
            main_header(title, modes, options, err_event.is_set(), True)

            if err_event.is_set() is True:
                err_event.clear()

            main_input = input_with_timeout(f"\n\t{message_color1('Your Choice  -->')} ", 300)

            if main_input is None or main_input.lower() == 'l':
                main_run = False
                continue

            elif main_input.isnumeric() is False:

                if main_input.lower() == 'q':
                    main_run = False
                    kevent.set()
                    continue

            else:

                if int(main_input) == 1:
                    # Adding New Program to the Directory.
                    add_file = True  # Flag Used to let Program Know Add Directory has Finished.
                    file_path = None  # The Directory to the Program or Full File Path.
                    alias = None  # Alias Name for the Screen that will be running the File.
                    ptype = "None"  # Type of program that will be running.
                    creds_answer = False  # Tells if the program has Arguements that need passing at start up.
                    creds = "None"  # String form of the Arguements passed with seperated by |'s
                    pargs = "None"
                    established = db_list_maker(read_from_database('''SELECT path FROM Minions''', file))
                    modes = "Adding File"
                    options = "OPTIONS  q-QUIT  m-MAIN MENU  l-LOG OUT"

                    while add_file is True:
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        file_path = input_with_timeout(f"\n\t{message_color1('File Path -->')} ", 30)

                        if file_path is None or file_path.lower() == 'l':
                            main_run = False
                            add_file = False
                            continue

                        # User Called for the Program to Quit.
                        elif file_path.lower() == 'q':
                            main_run = False
                            add_file = False
                            event.set()
                            continue

                        # User Called for Main Menu.
                        elif file_path.lower() == 'm':
                            main_menu = True
                            add_file = False
                            continue

                        elif os.path.exists(file_path) is False:
                            os.system("clear")
                            columns = terminal_size()[0]
                            msg = "File Path Does Not Exist!!!!"
                            msg_strt_pnt = int((columns-len(msg))/2)
                            msg1_strt_pnt = int((columns-len(file_path))/2)
                            msg_color = message_color1(msg)
                            msg1_color = message_color1(file_path)
                            print(f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}")
                            time.sleep(2)
                            continue

                        elif file_path in established:
                            os.system("clear")
                            columns = terminal_size()[0]
                            msg = "File Path Already Exist in Database!!!!"
                            msg_strt_pnt = int((columns-len(msg))/2)
                            msg1_strt_pnt = int((columns-len(file_path))/2)
                            msg_color = message_color1(msg)
                            msg1_color = message_color1(file_path)
                            print(f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}")
                            time.sleep(2)
                            continue

                        else:

                            while True:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Program Location"
                                strt_point = int((columns - len(msg))/2)
                                strt_point1 = int((columns - len(file_path))/2)
                                print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(file_path)}")
                                confrm_answer = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                if confrm_answer is None or confrm_answer.lower() == 'l':
                                    main_run = False
                                    add_file = False
                                    break

                                # User Called for the Program to Quit.
                                elif confrm_answer.lower() == 'q':
                                    main_run = False
                                    add_file = False
                                    event.set()
                                    break

                                # User Called for Main Menu.
                                elif confrm_answer.lower() == 'm':
                                    main_menu = True
                                    add_file = False
                                    break

                                elif confrm_answer.lower() == 'y':
                                    add_file = False
                                    break

                                elif confrm_answer.lower() == 'n':
                                    break 

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue

                    add_file = True

                    while add_file is True:
                        modes = f"Adding File {file_path}"
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        alias = input_with_timeout(f"\n\t{message_color1('Name for the Program --> ')}", 30)

                        if alias is None or alias.lower() == 'l':
                            main_run = False
                            add_file = False
                            continue

                        # User Called for the Program to Quit.
                        elif alias.lower() == 'q':
                            main_run = False
                            add_file = False
                            event.set()
                            continue

                        # User Called for Main Menu.
                        elif alias.lower() == 'm':
                            main_menu = True
                            add_file = False
                            continue
                        
                        elif len(alias) < 2:
                            columns = terminal_size()[0]
                            msg = "Alias Must be at least 2 Characters Long!!!!"
                            msg_strt_pnt = int((columns-len(msg))/2)
                            msg_color = message_color1(msg)
                            print(f"\n\n\033[{msg_strt_pnt}G{msg_color}")
                            time.sleep(2)
                            continue

                        elif len(read_from_database('''SELECT * FROM Minions WHERE alias=?''', file, (alias,))) > 0:
                            columns = terminal_size()[0]
                            msg = f"Alias: {alias} Already Exists for Another Program!!!!"
                            msg_strt_pnt = int((columns-len(msg))/2)
                            msg_color = message_color1(msg)
                            print(f"\n\n\033[{msg_strt_pnt}G{msg_color}")
                            time.sleep(2)
                            continue

                        else:

                            while True:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Program Name"
                                strt_point = int((columns - len(msg))/2)
                                strt_point1 = int((columns - len(alias))/2)
                                print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(alias)}")

                                confrm_answer = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                if confrm_answer is None or confrm_answer.lower() == 'l':
                                    main_run = False
                                    add_file = False
                                    break

                                # User Called for the Program to Quit.
                                elif confrm_answer.lower() == 'q':
                                    main_run = False
                                    add_file = False
                                    event.set()
                                    break

                                # User Called for Main Menu.
                                elif confrm_answer.lower() == 'm':
                                    main_menu = True
                                    add_file = False
                                    break

                                elif confrm_answer.lower() == 'y':
                                    add_file = False
                                    break

                                elif confrm_answer.lower() == 'n':
                                    break 

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue

                    add_file = True

                    while add_file is True:
                        modes = f"Adding File {file_path}"
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        ptype = input_with_timeout(f"\n\t{message_color1('Type of Program --> ')}", 30)

                        if ptype is None or ptype.lower() == 'l':
                            main_run = False
                            add_file = False
                            continue

                        # User Called for the Program to Quit.
                        elif ptype.lower() == 'q':
                            main_run = False
                            add_file = False
                            event.set()
                            continue

                        # User Called for Main Menu.
                        elif ptype.lower() == 'm':
                            main_menu = True
                            add_file = False
                            continue

                        elif ptype.find("python") < 0 :
                            columns = terminal_size()[0]
                            msg = "This Version Of Sauron Can Only Keep Track Of Python Programs!!!! Later Versions Will " \
                                  "Have The Capability To Keep Track Of Other Program Types!!!! Hit Enter to continue"
                            msg_lines = check_message_length(msg, columns, False)
                            print("\n\n")

                            for line in msg_lines:
                                print(f"\033[{int((columns-len(line))/2)}G{message_color1(line)}")

                            time_input = input_with_timeout('', 10)

                        else:

                            while True:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Program Type"
                                strt_point = int((columns - len(msg))/2)
                                strt_point1 = int((columns - len(ptype))/2)
                                print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(ptype)}")

                                confrm_answer = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                if confrm_answer is None or confrm_answer.lower() == 'l':
                                    main_run = False
                                    add_file = False
                                    break

                                # User Called for the Program to Quit.
                                elif confrm_answer.lower() == 'q':
                                    main_run = False
                                    add_file = False
                                    event.set()
                                    break

                                # User Called for Main Menu.
                                elif confrm_answer.lower() == 'm':
                                    main_menu = True
                                    add_file = False
                                    break

                                elif confrm_answer.lower() == 'y':
                                    add_file = False
                                    break

                                elif confrm_answer.lower() == 'n':
                                    break 

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue

                    add_file = True

                    while add_file is True:
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        credentials_answer = input_with_timeout(
                            f"\n\t{message_color1('Does the Program have a Credential File Y or N -->')} ",
                            15
                        )

                        if credentials_answer is None or credentials_answer.lower() == 'l':
                            main_run = False
                            add_file = False
                            continue

                        elif credentials_answer.isalpha() is True:

                            # User Called for the Program to Quit.
                            if credentials_answer.lower() == 'q':
                                main_run = False
                                add_file = False
                                event.set()
                                continue

                            # User Called for Main Menu.
                            elif credentials_answer.lower() == 'm':
                                main_menu = True
                                add_file = False
                                continue

                            # User Called for Credentials.
                            elif credentials_answer.lower() == 'y':
                                creds_answer = True
                                add_file = False

                            # User Called for no Credentials.
                            elif credentials_answer.lower() == 'n':
                                creds_answer = False
                                add_file = False

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue

                    if creds_answer is True:
                        add_file = True

                        while add_file is True:
                            main_header(title, modes, options, err_event.is_set(), False)

                            if err_event.is_set() is True:
                                err_event.clear()

                            creds = input_with_timeout(f"\n\t{message_color1('Arguements Seperate By | -->')} ", 120)

                            if creds is None or creds.lower() == 'l':
                                main_run = False
                                add_file = False
                                continue

                            # User Called for the Program to Quit.
                            elif creds.lower() == 'q':
                                main_run = False
                                add_file = False
                                event.set()
                                continue

                            # User Called for Main Menu.
                            elif creds.lower() == 'm':
                                main_menu = True
                                add_file = False
                                continue

                            elif creds.find('|') == -1:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Please Seperate Arguements By |...."
                                msg1 = "Example: 8.8.8.8|"
                                msg2 = "Example: 8.8.8.8|google.com|/home/user/Desktop/Test.txt"
                                msg_strt_pnt = int((columns-len(msg))/2)
                                msg1_strt_pnt = int((columns-len(msg1))/2)
                                msg2_strt_pnt = int((columns-len(msg2))/2)
                                msg_color = message_color1(msg)
                                msg1_color = message_color1(msg1)
                                msg2_color = message_color1(msg2)
                                print(
                                    f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}\n\033" \
                                    f"[{msg2_strt_pnt}G{msg2_color}"
                                )
                                time.sleep(3)
                                continue

                            elif 2 >= len(creds) <= 15000:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Credential String Can be between 2 and 15000 Characters Long...."
                                msg1 = f"Character Count: {len(creds)}"
                                msg_strt_pnt = int((columns-len(msg))/2)
                                msg1_strt_pnt = int((columns-len(msg1))/2)
                                msg_color = message_color1(msg)
                                msg1_color = message_color1(msg1)
                                print(f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}")
                                time.sleep(3)
                                continue
                            
                            else:

                                while True:
                                    os.system("clear")
                                    columns = terminal_size()[0]
                                    msg = "Credential Arguements"
                                    strt_point = int((columns - len(msg))/2)
                                    strt_point1 = int((columns - len(creds))/2)
                                    print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(creds)}")
                                    conformation = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                    if conformation is None or conformation.lower() == 'l':
                                        main_run = False
                                        add_file = False
                                        break

                                    # User Called for the Program to Quit.
                                    elif conformation.lower() == 'q':
                                        main_run = False
                                        add_file = False
                                        event.set()
                                        break

                                    # User Called for Main Menu.
                                    elif conformation.lower() == 'm':
                                        main_menu = True
                                        add_file = False
                                        break

                                    elif conformation.lower() == 'y':
                                        add_file = False
                                        break

                                    elif conformation.lower() == 'n':
                                        break 

                    else:
                        add_file = True

                        while add_file is True:
                            main_header(title, modes, options, err_event.is_set(), False)

                            if err_event.is_set() is True:
                                err_event.clear()

                            pargs_answer = input_with_timeout(
                                f"\n\t{message_color1('Does the Program take SYSTEM ARGS Y or N -->')} ",
                                15
                            )

                            if pargs_answer is None or pargs_answer.lower() == 'l':
                                main_run = False
                                add_file = False
                                continue

                            elif pargs_answer.isalpha() is True:

                                # User Called for the Program to Quit.
                                if pargs_answer.lower() == 'q':
                                    main_run = False
                                    add_file = False
                                    event.set()
                                    continue

                                # User Called for Main Menu.
                                elif pargs_answer.lower() == 'm':
                                    main_menu = True
                                    add_file = False
                                    continue

                                # User Called for pargs.
                                elif pargs_answer.lower() == 'y':
                                    creds_answer = True
                                    add_file = False

                                # User Called for no pargs.
                                elif pargs_answer.lower() == 'n':
                                    creds_answer = False
                                    add_file = False
                        
                        if event.is_set() is True or main_menu is True or main_run is False:
                            continue

                        if creds_answer is True:
                            add_file = True

                            while add_file is True:
                                main_header(title, modes, options, err_event.is_set(), False)

                                if err_event.is_set() is True:
                                    err_event.clear()

                                pargs = input_with_timeout(f"\n\t{message_color1('Type out Arguments -->')} ", 120)

                                if pargs is None or pargs.lower() == 'l':
                                    main_run = False
                                    add_file = False
                                    continue

                                # User Called for the Program to Quit.
                                elif pargs.lower() == 'q':
                                    main_run = False
                                    add_file = False
                                    event.set()
                                    continue

                                # User Called for Main Menu.
                                elif pargs.lower() == 'm':
                                    main_menu = True
                                    add_file = False
                                    continue

                                elif 2 >= len(pargs) <= 15000:
                                    os.system("clear")
                                    columns = terminal_size()[0]
                                    msg = "Arguements String Can be between 2 and 15000 Characters Long....."
                                    msg1 = f"Character Count: {len(pargs)}"
                                    msg_strt_pnt = int((columns-len(msg))/2)
                                    msg1_strt_pnt = int((columns-len(msg1))/2)
                                    msg_color = message_color1(msg)
                                    msg1_color = message_color1(msg1)
                                    print(f"\n\n\033[{msg_strt_pnt}G{msg_color}\n\033[{msg1_strt_pnt}G{msg1_color}")
                                    time.sleep(3)
                                    continue
                                
                                else:

                                    while True:
                                        os.system("clear")
                                        columns = terminal_size()[0]
                                        msg = "System Arguements"
                                        strt_point = int((columns - len(msg))/2)
                                        strt_point1 = int((columns - len(pargs))/2)
                                        print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(pargs)}")
                                        conformation = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                        if conformation is None or conformation.lower() == 'l':
                                            main_run = False
                                            add_file = False
                                            break

                                        # User Called for the Program to Quit.
                                        elif conformation.lower() == 'q':
                                            main_run = False
                                            add_file = False
                                            event.set()
                                            break

                                        # User Called for Main Menu.
                                        elif conformation.lower() == 'm':
                                            main_menu = True
                                            add_file = False
                                            break

                                        elif conformation.lower() == 'y':
                                            add_file = False
                                            break

                                        elif conformation.lower() == 'n':
                                            break

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue
                    
                    while True:
                        os.system("clear")
                        columns = terminal_size()[0]
                        msg = "New Program"
                        msg2 = "Program Name"
                        msg4 = "Program Type"
                        msg6 = "Credentials"
                        msg8 = "System Arguements"
                        strt_point = int((columns - len(msg))/2)
                        strt_point1 = int((columns - len(file_path))/2)
                        strt_point2 = int((columns - len(msg2))/2)
                        strt_point3 = int((columns - len(alias))/2)
                        strt_point4 = int((columns - len(msg4))/2)
                        strt_point5 = int((columns - len(ptype))/2)
                        strt_point6 = int((columns - len(msg6))/2)
                        strt_point7 = int((columns - len(creds))/2)
                        strt_point8 = int((columns - len(msg8))/2)
                        strt_point9 = int((columns - len(pargs))/2)
                        print(
                            f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(file_path)}" \
                            f"\n\n\033[{strt_point2}G{message_color1(msg2)}\n\033[{strt_point3}G{message_color1(alias)}" \
                            f"\n\n\033[{strt_point4}G{message_color1(msg4)}\n\033[{strt_point5}G{message_color1(ptype)}" \
                            f"\n\n\033[{strt_point6}G{message_color1(msg6)}\n\033[{strt_point7}G{message_color1(creds)}" \
                            f"\n\n\033[{strt_point8}G{message_color1(msg8)}\n\033[{strt_point9}G{message_color1(pargs)}"
                        )

                        conformation = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 30)

                        if conformation is None or conformation.lower() == 'l':
                            main_run = False
                            add_file = False
                            break

                        # User Called for the Program to Quit.
                        elif conformation.lower() == 'q':
                            main_run = False
                            add_file = False
                            event.set()
                            break

                        # User Called for Main Menu.
                        elif conformation.lower() == 'm':
                            main_menu = True
                            add_file = False
                            break

                        elif conformation.lower() == 'y':
                            add_file = False
                            break

                        elif conformation.lower() == 'n':
                            break

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue

                    q = """INSERT INTO Minions (path, alias, type, credentials, pargs) VALUES(?, ?, ?, ?, ?)"""

                    if creds != "None":
                        message = decrypt(pword, creds, err_event, 1)

                    else:
                        message = creds

                    write_to_database(q, file, (file_path, alias, ptype, message, pargs))
                    dataq.put("CHANGE|")
                    add_file = False

                elif int(main_input) == 2:
                    remove_file = True
                    answer = None
                    results = None

                    while remove_file is True:
                        modes = "Removing File"
                        options = "OPTIONS  q-QUIT  m-MAIN MENU  l-LOG OUT"
                        results = db_list_maker(read_from_database('''SELECT path FROM Minions''', file))
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        if len(results) == 0:
                            main_menu = True
                            remove_file = False
                            msg = "Database Has No Minion Files Currently!!!!"
                            msg_strt_pnt = int((terminal_size()[0]-len(msg))/2)
                            print(f"\n\n\033[{msg_strt_pnt}G{message_color1(msg)}")
                            time.sleep(1)
                            continue

                        print()

                        for i in range(len(results)):
                            print(f"\033[4G{message_color1(f'{i+1} - {results[i]}')}")

                        answer = input_with_timeout(f"\n\t{message_color1('Make a Selection -->')} ", 30)

                        if answer is None or answer.lower() == 'l':
                            main_run = False
                            remove_file = False
                            continue

                        elif answer.isnumeric() is True and int(answer) <= len(results) and int(answer) != 0:

                            while True:
                                os.system("clear")
                                msg = "Remove File"
                                msg1 = results[int(answer)-1]
                                strt_point = int((terminal_size()[0] - len(msg))/2)
                                strt_point1 = int((terminal_size()[0] - len(msg1))/2)
                                print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(msg1)}")
                                conformation = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                if conformation is None or conformation.lower() == 'l':
                                    main_run = False
                                    remove_file = False
                                    break

                                # User Called for the Program to Quit.
                                elif conformation.lower() == 'q':
                                    main_run = False
                                    remove_file = False
                                    event.set()
                                    break

                                # User Called for Main Menu.
                                elif conformation.lower() == 'm':
                                    main_menu = True
                                    remove_file = False
                                    break

                                elif conformation.lower() == 'y':
                                    remove_file = False
                                    break

                                elif conformation.lower() == 'n':
                                    break

                            continue
                        
                        elif answer.lower() == 'q':
                            main_run = False
                            remove_file = False
                            event.set()
                            continue

                        elif answer.lower() == 'm':
                            main_menu = True
                            remove_file = False
                            continue

                    if event.is_set() is True or main_menu is True or main_run is False:
                        continue

                    write_to_database('''DELETE FROM Minions WHERE path=?''', file, (results[int(answer)-1],))
                    dataq.put("CHANGE|")

                elif int(main_input) == 3:
                    stopping = True

                    while stopping is True:
                        modes = "Stop a Minion Program"
                        options = "OPTIONS  q-QUIT  m-MAIN MENU  l-LOG OUT"
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        results = running_programs(db_list_maker(
                            read_from_database(
                                '''SELECT path FROM Minions''',
                                file
                            )),
                            err_event
                        )

                        if len(results) == 0:
                            main_menu = True
                            stopping = False
                            msg = "Currently No Minions Are Running!!!!"
                            msg_strt_pnt = int((terminal_size()[0]-len(msg))/2)
                            print(f"\n\n\033[{msg_strt_pnt}G{message_color1(msg)}")
                            time.sleep(1)
                            continue

                        print()

                        for i in range(len(results)):
                            print(f"\033[4G{message_color1(f'{i+1} - {results[i]}')}")

                        answer = input_with_timeout(f"\n\t{message_color1('Make a Selection -->')} ", 30)

                        if answer is None or answer.lower() == 'l':
                            main_run = False
                            stopping = False
                            continue

                        elif answer.lower() == 'q':
                            main_run = False
                            stopping = False
                            event.set()
                            continue

                        elif answer.lower() == 'm':
                            main_menu = True
                            stopping = False
                            continue

                        elif answer.lower() == 'l':
                            main_run = False
                            stopping = False
                            continue

                        elif answer.isnumeric() is True and int(answer) <= len(results) and int(answer) != 0:

                            while True:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Stop Program"
                                msg1 = results[int(answer)-1]
                                strt_point = int((columns - len(msg))/2)
                                strt_point1 = int((columns - len(msg1))/2)
                                print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(msg1)}")
                                conformation = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                if conformation is None or conformation.lower() == 'l':
                                    main_run = False
                                    stopping = False
                                    break

                                # User Called for the Program to Quit.
                                elif conformation.lower() == 'q':
                                    main_run = False
                                    stopping = False
                                    event.set()
                                    break

                                # User Called for Main Menu.
                                elif conformation.lower() == 'm':
                                    main_menu = True
                                    stopping = False
                                    break

                                elif conformation.lower() == 'y':
                                    stopping = False
                                    break

                                elif conformation.lower() == 'n':
                                    break

                            if event.is_set() is True or main_menu is True or main_run is False or \
                                    stopping is True:
                                continue

                            dataq.put(f"KILL|{results[int(answer)-1]}")

                elif int(main_input) == 4:
                    restrt = True

                    while restrt is True:
                        modes = "Start/Restart a Minion Program"
                        options = "OPTIONS  q-QUIT  m-MAIN MENU  l-LOG OUT"
                        main_header(title, modes, options, err_event.is_set(), False)

                        if err_event.is_set() is True:
                            err_event.clear()

                        results = db_list_maker(read_from_database('''SELECT path FROM Minions''', file))

                        if len(results) == 0:
                            main_menu = True
                            restrt = False
                            msg = "Database Has No Minion Files Currently!!!!"
                            msg_strt_pnt = int((terminal_size()[0]-len(msg))/2)
                            print(f"\n\n\033[{msg_strt_pnt}G{message_color1(msg)}")
                            time.sleep(1)
                            continue

                        msg_lines = []
                        strt_point = 4

                        for i in range(len(results)):
                            file_name = results[i].split('/')[len(results[i].split('/'))-1]

                            for i1 in pid_getter(results[i], err_event):
                                
                                msg = f"{i+1}    -->    {file_name}    -->    RUNNING" if i1 is not None else \
                                    f"{i+1}    -->    {file_name}    -->    NOT RUNNING"

                                if len(msg) > strt_point:
                                    strt_point = len(msg)

                                msg_lines.append(msg)
                                break

                        strt_point = int((terminal_size()[0] - strt_point)/2)
                        print()

                        for i in msg_lines:
                            print(f"\033[{strt_point}G{adding_extra_color(i, True)}")

                        answer = input_with_timeout(f"\n\t{message_color1('Make a Selection -->')} ", 30)

                        if answer is None or answer.lower() == 'l':
                            main_run = False
                            restrt = False
                            continue

                        elif answer.lower() == 'q':
                            main_run = False
                            restrt = False
                            event.set()
                            continue

                        elif answer.lower() == 'm':
                            main_menu = True
                            restrt = False
                            continue

                        elif answer.isnumeric() is True and int(answer) <= len(results) and int(answer) != 0:

                            while True:
                                os.system("clear")
                                columns = terminal_size()[0]
                                msg = "Start/Restart Program"
                                msg1 = results[int(answer)-1]
                                strt_point = int((columns - len(msg))/2)
                                strt_point1 = int((columns - len(msg1))/2)
                                print(f"\n\033[{strt_point}G{message_color1(msg)}\n\033[{strt_point1}G{message_color1(msg1)}")
                                conformation = input_with_timeout(f"\n\t{message_color1('Is This Correct. [y,n] -->')} ", 15)

                                if conformation is None or conformation.lower() == 'l':
                                    main_run = False
                                    restrt = False
                                    break

                                # User Called for the Program to Quit.
                                elif conformation.lower() == 'q':
                                    main_run = False
                                    restrt = False
                                    event.set()
                                    break

                                # User Called for Main Menu.
                                elif conformation.lower() == 'm':
                                    main_menu = True
                                    restrt = False
                                    break

                                elif conformation.lower() == 'y':
                                    restrt = False
                                    break

                                elif conformation.lower() == 'n':
                                    break

                            if event.is_set() is True or main_menu is True or main_run is False or \
                                    restrt is True:
                                continue

                            dataq.put(f"RESTRT|{results[int(answer)-1]}")

                else:
                    pass

    return


if __name__ == '__main__':
    pw = start_up()
    dataq = TQ()
    kevent = threading.Event()
    err_event = threading.Event()
    tlock = threading.Lock()
    main_file_hash = hashing_file(f"{find_directory(__file__)}/Sauron.py")
    file = f"{find_directory(__file__)}/Sauron.db"
    first_time = os.path.exists(file)
    make_db_file(file)
    time.sleep(1)
    kevent.clear()
    err_event.clear()

    tqui = threading.Thread(target=gui, args=(kevent, dataq, tlock, file, err_event, first_time))
    tqui.setDaemon(True)
    tqui.start()

    time.sleep(2)

    '''
    Dictionary Holding all the information for the file.
    {Directory: {"ALIAS": Name of Program,
                 "CREDS": Encrypted String,
                 "PARGS": System Arguments,
                 "PID": {MAIN PID: [PID, PID]},
                 "HASH": Hash of the File,
                 "STRTTIME": Datetime Object}}
    '''
    stopped_programs = []
    directories = dicionary_compare({}, get_directories(file, err_event), pw, err_event, stopped_programs)
    strt_tm = datetime.datetime.now()

    while kevent.is_set() is False:
        dt = datetime.datetime.now()
        checks = False

        if dt >= strt_tm + datetime.timedelta(seconds=10):
            strt_tm = dt
            checks = True
            directories = dicionary_compare(directories, get_directories(file, err_event), pw, err_event, stopped_programs)

        if not dataq.empty():
            info = dataq.get().split('|')

            if info[0] == "PW":
                pw = info[1]
                directories = dicionary_compare({}, directories, pw, err_event, stopped_programs)

            elif info[0] == "CHANGE":
                directories = dicionary_compare(directories, get_directories(file, err_event), pw, err_event, stopped_programs)
                os.system(f"cp {file} {Path.home()}/.giblets")
            
            elif info[0] == "KILL":
                stopped_programs.append(info[1])
                pid = None

                for i in directories[info[1]]["PID"]:
                    pid = i

                if pid is not None:
                    stop_program(info[1], directories[info[1]]['PID'], err_event)
                    directories[info[1]]["STRTTIME"] = datetime.datetime.now()
                    directories[info[1]]['PID'] = pid_getter(info[1], err_event)

            elif info[0] == "RESTRT":
                
                if info[1] in stopped_programs:
                    stopped_programs.remove(info[1])

                if info[1] in directories:
                    rstrt_pid = None

                    for i in directories[info[1]]:
                        rstrt_pid = i

                    if rstrt_pid is None:
                        starting_files(
                            directories[info[1]]["CREDS"],
                            directories[info[1]]["ALIAS"],
                            directories[info[1]]["TYPE"],
                            directories[info[1]]["PARGS"],
                            pw,
                            info[1],
                            err_event
                        )

                        directories[info[1]]["PID"] = pid_getter(info[1], err_event)
                        directories[info[1]]["STRTTIME"] = datetime.datetime.now()

                    else:
                        stop_program(info[1], directories[info[1]]['PID'], err_event)
                        starting_files(
                            directories[info[1]]["CREDS"],
                            directories[info[1]]["ALIAS"],
                            directories[info[1]]["TYPE"],
                            directories[info[1]]["PARGS"],
                            pw,
                            info[1],
                            err_event
                        )

                        directories[info[1]]["PID"] = pid_getter(info[1], err_event)
                        directories[info[1]]["STRTTIME"] = datetime.datetime.now()

        if main_file_hash != hashing_file(f"{find_directory(__file__)}/Sauron.py"):
            fifo_path = f"{find_random_path()}{uuid.uuid4()}"
            command = f'screen -dm -S sauron python3 {find_directory(__file__)}/Sauron.py {fifo_path}'
            os.system(command)
            time.sleep(1)

            if pipe_writer(fifo_path, str(pw)) is False:
                err_event.set()
                err = f"{tacs}Pipe Writer{tacs}\n\tFile Name: {fifo_path}\n{tacs}Pipe Writer{tacs}\n"
                logger(err)

            else:
                os.kill(os.getpid(), signal.SIGTERM)

        time.sleep(2)

    tqui.join()
    os.system("clear")
    print("Good Bye!!!!")
