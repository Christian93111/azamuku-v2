# Azamuku v2

A Python-based C2 (Command and Control) server with support for HTTP/HTTPS, tunneling (ngrok, localtunnel), and payload generation.

**Authors:**

- [otter](https://github.com/whatotter)
- Supported by [Fan2K](https://github.com/Christian93111)

**Credits & Inspiration:**

- Based on the original [Azamuku](https://github.com/whatotter/azamuku) repository.
- Inspired by [HoaxShell](https://github.com/t3l3machus/hoaxshell).

## **DISCLAIMERS**

- **_Please don't use this in real world attacks. This was made for educational purposes and I'd like to keep it that way. I'm also not responsible of what you do with this tool - you are responsible of your own actions._**
- This isn't meant to be "best reverse shell ever!!!" This was just a little project to teach me more about AMSI, powershell, and windows defender, that turned out to be an actual pretty cool tool.
- This isn't foolproof.
- HTTPS doesn't really work perfectly, but it's not expected of you to use it anyways.
- It's **highly** recommended to create/obfuscate the payload - Microsoft does crawl github to find payloads, and it's highly likely it's found the one here.

## Features

- **HTTP & HTTPS Server:** Easily host your C2 server on HTTP or HTTPS.
- **Tunneling Support:** Built-in support for `ngrok` and `localtunnel` to expose your local server to the internet.
- **Payload Generation:** Automatically generate payloads for your specific configuration (HTTP, HTTPS, Tunnels).
- **Interactive Shell:** Drop into a shell on connected victims.
- **Session Management:** View connected victims, remove sessions, and manage authorizations.
- **Multi-Client Execution:** Run commands on multiple selected victims simultaneously.
- **Stager Support:** Execute a sequence of commands from a file upon connection.
- **Strict Mode:** Disable initial information gathering for stealth.

## How does it work?

Azamuku is a reverse shell that aims to bypass Windows Defender, AMSI, and even Malwarebytes. It is designed to look like normal traffic to sysadmins inspecting LAN/WAN traffic due to alternating endpoints and HTML-wrapped commands.

**Flow:**

1.  The victim connects to the implementation.
2.  The implementation checks the command pool for commands.
3.  The HTML response when checking the command pool is an HTML file from `./core/masks/html`, with a replaced tag - these are called **masks**.
4.  Once it receives and parses the command from the mask, it runs the command.
5.  It POSTs the output to a random endpoint from `./core/masks/endpoints.txt`, which the server automatically receives and saves.

It uses HTTP GET requests to beacon and HTTP POST requests to send data.

### What's a Mask?

A "mask" in this situation is an HTML file (could be literally anything actually) with a specific HTML comment tag:

```html
<!--%()%-->
```

The Azamuku manager will automatically replace `%()%` with the encoded command for the victim to parse.

**Where do I get a mask?**
Literally anywhere. A good way of making some is:

1.  Open the site you want to turn into a mask.
2.  Right click -> View Source.
3.  Copy and paste everything into a new file under `./core/masks/html/` (ex: `google.html`).
4.  Paste it in that file, find somewhere to make a comment, paste the tag `<!--%()%-->`.
5.  Enjoy.

A mask could literally just be:

```html
<!DOCTYPE html>
<html>
  <body>
    <h1>My First Heading</h1>
    <p>My first paragraph.</p>

    <!--%()%-->
    < heres the comment tag
  </body>
</html>
```

The payload will automatically figure out which comment is correct (usually), so you can use any HTML content.

## Requirements

- Python 3
- `prettytable`
- `openssl`
- `ngrok`
- `localtunnel`

## Installation

1. Clone the repository.
   ```bash
   git clone https://github.com/Christian93111/azamuku-v2.git && cd azamuku-v2
   ```
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Make executable (Linux):
   ```bash
   chmod +x azamuku.py
   ```

## Usage

Start the server using `python3 azamuku.py`. You can configure it using the following arguments:

### Command Line Arguments

| Argument               | Description                                              | Default        |
| :--------------------- | :------------------------------------------------------- | :------------- |
| `-s`, `--server`       | IP to bind the HTTP(s) server to                         | `0.0.0.0`      |
| `--http-port`          | Port to bind the HTTP server to                          | `8080`         |
| `--https-port`         | Port to bind the HTTPS server to                         | `0` (Disabled) |
| `--certfile`           | Certificate file for HTTPS                               | `server.pem`   |
| `--keyfile`            | Key file for HTTPS                                       | `key.pem`      |
| `--stager`             | A text file containing commands to execute on connection | `None`         |
| `--strict`             | Disable information gathering commands                   | `False`        |
| `-lt`, `--localtunnel` | Use localtunnel for tunneling                            | `False`        |
| `-ng`, `--ngrok`       | Use ngrok for tunneling                                  | `False`        |
| `-b64`, `--base64`     | Use base64 encoding for payload                          | `False`        |

**Examples:**

```bash
# Start with default settings
python3 azamuku.py

# Start with HTTPS on port 443
python3 azamuku.py --https-port 443

# Start with ngrok tunneling
python3 azamuku.py --ngrok

# Start with ngrok tunneling and base64 encoding
python3 azamuku.py --ngrok --base64
```

### Advanced Usage Tips

**Using HTTPS:**
If certificate files don't exist, Azamuku will ask if you'd like to make them using openssl.

```bash
python3 azamuku.py --certfile cert.pem --keyfile key.pem
```

**Stager/Autorun Commands:**
You can load a list of commands to run automatically:

```bash
python3 azamuku.py --stager script.txt
```

**With Domain Name:**
You don't need to do anything special here. When you generate the payload, just set it as your domain instead of your IP.

```bash
python3 azamuku.py -s 0.0.0.0 --http-port 80
[azamuku]> payload example.com 80
```

## Interactive Console Commands

Once the server is running, you can use the following commands in the Azamuku console:

| Command         | Arguments               | Description                                                                                                                                                                                                 |
| :-------------- | :---------------------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `help`          | None                    | Displays the help menu with a list of commands.                                                                                                                                                             |
| `clear`         | None                    | Clears the terminal screen.                                                                                                                                                                                 |
| `info`          | None                    | Shows a table of all connected victims with their UIDs, IP addresses, Hostnames, and Status.                                                                                                                |
| `shell`         | `<uid>`                 | Opens an interactive shell session with the specified victim. <br> **Example:** `shell 12345`                                                                                                               |
| `payload`       | `[ip] [port]`           | Generates a payload script. If a tunnel is active (ngrok/localtunnel), it will automatically use the tunnel URL. Otherwise, you must provide the IP and Port. <br> **Example:** `payload 192.168.1.10 8080` |
| `allow`         | `<uid>` or `<filename>` | Authorizes a specific UID or imports a list of UIDs from a file. Allowed UIDs can connect back to the server. <br> **Example:** `allow 12345` or `allow old_sessions.txt`                                   |
| `grab`          | None                    | Toggles "grabbing" mode. When enabled, the server will accept connections from ANY UID, even if not explicitly authorized (useful for reconnecting lost sessions).                                          |
| `export`        | `<filename>`            | Saves the current list of authorized UIDs to a file. <br> **Example:** `export sessions.txt`                                                                                                                |
| `wait`          | None                    | Waits for the next new connection and automatically drops you into a shell for that victim.                                                                                                                 |
| `rm`            | `<uid>`                 | Removes a victim from the session list and de-authorizes their UID. <br> **Example:** `rm 12345`                                                                                                            |
| `select`        | `<uid>` or `*`          | Toggles selection of a UID for multi-execution. Use `*` to select/deselect all currently connected victims. <br> **Example:** `select 12345` or `select *`                                                  |
| `multirun`      | `<command>`             | Executes a shell command on all currently _selected_ victims. <br> **Example:** `multirun whoami`                                                                                                           |
| `exit` / `quit` | None                    | Terminates the server and all active connections.                                                                                                                                                           |
| `base64`        | None                    | Toggles base64 encoding for payload                                                                                                                                                                         |

## Limits

- **No True Interactive Shells:** Since this is HTTP-based, it is not a true interactive shell (like SSH or Netcat). It polls for commands.
- **Latency:** There might be a delay depending on the beacon interval.
