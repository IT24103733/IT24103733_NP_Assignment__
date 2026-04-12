#!/usr/bin/env python3
"""
client_3733.py — Interactive CLI Client for Network Programming Assignment

Registration: IT24103733
Server Port:  50733

Menu-driven interface with 3 screens:
  1. Welcome   — LOGIN / REGISTER / Quit
  2. Auth      — Login or Register prompts
  3. Session   — Logged-in view with LOGOUT

Protocol layer is hidden from the user. All communication uses
the custom LEN:<n>\\n<payload> framing protocol.
"""

import socket
import sys
import re
import getpass
import os

# ============================================================
#  Constants
# ============================================================

SERVER_HOST = "localhost"
SERVER_PORT = 50733
RECV_SIZE = 4096

# ============================================================
#  ANSI Color Codes
# ============================================================

class Color:
    """ANSI escape codes for terminal colors."""
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    CYAN    = "\033[96m"
    GREY    = "\033[90m"
    WHITE   = "\033[97m"

def success(msg):
    """Print a green success message."""
    print(f"\n  {Color.GREEN}✓ {msg}{Color.RESET}")

def error(msg):
    """Print a red error message."""
    print(f"\n  {Color.RED}✗ {msg}{Color.RESET}")

def warning(msg):
    """Print a yellow warning message."""
    print(f"\n  {Color.YELLOW}⚠ {msg}{Color.RESET}")

def info(msg):
    """Print a cyan info message."""
    print(f"  {Color.CYAN}{msg}{Color.RESET}")

def dim(msg):
    """Print a grey dim message."""
    print(f"  {Color.GREY}{msg}{Color.RESET}")


# ============================================================
#  Protocol Layer (hidden from user)
# ============================================================

def send_command(sock, payload: str):
    """
    Send a framed message to the server.

    Protocol: LEN:<n>\\n<payload>
    where <n> is the byte count of the encoded payload.
    """
    data = payload.encode("utf-8")
    frame = f"LEN:{len(data)}\n".encode("utf-8") + data
    sock.sendall(frame)


def recv_response(sock):
    """
    Receive and parse a server response.

    Expected format: "<status> <code> SID:<sid> <message>\\n"
    Example: "OK 200 SID:1037 Login successful TOKEN:abc123\\n"

    Returns: dict with keys: status, code, sid, message
             or None if connection closed.
    """
    response = b""
    while True:
        chunk = sock.recv(RECV_SIZE)
        if not chunk:
            return None  # Connection closed
        response += chunk
        if b"\n" in response:
            break

    line = response.decode("utf-8").strip()
    if not line:
        return None

    # Parse: "<status> <code> SID:<sid> <message>"
    parts = line.split(" ", 3)
    if len(parts) < 4:
        return {"status": "ERR", "code": 0, "sid": "", "message": line}

    status = parts[0]
    try:
        code = int(parts[1])
    except ValueError:
        code = 0

    # Extract SID from "SID:1037"
    sid = parts[2].replace("SID:", "")

    message = parts[3]

    return {"status": status, "code": code, "sid": sid, "message": message}


# ============================================================
#  Client-Side Validation
# ============================================================

def validate_username(username: str) -> str | None:
    """
    Validate a username before sending to server.

    Rules: 3-32 chars, alphanumeric + underscore only.
    Returns error message string or None if valid.
    """
    if not username:
        return "Username cannot be empty"
    if len(username) < 3:
        return "Username must be at least 3 characters"
    if len(username) > 32:
        return "Username must be at most 32 characters"
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return "Username can only contain letters, numbers, and underscore"
    if ".." in username:
        return "Invalid username"
    return None


def validate_password(password: str) -> str | None:
    """
    Validate a password before sending to server.

    Rules: non-empty, minimum 4 characters.
    Returns error message string or None if valid.
    """
    if not password:
        return "Password cannot be empty"
    if len(password) < 4:
        return "Password must be at least 4 characters"
    return None


# ============================================================
#  Screen Functions
# ============================================================

def clear_screen():
    """Clear the terminal screen."""
    os.system("cls" if os.name == "nt" else "clear")


def show_welcome_banner(host, port):
    """Display the welcome banner with connection info."""
    print()
    print(f" {Color.CYAN}Connected to {host}:{port}{Color.RESET}             ")
    print(f" {Color.WHITE}Welcome to NP Assignment Demo!{Color.RESET}        ")
    print(f" {Color.GREY}Registration: IT24103733{Color.RESET}               ")
    print()


def screen_welcome(sock):
    """
    Screen 1 — Welcome (unauthenticated).

    Options: 1) LOGIN, 2) REGISTER, Q) Exit
    Returns: "login", "register", or "quit"
    """
    clear_screen()
    show_welcome_banner(SERVER_HOST, SERVER_PORT)

    info("Please pick an option:\n")
    print(f"    {Color.BOLD}1){Color.RESET} LOGIN     — Already have an account?")
    print(f"    {Color.BOLD}2){Color.RESET} REGISTER  — New member? Create an account")
    print()
    dim("Press Q to exit")
    print()

    while True:
        try:
            choice = input(f"  {Color.CYAN}>{Color.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return "quit"

        if choice == "1":
            return "login"
        elif choice == "2":
            return "register"
        elif choice == "q":
            return "quit"
        else:
            warning("Invalid option. Please enter 1, 2, or Q.")


def screen_login(sock):
    """
    Screen 2a — Login.

    Prompts for username and password, sends LOGIN to server.
    Returns: (username, token) on success, or None on failure/back.
    """
    clear_screen()
    print(f"\n  {Color.BOLD}━━━ LOGIN ━━━{Color.RESET}\n")

    while True:
        # --- Username ---
        try:
            username = input(f"  {Color.CYAN}Username:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        err = validate_username(username)
        if err:
            error(err)
            continue

        # --- Password ---
        try:
            password = input(f"  {Color.CYAN}Password:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        err = validate_password(password)
        if err:
            error(err)
            continue

        # --- Send to server ---
        try:
            send_command(sock, f"LOGIN {username} {password}")
            resp = recv_response(sock)
        except (ConnectionError, OSError):
            error("Connection lost. Exiting.")
            return "disconnect"

        if resp is None:
            error("Server closed the connection.")
            return "disconnect"

        if resp["status"] == "OK":
            # Extract token from message
            token = ""
            msg = resp["message"]
            if "TOKEN:" in msg:
                token = msg.split("TOKEN:")[1].strip()
            success(f"Login successful! Welcome, {Color.BOLD}{username}{Color.RESET}")
            dim(f"Token: {token[:16]}...")
            input(f"\n  {Color.GREY}Press Enter to continue...{Color.RESET}")
            return (username, token)
        else:
            error(resp["message"])
            print()
            try:
                retry = input(f"  {Color.GREY}Press Enter to try again or Q to go back:{Color.RESET} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return None
            if retry == "q":
                return None
            print()
            continue


def screen_register(sock):
    """
    Screen 2b — Register.

    Prompts for username, password, and password confirmation.
    Sends REGISTER to server.
    Returns: True on success, None on failure/back.
    """
    clear_screen()
    print(f"\n  {Color.BOLD}━━━ REGISTER ━━━{Color.RESET}\n")

    while True:
        # --- Username ---
        try:
            username = input(f"  {Color.CYAN}Choose a username:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        err = validate_username(username)
        if err:
            error(err)
            continue

        # --- Password ---
        try:
            password = input(f"  {Color.CYAN}Choose a password:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        err = validate_password(password)
        if err:
            error(err)
            continue

        # --- Confirm password ---
        try:
            confirm = input(f"  {Color.CYAN}Confirm password:{Color.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        if password != confirm:
            error("Passwords do not match")
            continue

        # --- Send to server ---
        try:
            send_command(sock, f"REGISTER {username} {password}")
            resp = recv_response(sock)
        except (ConnectionError, OSError):
            error("Connection lost. Exiting.")
            return "disconnect"

        if resp is None:
            error("Server closed the connection.")
            return "disconnect"

        if resp["status"] == "OK":
            success("Registration successful! You can now login.")
            input(f"\n  {Color.GREY}Press Enter to continue...{Color.RESET}")
            return True
        else:
            error(resp["message"])
            print()
            try:
                retry = input(f"  {Color.GREY}Press Enter to try again or Q to go back:{Color.RESET} ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                return None
            if retry == "q":
                return None
            print()
            continue


def screen_session(sock, username, token):
    """
    Screen 3 — Session (authenticated).

    Options: 1) LOGOUT, Q) Quit (auto-logout first)
    Returns: "logout" or "quit"
    """
    clear_screen()
    print(f"\n  {Color.BOLD}━━━ Logged in as: {Color.GREEN}{username}{Color.RESET}{Color.BOLD} ━━━{Color.RESET}\n")
    dim(f"Session active | SID: 1037")
    print()
    print(f"    {Color.BOLD}1){Color.RESET} LOGOUT  — End your session")
    print()
    dim("Press Q to quit (auto-logout)")
    print()

    while True:
        try:
            choice = input(f"  {Color.CYAN}>{Color.RESET} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            # Attempt logout before exiting
            try:
                send_command(sock, f"LOGOUT {token}")
                recv_response(sock)
            except (ConnectionError, OSError):
                pass
            return "quit"

        if choice == "1":
            # Send LOGOUT to server
            try:
                send_command(sock, f"LOGOUT {token}")
                resp = recv_response(sock)
            except (ConnectionError, OSError):
                error("Connection lost. Exiting.")
                return "quit"

            if resp is None:
                error("Server closed the connection.")
                return "quit"

            if resp["status"] == "OK":
                success("Logged out successfully")
                input(f"\n  {Color.GREY}Press Enter to continue...{Color.RESET}")
                return "logout"
            else:
                error(resp["message"])

        elif choice == "q":
            # Auto-logout then quit
            try:
                send_command(sock, f"LOGOUT {token}")
                resp = recv_response(sock)
                if resp and resp["status"] == "OK":
                    success("Logged out successfully")
            except (ConnectionError, OSError):
                pass
            return "quit"

        else:
            warning("Invalid option. Please enter 1 or Q.")


# ============================================================
#  Main Application Loop
# ============================================================

def connect_to_server():
    """Establish a TCP connection to the server."""
    try:
        sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=5)
        sock.settimeout(30)  # 30s timeout for recv during session
        return sock
    except ConnectionRefusedError:
        error(f"Connection refused. Is the server running on {SERVER_HOST}:{SERVER_PORT}?")
        return None
    except socket.timeout:
        error("Connection timed out.")
        return None
    except OSError as e:
        error(f"Connection failed: {e}")
        return None


def main():
    """Main application entry point."""
    # --- Connect to server ---
    sock = connect_to_server()
    if sock is None:
        sys.exit(1)

    try:
        while True:
            # --- Screen 1: Welcome ---
            action = screen_welcome(sock)

            if action == "quit":
                break

            elif action == "login":
                result = screen_login(sock)

                if result == "disconnect":
                    break
                elif result is None:
                    continue  # Back to Welcome
                else:
                    # Login successful: (username, token)
                    username, token = result

                    # --- Screen 3: Session ---
                    session_result = screen_session(sock, username, token)

                    if session_result == "quit":
                        break
                    # "logout" -> back to Welcome loop

            elif action == "register":
                result = screen_register(sock)

                if result == "disconnect":
                    break
                # True or None -> back to Welcome

    except KeyboardInterrupt:
        print()
        dim("Interrupted. Disconnecting...")
    finally:
        try:
            sock.close()
        except OSError:
            pass
        print()
        dim("Disconnected. Goodbye!")
        print()


if __name__ == "__main__":
    main()
