# Assignment Description

## 1. Environmental Configuration Requirements

### a. Server
* **Language:** Must be implemented in C language.
* **Protocol:** Must use TCP only.
* **Architecture:** Must use multiprocessing (`fork`).
* **Compiler:** Must compile using `gcc`.
* **Build Tool:** Must build using a `Makefile`.
* **File Naming:** Server file name should be `server_<last4digits_registrationNo>.c`. 
    * *Example:* Assume registration number `IT24103733` ➔ `server_3733.c`
* **Port Number:** `PORT = 50<last 3 digits_registrationNo>`.
    * *Example:* `IT24103733` ➔ Port = `50733`
* **Server ID in Responses:** Every server response must include: `SID:<middle4digits>`.
    * *Example:* `SID:1037`
* **Log File Name:** `server_<regno>.log`.
    * *Example:* `server_IT24103733.log`
* **Data Storage:** Server must store data under: `/srv/ie2102/<regno>/<username>/`.
    * *Example:* `/srv/ie2102/IT24103733/amal/`

### b. Client
* **Language:** Must be implemented in Python.
* **File Naming:** Client file name should be `client_<last4digits_registrationNo>.py`.
    * *Example:* Assume registration number `IT24103733` ➔ `client_3733.py`

### c. Makefile
* **File Naming:** Make file name: `Makefile_<last4digits>`.
    * *Example:* `Makefile_3733`
* **Build Command:** Build using: `make -f Makefile_5678`

---

## Assignment Tasks

### a. PART A – Take-Home Component

#### A1 – Custom TCP Protocol
1.  Implement explicit framing architecture.
2.  **Client sends:**
    ```text
    LEN:<n>
    <payload>
    ```
3.  Where `<n>` equals the exact payload byte count.
4.  **Server must handle:**
    * Partial `recv()`
    * Multiple messages in one buffer
    * Invalid length
    * Oversized payload (>4096 bytes)
5.  **Response format:**
    ```text
    OK <code> SID:<middle4digits> <message>
    ERR <code> SID:<middle4digits> <message>
    ```

#### A2 – Multiprocessing Design Using `fork()`
6.  **Server must:**
    * Accept multiple clients concurrently using `fork()`.
    * Parent continues accepting connections.
    * Child handles one client session.
7.  **Proper `SIGCHLD` handling:**
    * `waitpid()` to avoid zombie processes.
    * Clean shutdown behavior.
    * Must demonstrate handling at least 10 concurrent clients.

#### A3 – Authentication + Session Tokens
8.  **Required commands:**
    ```text
    REGISTER <user> <pass>
    LOGIN <user> <pass>
    LOGOUT
    ```
9.  **Rules:**
    * Passwords must not be stored in plain text.
    * Must use salted hashing.
    * On login, the server issues a session token.
    * Protected commands require a token.
    * Token expires after inactivity (e.g., 5 minutes).

#### A4 – Abuse Protection
Must implement:
10. Rate limiting per client.
11. Login brute-force lockout.
12. Username validation.
13. Payload overflow rejection.

#### A5 – Persistent Audit Logging
Log must include:
14. Timestamp.
15. Client IP:port.
16. Child PID.
17. Username (if logged in).
18. Command and result.
19. **Log file name:** `server_<regno>.log` (e.g., `server_IT12345678.log`).

---

### Report Requirements
**Create a report for the Take-home component.**

20. **The report must include screenshots of:**
    * **a.** Hostname configuration.
    * **b.** Network configuration.
    * **c.** Server running (port proof using `ss`/`netstat`).
    * **d.** Successful `REGISTER` and `LOGIN`.
    * **e.** Failed login + lockout proof.
    * **f.** Multiple forked processes (`ps` output).
    * **g.** Log file entries.
    * **h.** Proper child cleanup (no zombie processes).
21. Screenshots must visibly show your registration number. Provide...


