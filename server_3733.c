/*
 * server_3733.c - TCP Server for Network Programming Assignment
 *
 * Registration: IT24103733
 * Port:         50733
 * SID:          1037
 *
 * This file contains all server logic organized into clearly separated
 * sections:
 *   1. Constants & Structs
 *   2. Protocol           (send_response, read_message)
 *   3. Authentication      (validate_username, hash_password, verify_password,
 *                           generate_token, check_lockout, record_failed_login,
 *                           reset_lockout, handle_register, handle_login,
 *                           handle_logout)
 *   4. Abuse Protection    (check_rate_limit)
 *   5. Audit Logging       (audit_log)
 *   6. Socket & Process    (setup_server, sigchld_handler, handle_client)
 *   7. Main
 */

#define _GNU_SOURCE /* Required for memmem() */

#include <arpa/inet.h>
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ============================================================
 *  Section 1: Constants & Structs
 * ============================================================ */

#define PORT "50733"
#define SID "1037"
#define MAX_PAYLOAD 4096 // Max payload set to 4096 bytes
#define BUF_SIZE 8192
#define BACKLOG 10
#define TOKEN_LEN 32
#define SESSION_TIMEOUT 300

#define DATA_BASE_PATH "srv/ie2102/IT24103733"

// Audit logging
#define LOG_FILE "server_IT24103733.log"

// Abuse protection: brute-force login lockout
#define MAX_LOGIN_ATTEMPTS 5
#define LOCKOUT_DURATION 900 /* 15 minutes in seconds */

// Abuse protection: rate limiting (A4.10)
#define RATE_LIMIT_WINDOW 60 /* sliding window in seconds */
#define RATE_LIMIT_MAX 30    /* max requests per window */

// Abuse protection: consecutive error threshold
#define MAX_CONSECUTIVE_ERRORS 3

// Rate limiter state — circular buffer of request timestamps
typedef struct {
  time_t timestamps[RATE_LIMIT_MAX + 1];
  int head;  // next write position
  int count; // total entries in buffer
} rate_limiter_t;

// Client session state — one per forked child
typedef struct {
  char username[64];
  char token[TOKEN_LEN * 2 + 1];
  time_t last_activity;
  int is_authenticated;
  char client_ip[INET_ADDRSTRLEN];
  int client_port;
} client_session_t;

/* Persistent read buffer for protocol parsing */
typedef struct {
  char data[BUF_SIZE];
  int len; /* bytes currently in buffer */
} read_buffer_t;

/* Global flag for clean shutdown */
static volatile sig_atomic_t g_shutdown = 0;
static int g_listen_fd = -1; /* For signal handler access */

/* Forward declaration — defined in Section 5 */
static void audit_log(const client_session_t *session, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* ============================================================
 *  Section 2: Protocol — send_response(), read_message()
 * ============================================================ */

/*
 * send_response — Format and send a protocol response to the client.
 *
 * Format: "<status> <code> SID:<sid> <message>\n"
 * Example: "OK 200 SID:1037 PONG\n"
 *
 * Returns: bytes sent on success, -1 on error.
 */
static int send_response(int fd, const char *status, int code,
                         const char *msg) {
  char response[MAX_PAYLOAD + 128];
  int n = snprintf(response, sizeof(response), "%s %d SID:%s %s\n", status,
                   code, SID, msg);

  if (n < 0 || n >= (int)sizeof(response)) {
    return -1;
  }

  int total_sent = 0;
  while (total_sent < n) {
    int sent = send(fd, response + total_sent, n - total_sent, 0);
    if (sent <= 0) {
      return -1;
    }
    total_sent += sent;
  }

  return total_sent;
}

/*
 * read_message — Read one complete framed message from the client.
 *
 * Protocol frame: "LEN:<n>\n<payload>"
 *   where <n> is the exact byte count of <payload>.
 *
 * Handles:
 *   - Partial recv()  (accumulates data across multiple reads)
 *   - Pipelined messages (advances past consumed message in buffer)
 *   - Invalid LEN: header
 *   - Oversized payload (> MAX_PAYLOAD)
 *
 * Parameters:
 *   fd      — client socket file descriptor
 *   buf     — persistent read buffer (preserves unconsumed data between calls)
 *   payload — output buffer for extracted payload (must be >= MAX_PAYLOAD + 1)
 *
 * Returns:
 *   > 0 : payload length (success)
 *     0 : client disconnected cleanly
 *    -1 : protocol error (response already sent to client, keep connection
 * open) -2 : fatal error (connection should be closed)
 */
static int read_message(int fd, read_buffer_t *buf, char *payload) {
  while (1) {
    // Try to parse a complete message from buffered data
    if (buf->len > 0) {
      // Need at least 4 bytes for LEN:
      if (buf->len >= 4) {

        // Verifying LEN: prefix
        if (strncmp(buf->data, "LEN:", 4) != 0) {
          send_response(fd, "ERR", 400, "Invalid frame");

          // Attempting recovery: find next LEN: in buffer
          char *next = memmem(buf->data + 1, buf->len - 1, "LEN:", 4);
          if (next) {
            int skip = next - buf->data;
            memmove(buf->data, next, buf->len - skip);
            buf->len -= skip;
          } else {
            buf->len = 0;
          }
          return -1;
        }

        // Looking for the newline that terminates the header
        char *newline = memchr(buf->data + 4, '\n', buf->len - 4);
        if (newline) {
          int header_len = (newline - buf->data) + 1;

          // Extracting the number string between LEN: and \n
          int num_len = newline - (buf->data + 4);
          if (num_len <= 0 || num_len > 10) {
            send_response(fd, "ERR", 400, "Invalid length value");
            memmove(buf->data, newline + 1, buf->len - header_len);
            buf->len -= header_len;
            return -1;
          }

          char num_str[16];
          memcpy(num_str, buf->data + 4, num_len);
          num_str[num_len] = '\0';

          // Validating if it's a proper non-negative integer
          for (int i = 0; i < num_len; i++) {
            if (!isdigit((unsigned char)num_str[i])) {
              send_response(fd, "ERR", 400, "Invalid length value");
              memmove(buf->data, newline + 1, buf->len - header_len);
              buf->len -= header_len;
              return -1;
            }
          }

          long payload_len = strtol(num_str, NULL, 10);

          // Rejecting oversized payloads
          if (payload_len > MAX_PAYLOAD) {
            send_response(fd, "ERR", 413, "Payload too large");
            memmove(buf->data, newline + 1, buf->len - header_len);
            buf->len -= header_len;
            return -1;
          }

          // Rejecting zero length payloads
          if (payload_len == 0) {
            send_response(fd, "ERR", 400, "Empty payload");
            memmove(buf->data, newline + 1, buf->len - header_len);
            buf->len -= header_len;
            return -1;
          }

          // Verify that the complete payload is currently available in the
          // persistent read buffer
          int total_msg_len = header_len + (int)payload_len;
          if (buf->len >= total_msg_len) {
            // Extract payload
            memcpy(payload, buf->data + header_len, (int)payload_len);
            payload[(int)payload_len] = '\0';

            // Shift the remaining data forward to advance the buffer past the
            // consumed message
            memmove(buf->data, buf->data + total_msg_len,
                    buf->len - total_msg_len);
            buf->len -= total_msg_len;

            return (int)payload_len;
          }
        }
      }
    }

    

    /* Guard against buffer overflow */
    if (buf->len >= BUF_SIZE - 1) {
      send_response(fd, "ERR", 400, "Buffer overflow");
      buf->len = 0;
      return -2;
    }

    int bytes = recv(fd, buf->data + buf->len, BUF_SIZE - buf->len - 1, 0);
    if (bytes <= 0) {
      if (bytes == 0) {
        return 0; /* Client disconnected */
      }
      if (errno == EINTR) {
        continue; /* Interrupted by signal, retry */
      }
      return -2; /* Fatal recv error */
    }

    buf->len += bytes;
  }
}

/* ============================================================
 *  Section 3: Authentication & Security
 *
 *  Covers assignment requirements:
 *    A3 – Authentication + Session Tokens
 *    A4.11 – Login brute-force lockout
 *    A4.12 – Username validation
 * ============================================================ */

/*
 * mkdir_recursive — Create a directory and all parent directories.
 *
 * Similar to `mkdir -p`. Ignores EEXIST errors on intermediate dirs.
 * Returns 0 on success, -1 on failure.
 */
static int mkdir_recursive(const char *path, mode_t mode) {
  char tmp[512];
  char *p = NULL;
  size_t len;

  snprintf(tmp, sizeof(tmp), "%s", path);
  len = strlen(tmp);

  /* Remove trailing slash */
  if (len > 0 && tmp[len - 1] == '/') {
    tmp[len - 1] = '\0';
  }

  /* Create each directory component */
  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, mode) == -1 && errno != EEXIST) {
        return -1;
      }
      *p = '/';
    }
  }

  /* Create the final directory */
  if (mkdir(tmp, mode) == -1 && errno != EEXIST) {
    return -1;
  }

  return 0;
}

/*
 * validate_username — Check if a username meets security requirements.
 *
 * Rules (per assignment A4.12):
 *   - Length: 3 to 32 characters
 *   - Characters: alphanumeric and underscore only [a-zA-Z0-9_]
 *   - No path traversal sequences (.., /, \, null bytes)
 *
 * Returns: 1 if valid, 0 if invalid.
 */
static int validate_username(const char *username) {
  if (!username)
    return 0;

  int len = (int)strlen(username);

  /* Length check */
  if (len < 3 || len > 32)
    return 0;

  /* Character check */
  for (int i = 0; i < len; i++) {
    char c = username[i];
    if (!isalnum((unsigned char)c) && c != '_') {
      return 0;
    }
  }

  /* Path traversal check (defense in depth) */
  if (strstr(username, "..") != NULL)
    return 0;
  if (strchr(username, '/') != NULL)
    return 0;
  if (strchr(username, '\\') != NULL)
    return 0;

  return 1;
}

/*
 * hash_password — Hash a plaintext password using SHA-512 with a random salt.
 *
 * Uses crypt() with $6$ prefix for SHA-512 (per assignment A3.9: salted
 * hashing). Salt is generated from /dev/urandom.
 *
 * Parameters:
 *   password — plaintext password to hash
 *   hash_out — output buffer (must be >= 128 bytes)
 *   hash_out_size — size of output buffer
 *
 * Returns: hash_out on success, NULL on failure.
 */
static char *hash_password(const char *password, char *hash_out,
                           size_t hash_out_size) {
  unsigned char rand_bytes[16];

  // Read random bytes for salt
  FILE *f = fopen("/dev/urandom", "rb");
  if (!f)
    return NULL;

  if (fread(rand_bytes, 1, sizeof(rand_bytes), f) != sizeof(rand_bytes)) {
    fclose(f);
    return NULL;
  }
  fclose(f);

  // Build SHA-512 salt: $6$<32 hex chars>$
  char salt[48];
  strcpy(salt, "$6$");
  for (int i = 0; i < 16; i++) {
    sprintf(salt + 3 + i * 2, "%02x", rand_bytes[i]);
  }
  strcat(salt, "$");

  // Hash the password
  char *result = crypt(password, salt);
  if (!result || result[0] == '*') {
    return NULL; // crypt() will return "*" on error
  }

  // Copy to output buffer (crypt uses a static buffer)
  strncpy(hash_out, result, hash_out_size - 1);
  hash_out[hash_out_size - 1] = '\0';

  return hash_out;
}

/*
 * verify_password — Compare a plaintext password against a stored hash.
 *
 * crypt() automatically extracts the salt from the stored hash.
 *
 * Returns: 1 if password matches, 0 if not.
 */
static int verify_password(const char *password, const char *stored_hash) {
  char *computed = crypt(password, stored_hash);
  if (!computed || computed[0] == '*') {
    return 0;
  }
  return strcmp(computed, stored_hash) == 0;
}

/*
 * generate_token — Generate a cryptographically random session token.
 *
 * Produces a 64-character hex string (32 random bytes).
 * Reads from /dev/urandom for security.
 *
 * Returns: 0 on success, -1 on failure.
 */
static int generate_token(char *token_out) {
  unsigned char rand_bytes[TOKEN_LEN];

  FILE *f = fopen("/dev/urandom", "rb");
  if (!f)
    return -1;

  if (fread(rand_bytes, 1, TOKEN_LEN, f) != TOKEN_LEN) {
    fclose(f);
    return -1;
  }
  fclose(f);

  for (int i = 0; i < TOKEN_LEN; i++) {
    sprintf(token_out + (i * 2), "%02x", rand_bytes[i]);
  }
  token_out[TOKEN_LEN * 2] = '\0';

  return 0;
}

/*
 * check_lockout — Check if a user account is currently locked out.
 *
 * Reads the lockout file at DATA_BASE_PATH/<username>/lockout.
 * Format: "<fail_count>\n<last_fail_timestamp>\n"
 *
 * An account is locked when:
 *   fail_count >= MAX_LOGIN_ATTEMPTS AND
 *   current_time - last_fail_timestamp < LOCKOUT_DURATION
 *
 * Returns:
 *   0  — account is NOT locked (or lockout expired, or no lockout file)
 *   1  — account IS locked
 *  -1  — error
 */
static int check_lockout(const char *username) {
  char lockout_path[512];
  snprintf(lockout_path, sizeof(lockout_path), "%s/%s/lockout", DATA_BASE_PATH,
           username);

  FILE *f = fopen(lockout_path, "r");
  if (!f)
    return 0; // No lockout file = not locked

  int fail_count = 0;
  long last_fail_time = 0;

  if (fscanf(f, "%d\n%ld", &fail_count, &last_fail_time) != 2) {
    fclose(f);
    return 0; // Malformed file, treat as not locked
  }
  fclose(f);

  if (fail_count >= MAX_LOGIN_ATTEMPTS) {
    time_t now = time(NULL);
    if (now - (time_t)last_fail_time < LOCKOUT_DURATION) {
      return 1; // Account is locked
    }
    // Lockout expired — will be reset on next successful login
  }

  return 0;
}

/*
 * record_failed_login — Increment the failed login counter for a user.
 *
 * Updates the lockout file with the new fail count and current timestamp.
 * Uses file locking (flock) for safe concurrent access from forked children.
 */
static void record_failed_login(const char *username) {
  char lockout_path[512];
  snprintf(lockout_path, sizeof(lockout_path), "%s/%s/lockout", DATA_BASE_PATH,
           username);

  int fail_count = 0;

  /* Read existing fail count */
  FILE *f = fopen(lockout_path, "r");
  if (f) {
    long dummy;
    if (fscanf(f, "%d\n%ld", &fail_count, &dummy) != 2) {
      fail_count = 0;
    }
    fclose(f);
  }

  fail_count++;

  /* Write updated count with file locking */
  f = fopen(lockout_path, "w");
  if (f) {
    int fd = fileno(f);
    flock(fd, LOCK_EX);
    fprintf(f, "%d\n%ld\n", fail_count, (long)time(NULL));
    fflush(f);
    flock(fd, LOCK_UN);
    fclose(f);
  }
}

/*
 * reset_lockout — Clear failed login attempts for a user.
 *
 * Called on successful login to reset the lockout counter.
 */
static void reset_lockout(const char *username) {
  char lockout_path[512];
  snprintf(lockout_path, sizeof(lockout_path), "%s/%s/lockout", DATA_BASE_PATH,
           username);

  /* Delete the lockout file */
  unlink(lockout_path);
}

/* ---- Command Handlers ---- */

/*
 * handle_register — Process a REGISTER <username> <password> command.
 *
 * Flow:
 *   1. Parse and validate username/password from args
 *   2. Check if user already exists
 *   3. Create user directory under DATA_BASE_PATH
 *   4. Hash password with SHA-512 + random salt
 *   5. Write hashed password to credentials file
 *
 * Response codes:
 *   OK  201 — User registered successfully
 *   ERR 400 — Invalid arguments or username
 *   ERR 409 — User already exists
 *   ERR 500 — Internal server error
 */
static void handle_register(int client_fd, const char *args) {
  /* --- Parse username and password --- */
  if (!args || args[0] == '\0') {
    send_response(client_fd, "ERR", 400,
                  "Usage: REGISTER <username> <password>");
    return;
  }

  char username[64], password[256];
  const char *space = strchr(args, ' ');

  if (!space || space == args) {
    send_response(client_fd, "ERR", 400,
                  "Usage: REGISTER <username> <password>");
    return;
  }

  /* Extract username */
  int ulen = space - args;
  if (ulen >= (int)sizeof(username))
    ulen = (int)sizeof(username) - 1;
  memcpy(username, args, ulen);
  username[ulen] = '\0';

  /* Extract password (everything after the first space) */
  const char *pass_start = space + 1;
  if (*pass_start == '\0') {
    send_response(client_fd, "ERR", 400, "Password cannot be empty");
    return;
  }
  strncpy(password, pass_start, sizeof(password) - 1);
  password[sizeof(password) - 1] = '\0';

  /* --- Validate username --- */
  if (!validate_username(username)) {
    send_response(client_fd, "ERR", 400,
                  "Invalid username (3-32 chars, alphanumeric and _ only)");
    return;
  }

  /* --- Check if user already exists --- */
  char user_dir[512];
  snprintf(user_dir, sizeof(user_dir), "%s/%s", DATA_BASE_PATH, username);

  struct stat st;
  if (stat(user_dir, &st) == 0) {
    send_response(client_fd, "ERR", 409, "User already exists");
    return;
  }

  /* --- Create user directory --- */
  if (mkdir_recursive(user_dir, 0700) != 0) {
    send_response(client_fd, "ERR", 500, "Failed to create user directory");
    return;
  }

  /* --- Hash password with SHA-512 --- */
  char hashed[256];
  if (!hash_password(password, hashed, sizeof(hashed))) {
    send_response(client_fd, "ERR", 500, "Password hashing failed");
    return;
  }

  /* --- Write credentials file --- */
  char cred_path[1024];
  snprintf(cred_path, sizeof(cred_path), "%s/credentials", user_dir);

  FILE *f = fopen(cred_path, "w");
  if (!f) {
    send_response(client_fd, "ERR", 500, "Failed to write credentials");
    return;
  }

  /* Set restrictive permissions on credentials file */
  fchmod(fileno(f), 0600);
  fprintf(f, "%s\n", hashed);
  fclose(f);

  /* Scrub password from memory */
  memset(password, 0, sizeof(password));

  audit_log(NULL, "REGISTER %s -> OK 201", username);
  send_response(client_fd, "OK", 201, "User registered");
}

/*
 * handle_login — Process a LOGIN <username> <password> command.
 *
 * Flow:
 *   1. Parse and validate username/password from args
 *   2. Check if already logged in
 *   3. Check if user exists
 *   4. Check brute-force lockout (A4.11)
 *   5. Read stored hash, verify password
 *   6. On success: generate token, update session, reset lockout
 *   7. On failure: record failed attempt
 *
 * Response codes:
 *   OK  200 — Login successful, TOKEN:<hex> included
 *   ERR 400 — Invalid arguments or username, or already logged in
 *   ERR 401 — Invalid credentials
 *   ERR 404 — User not found
 *   ERR 423 — Account locked (brute-force protection)
 *   ERR 500 — Internal server error
 */
static void handle_login(int client_fd, const char *args,
                         client_session_t *session) {
  /* --- Parse username and password --- */
  if (!args || args[0] == '\0') {
    send_response(client_fd, "ERR", 400, "Usage: LOGIN <username> <password>");
    return;
  }

  char username[64], password[256];
  const char *space = strchr(args, ' ');

  if (!space || space == args) {
    send_response(client_fd, "ERR", 400, "Usage: LOGIN <username> <password>");
    return;
  }

  /* Extract username */
  int ulen = space - args;
  if (ulen >= (int)sizeof(username))
    ulen = (int)sizeof(username) - 1;
  memcpy(username, args, ulen);
  username[ulen] = '\0';

  /* Extract password */
  const char *pass_start = space + 1;
  if (*pass_start == '\0') {
    send_response(client_fd, "ERR", 400, "Password cannot be empty");
    return;
  }
  strncpy(password, pass_start, sizeof(password) - 1);
  password[sizeof(password) - 1] = '\0';

  /* --- Validate username --- */
  if (!validate_username(username)) {
    send_response(client_fd, "ERR", 400,
                  "Invalid username (3-32 chars, alphanumeric and _ only)");
    memset(password, 0, sizeof(password));
    return;
  }

  /* --- Check if already logged in --- */
  if (session->is_authenticated) {
    send_response(client_fd, "ERR", 400, "Already logged in");
    memset(password, 0, sizeof(password));
    return;
  }

  /* --- Check if user exists --- */
  char cred_path[1024];
  snprintf(cred_path, sizeof(cred_path), "%s/%s/credentials", DATA_BASE_PATH,
           username);

  struct stat st;
  if (stat(cred_path, &st) != 0) {
    send_response(client_fd, "ERR", 404, "User not found");
    memset(password, 0, sizeof(password));
    return;
  }

  /* --- Check brute-force lockout (A4.11) --- */
  int locked = check_lockout(username);
  if (locked == 1) {
    send_response(client_fd, "ERR", 423,
                  "Account locked (too many failed attempts)");
    memset(password, 0, sizeof(password));
    return;
  }

  /* --- Read stored hash --- */
  FILE *f = fopen(cred_path, "r");
  if (!f) {
    send_response(client_fd, "ERR", 500, "Failed to read credentials");
    memset(password, 0, sizeof(password));
    return;
  }

  char stored_hash[256];
  if (!fgets(stored_hash, sizeof(stored_hash), f)) {
    fclose(f);
    send_response(client_fd, "ERR", 500, "Failed to read credentials");
    memset(password, 0, sizeof(password));
    return;
  }
  fclose(f);

  /* Remove trailing newline from stored hash */
  size_t hash_len = strlen(stored_hash);
  if (hash_len > 0 && stored_hash[hash_len - 1] == '\n') {
    stored_hash[hash_len - 1] = '\0';
  }

  /* --- Verify password --- */
  if (!verify_password(password, stored_hash)) {
    /* Wrong password — record failure for lockout tracking */
    record_failed_login(username);
    audit_log(NULL, "LOGIN %s -> ERR 401 (wrong password)", username);
    send_response(client_fd, "ERR", 401, "Invalid credentials");
    memset(password, 0, sizeof(password));
    return;
  }

  /* --- Login successful --- */
  memset(password, 0, sizeof(password));

  /* Reset lockout counter */
  reset_lockout(username);

  /* Generate session token */
  if (generate_token(session->token) != 0) {
    send_response(client_fd, "ERR", 500, "Token generation failed");
    return;
  }

  /* Update session state */
  strncpy(session->username, username, sizeof(session->username) - 1);
  session->username[sizeof(session->username) - 1] = '\0';
  session->is_authenticated = 1;
  session->last_activity = time(NULL);

  /* Build response with token */
  char token_msg[128];
  snprintf(token_msg, sizeof(token_msg), "Login successful TOKEN:%s",
           session->token);

  audit_log(session, "LOGIN %s -> OK 200", username);
  send_response(client_fd, "OK", 200, token_msg);
}

/*
 * handle_logout — Process a LOGOUT command.
 *
 * Requires an active session and a valid token. Clears all session state.
 *
 * Response codes:
 *   OK  200 — Logged out successfully
 *   ERR 401 — Not authenticated or invalid token
 */
static void handle_logout(int client_fd, const char *args,
                          client_session_t *session) {
  if (!session->is_authenticated) {
    send_response(client_fd, "ERR", 401, "Not authenticated");
    return;
  }

  if (args == NULL || strlen(args) == 0) {
    send_response(client_fd, "ERR", 401, "Missing session token");
    audit_log(session, "LOGOUT -> ERR 401 Missing token");
    return;
  }

  if (strcmp(args, session->token) != 0) {
    send_response(client_fd, "ERR", 401, "Invalid session token");
    audit_log(session, "LOGOUT -> ERR 401 Invalid token");
    return;
  }

  audit_log(session, "LOGOUT %s -> OK 200", session->username);

  /* Clear session state */
  memset(session->username, 0, sizeof(session->username));
  memset(session->token, 0, sizeof(session->token));
  session->is_authenticated = 0;
  session->last_activity = 0;

  send_response(client_fd, "OK", 200, "Logged out");
}

/* ============================================================
 *  Section 4: Abuse Protection — check_rate_limit()
 *
 *  Covers assignment requirement A4.10: Rate limiting per client.
 * ============================================================ */

/*
 * check_rate_limit — Enforce per-client request rate limiting.
 *
 * Uses a sliding window algorithm: counts requests within the last
 * RATE_LIMIT_WINDOW seconds. If the count exceeds RATE_LIMIT_MAX,
 * the request is rejected.
 *
 * Parameters:
 *   rl  — per-client rate limiter state (stored in handle_client scope)
 *
 * Returns:
 *   0 — request allowed
 *   1 — rate limit exceeded (caller should reject the request)
 */
static int check_rate_limit(rate_limiter_t *rl) {
  time_t now = time(NULL);

  // Count requests within the sliding window
  int recent = 0;
  for (int i = 0; i < rl->count; i++) {
    int idx = (rl->head - 1 - i + RATE_LIMIT_MAX + 1) % (RATE_LIMIT_MAX + 1);
    if (now - rl->timestamps[idx] <= RATE_LIMIT_WINDOW) {
      recent++;
    } else {
      break; // Older entries are outside the window
    }
  }

  if (recent >= RATE_LIMIT_MAX) {
    return 1; // Rate limit exceeded
  }

  // Record this request
  rl->timestamps[rl->head] = now;
  rl->head = (rl->head + 1) % (RATE_LIMIT_MAX + 1);
  if (rl->count < RATE_LIMIT_MAX + 1) {
    rl->count++;
  }

  return 0;
}

/* ============================================================
 *  Section 5: Audit Logging — audit_log()
 *
 *  Covers assignment requirement A5: Persistent Audit Logging.
 *  Log file: server_IT24103733.log
 * ============================================================ */

/*
 * audit_log — Write a structured log entry to the audit log file.
 *
 * Each entry includes (per A5 requirements):
 *   - ISO timestamp (A5.14)
 *   - Child PID (A5.16)
 *   - Client IP:port (A5.15)
 *   - Username or "-" if not logged in (A5.17)
 *   - Command and result (A5.18)
 *
 * Format:
 *   [2026-04-12 04:30:00] [PID:12345] [192.168.1.10:54321] [user:alice] LOGIN
 * alice -> OK 200
 *
 * Uses flock() for safe concurrent writes from multiple forked children.
 * Also prints to stdout for real-time monitoring.
 */
static void audit_log(const client_session_t *session, const char *fmt, ...) {
  char msg[1024];
  va_list args;

  va_start(args, fmt);
  vsnprintf(msg, sizeof(msg), fmt, args);
  va_end(args);

  // Build timestamp
  time_t now = time(NULL);
  struct tm *tm_info = localtime(&now);
  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

  // Determine client info and username
  const char *ip = session ? session->client_ip : "-";
  int port = session ? session->client_port : 0;
  const char *user =
      (session && session->is_authenticated && session->username[0])
          ? session->username
          : "-";

  // Build full log line
  char logline[2048];
  int n;
  if (port > 0) {
    n = snprintf(logline, sizeof(logline),
                 "[%s] [PID:%d] [%s:%d] [user:%s] %s\n", timestamp, getpid(),
                 ip, port, user, msg);
  } else {
    n = snprintf(logline, sizeof(logline), "[%s] [PID:%d] %s\n", timestamp,
                 getpid(), msg);
  }

  if (n < 0 || n >= (int)sizeof(logline))
    return;

  // Print to stdout for real-time monitoring
  fputs(logline, stdout);
  fflush(stdout);

  // Append to log file with file locking
  FILE *f = fopen(LOG_FILE, "a");
  if (f) {
    int fd = fileno(f);
    flock(fd, LOCK_EX);
    fputs(logline, f);
    fflush(f);
    flock(fd, LOCK_UN);
    fclose(f);
  }
}

/* ============================================================
 *  Section 6: Socket & Process — setup_server(), sigchld_handler(),
 *             handle_client()
 * ============================================================ */

/*
 * setup_server — Create, bind, and listen on a TCP socket.
 *
 * Uses getaddrinfo() with AF_INET (IPv4 only).
 * Sets SO_REUSEADDR for quick server restarts.
 * Ensures the DATA_BASE_PATH directory exists.
 *
 * Returns: listening socket fd on success, exits on failure.
 */
static int setup_server(void) {
  struct addrinfo hints, *res, *p;
  int sockfd;
  int yes = 1;

  /* Ensure data storage directory exists */
  if (mkdir_recursive(DATA_BASE_PATH, 0755) != 0) {
    fprintf(stderr, "Warning: could not create data directory '%s': %s\n",
            DATA_BASE_PATH, strerror(errno));
    /* Continue anyway — individual operations will fail if needed */
  }

  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;       /* IPv4 only */
  hints.ai_socktype = SOCK_STREAM; /* TCP */
  hints.ai_flags = AI_PASSIVE;     /* Bind to all interfaces */

  int rv = getaddrinfo(NULL, PORT, &hints, &res);
  if (rv != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
    exit(EXIT_FAILURE);
  }

  /* Walk the result list, bind to the first address we can */
  for (p = res; p != NULL; p = p->ai_next) {
    sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sockfd == -1) {
      perror("socket");
      continue;
    }

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
      close(sockfd);
      continue;
    }

    if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
      perror("bind");
      close(sockfd);
      continue;
    }

    break; /* Successfully bound */
  }

  freeaddrinfo(res);

  if (p == NULL) {
    fprintf(stderr, "Failed to bind to port %s\n", PORT);
    exit(EXIT_FAILURE);
  }

  if (listen(sockfd, BACKLOG) == -1) {
    perror("listen");
    close(sockfd);
    exit(EXIT_FAILURE);
  }

  printf("Server listening on port %s (SID:%s)\n", PORT, SID);

  g_listen_fd = sockfd;
  return sockfd;
}

/*
 * sigchld_handler — Reap zombie child processes.
 *
 * Uses waitpid() with WNOHANG to reap all terminated children
 * without blocking the parent process.
 */
static void sigchld_handler(int sig) {
  (void)sig;
  int saved_errno = errno;
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;
  errno = saved_errno;
}

/*
 * shutdown_handler — Handle SIGTERM/SIGINT for clean server shutdown.
 *
 * Sets the global shutdown flag so the accept loop exits gracefully.
 * Logs the shutdown event.
 */
static void shutdown_handler(int sig) {
  (void)sig;
  g_shutdown = 1;
  /* Close listener to unblock accept() */
  if (g_listen_fd >= 0) {
    close(g_listen_fd);
    g_listen_fd = -1;
  }
}

/*
 * handle_client — Main loop for a connected client (runs in child process).
 *
 * Reads framed messages, parses the command word, dispatches to handlers.
 * Checks session token expiry before processing protected commands.
 *
 * Supported commands:
 *   PING     — health check (no auth required)
 *   REGISTER — create new user account (no auth required)
 *   LOGIN    — authenticate and get session token (no auth required)
 *   LOGOUT   — end session (auth required)
 *
 * Abuse protection integrated:
 *   - Rate limiting: rejects requests exceeding RATE_LIMIT_MAX per window
 *   - Consecutive error tracking: disconnects after MAX_CONSECUTIVE_ERRORS
 */
static void handle_client(int client_fd, client_session_t *session) {
  read_buffer_t buf;
  char payload[MAX_PAYLOAD + 1];
  rate_limiter_t rate_limiter;
  int consecutive_errors = 0;

  memset(&buf, 0, sizeof(buf));
  memset(&rate_limiter, 0, sizeof(rate_limiter));

  audit_log(session, "NEW CONNECTION from %s:%d", session->client_ip,
            session->client_port);

  while (1) {
    int msg_len = read_message(client_fd, &buf, payload);

    /* Client disconnected */
    if (msg_len == 0) {
      audit_log(session, "DISCONNECTED %s:%d", session->client_ip,
                session->client_port);
      break;
    }

    /* Fatal error — close connection */
    if (msg_len == -2) {
      audit_log(session, "FATAL ERROR for %s:%d, closing", session->client_ip,
                session->client_port);
      break;
    }

    /* Protocol error — track consecutive errors (A4.13 hardening) */
    if (msg_len == -1) {
      consecutive_errors++;
      if (consecutive_errors >= MAX_CONSECUTIVE_ERRORS) {
        audit_log(session, "TOO MANY ERRORS from %s:%d, disconnecting",
                  session->client_ip, session->client_port);
        send_response(client_fd, "ERR", 400,
                      "Too many invalid frames - disconnecting");
        break;
      }
      continue;
    }

    /* Valid message received — reset consecutive error counter */
    consecutive_errors = 0;

    /* ---------- Rate limiting (A4.10) ---------- */
    if (check_rate_limit(&rate_limiter)) {
      audit_log(session, "RATE LIMIT exceeded for %s:%d", session->client_ip,
                session->client_port);
      send_response(client_fd, "ERR", 429, "Rate limit exceeded");
      continue;
    }

    /* ---------- Check session token expiry ---------- */
    if (session->is_authenticated) {
      time_t now = time(NULL);
      if (now - session->last_activity > SESSION_TIMEOUT) {
        /* Session expired — clear it */
        audit_log(session, "SESSION EXPIRED for user '%s'", session->username);
        memset(session->username, 0, sizeof(session->username));
        memset(session->token, 0, sizeof(session->token));
        session->is_authenticated = 0;
        session->last_activity = 0;
        send_response(client_fd, "ERR", 401, "Session expired");
        continue;
      }
      /* Update last activity time */
      session->last_activity = now;
    }

    /* ---------- Parse command (first word of payload) ---------- */
    char command[64];
    char args[MAX_PAYLOAD];
    args[0] = '\0';

    char *space = strchr(payload, ' ');
    if (space) {
      int cmd_len = space - payload;
      if (cmd_len >= (int)sizeof(command)) {
        cmd_len = (int)sizeof(command) - 1;
      }
      memcpy(command, payload, cmd_len);
      command[cmd_len] = '\0';
      strncpy(args, space + 1, sizeof(args) - 1);
      args[sizeof(args) - 1] = '\0';
    } else {
      strncpy(command, payload, sizeof(command) - 1);
      command[sizeof(command) - 1] = '\0';
    }

    /* ---------- Command dispatch ---------- */

    if (strcmp(command, "PING") == 0) {
      send_response(client_fd, "OK", 200, "PONG");
      audit_log(session, "PING -> OK 200");
    } else if (strcmp(command, "REGISTER") == 0) {
      handle_register(client_fd, args);
    } else if (strcmp(command, "LOGIN") == 0) {
      handle_login(client_fd, args, session);
    } else if (strcmp(command, "LOGOUT") == 0) {
      handle_logout(client_fd, args, session);
    } else {
      send_response(client_fd, "ERR", 400, "Unknown command");
      audit_log(session, "%s -> ERR 400 Unknown command", command);
    }
  }
}

/* ============================================================
 *  Section 7: Main
 * ============================================================ */

int main(void) {
  // Create and bind the listening socket
  int listen_fd = setup_server();

  // Install signal handlers
  struct sigaction sa;

  // SIGCHLD: reap zombie children
  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction SIGCHLD");
    close(listen_fd);
    exit(EXIT_FAILURE);
  }

  // SIGTERM/SIGINT: clean shutdown
  sa.sa_handler = shutdown_handler;
  sa.sa_flags = 0; // Do NOT restart accept()
  if (sigaction(SIGTERM, &sa, NULL) == -1 ||
      sigaction(SIGINT, &sa, NULL) == -1) {
    perror("sigaction SIGTERM/SIGINT");
    close(listen_fd);
    exit(EXIT_FAILURE);
  }

  // Log server start
  audit_log(NULL, "SERVER STARTED on port %s (SID:%s)", PORT, SID);
  printf("Server ready. Waiting for connections...\n");

  // Forking accept loop
  while (!g_shutdown) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client_fd =
        accept(listen_fd, (struct sockaddr *)&client_addr, &addr_len);
    if (client_fd == -1) {
      if (errno == EINTR) {
        if (g_shutdown)
          break;
        continue;
      }
      if (g_shutdown)
        break;
      perror("accept");
      continue;
    }

    // Fork a child process to handle this client
    pid_t pid = fork();

    if (pid < 0) {
      perror("fork");
      close(client_fd);
      continue;
    }

    if (pid == 0) {
      // Child process
      close(listen_fd); // Child doesn't need the listener

      // Initialize client session
      client_session_t session;
      memset(&session, 0, sizeof(session));
      inet_ntop(AF_INET, &client_addr.sin_addr, session.client_ip,
                sizeof(session.client_ip));
      session.client_port = ntohs(client_addr.sin_port);
      session.is_authenticated = 0;

      // Handle all communication with this client
      handle_client(client_fd, &session);

      close(client_fd);
      exit(EXIT_SUCCESS);
    }

    // Parent process
    close(client_fd); // Parent doesn't need the client socket
  }

  // Clean shutdown
  audit_log(NULL, "SERVER SHUTTING DOWN");

  // Reap any remaining children
  while (waitpid(-1, NULL, WNOHANG) > 0)
    ;

  if (g_listen_fd >= 0) {
    close(g_listen_fd);
  }

  audit_log(NULL, "SERVER STOPPED");
  return 0;
}
