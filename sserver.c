#include <stdio.h>
#include <errno.h>
#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <netdb.h>

#include "macro.h"
/*--------------------------------------------------------------------------------*/

int process_header_line_part(struct addrinfo *res, char *part,int part_id, int *line_id, int client_sock, int *read_error,int *i,int *cont_len, int sig);
int recv_len(int s, char *received_message, int len);
int send_bad_request(const int sock);
int recv_header(const int sock, char *msg_recvd, const int len);

int
main(const int argc, const char **argv)
{
    int i;
    int port = -1;

	/* Argument parsing */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-p") == 0 && (i+1) < argc) {
            port = atoi(argv[i+1]);
            i++;
        }
    }
    if (port <= 0 || port > 65535) {
        printf("usage: %s -p port\n", argv[0]);
        exit(-1);
    }

	struct addrinfo hints, *res;

	/* Zero out structure hints */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
    char pt_port[10]; // Buffer for port number
    snprintf(pt_port, sizeof(pt_port), "%d", port); // Convert port number to string

	/* Call getaddrinfo() to get a list of IP addresses and port numbers */
    if (getaddrinfo(NULL, pt_port, &hints, &res) != 0) {
        perror("getaddrinfo failed");
        exit(-1);
    }

	/* Create a new socket */
	int s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s < 0) {
        perror("Cannot create socket");
        exit(-1);
    }

	/* Bind the socket to the IP address and port */
	if (bind(s, res->ai_addr, res->ai_addrlen) < 0) {
        perror("Bind failed");
        exit(-1);
    }

	printf("waiting for the connection:\n");

	listen(s, 20);

	int client_sock;
	while ((client_sock = accept(s, NULL, NULL)) >= 0) {
		const int pid = fork();
		if (pid == -1) {
			perror("Cannot create child process");
  		    close(client_sock);
		}
		if (pid > 0) {
			// Parent process
			continue;
		}
		fprintf(stderr, "socket number: %d\nprocess number: %d\n", client_sock, getpid());
		char buf[MAX_HDR];
		int recvd = recv_header(client_sock, buf, MAX_HDR);	
		if (recvd < 0) {
			fprintf(stderr, "nothing received for socket %d\n", client_sock);
			if (pid == 0) exit(-1);
			continue;
		}

		/* Splitting header from content */
		char header_in[MAX_HDR];
		char *cont = strstr(buf, "\r\n\r\n");
		snprintf(header_in, MAX_HDR, "%.*s", (int)(cont - buf), buf);
		cont += 4;
		int header_in_len = 0;
		int cont_len = 0;
		int i = 0;
		int line_id = -1;
		int read_error = FALSE;

		/* Parsing each line of the header */
		for (char *token = strtok(header_in, "\r\n"); token != NULL; token = strtok(NULL, "\r\n"), ++i) {
			header_in_len += 2; 
			int last_space = FALSE;
			char *beg = token;
			int part_id = 0;
			for (char *c = token; *c != '\0'; ++c) {
				++header_in_len;
				if (isspace(*c) || (*c == ':' && part_id == 0)) {
					if (last_space) {
						continue;
					}
					char part[MAX_HDR];
					snprintf(part, MAX_HDR, "%.*s", (int) (c - beg), beg);
					int sig = 1;
					if(process_header_line_part(res, part, part_id, &line_id, client_sock, &read_error, &i, &cont_len, sig) == -1) {
						break;
					}
			
					++part_id;
					last_space = TRUE;
					continue;
				}
				if (last_space) {
					beg = c;
				}
				last_space = FALSE;
			}

			if (read_error) break;
			if (!last_space) {
				char part[MAX_HDR];
				snprintf(part, MAX_HDR, "%s", beg);
				int sig = 0;
				if(process_header_line_part(res, part, part_id, &line_id, client_sock, &read_error, &i, &cont_len, sig) == -1) {
					break;
				}
			}
		}

		if (i != 3 || cont_len == 0 || read_error) {
			/* In case of errors, send bad request response and close connection */
			send_bad_request(client_sock);
			close(client_sock);
			if (pid == 0) exit(-1);
			continue;
		}

		header_in_len += 2; 
		const int cont_recvd = recvd - header_in_len;

		/* Allocate space for and copy over the content */
		char *tmp = malloc(cont_len);
		memcpy(tmp, cont, cont_recvd);
		cont = tmp;
		if (header_in_len + cont_len > recvd) {
			/* More content needs to be received */
			if (recv_len(client_sock, cont + cont_recvd, cont_len - cont_recvd) != cont_len - cont_recvd) {
				send_bad_request(client_sock);
				close(client_sock);
				free(cont);
				if (pid == 0) exit(-1);
				continue;
			}
		} else if (cont_recvd != cont_len) {
			send_bad_request(client_sock);
			close(client_sock);
			free(cont);
			if (pid == 0) exit(-1);
			continue;
		}

		/* Sending response header */
		char header[MAX_HDR];
		if (snprintf(header, MAX_HDR, "SIMPLE/1.0 200 OK\r\nContent-length: %d\r\n\r\n", cont_len) < 0) {
			fprintf(stderr, "Header exceeded %d characters\n", MAX_HDR);
			close(client_sock);
			free(cont);
			if (pid == 0) exit(-1);
			continue;
		}

		/* Send the response header */
		int total_bytes_sent = 0;
		int bytes_sent = 0;
		int header_len = strlen(header);
		while (total_bytes_sent < header_len) {
			bytes_sent = send(client_sock, header + total_bytes_sent, header_len - total_bytes_sent, 0);
			if (bytes_sent <= 0) {
				/* If unable to send, log error and exit child process */
				fprintf(stderr, "failed to reply to %d\n", client_sock);
				close(client_sock);
				free(cont);
				if (pid == 0) exit(-1);
				continue;
			}
			total_bytes_sent += bytes_sent;
		}

		/* Send the content */
		total_bytes_sent = 0;
		bytes_sent = 0;
		while (total_bytes_sent < cont_len) {
			bytes_sent = send(client_sock, cont + total_bytes_sent, cont_len - total_bytes_sent, 0);
			if (bytes_sent <= 0) {
				/* If unable to send, log error and exit child process */
				fprintf(stderr, "failed to reply to %d\n", client_sock);
				close(client_sock);
				free(cont);
				if (pid == 0) exit(-1);
				continue;
			}
			total_bytes_sent += bytes_sent;
		}

		/* Clean up for this request */
		free(cont);
		close(client_sock);
		if (pid == 0) exit(0); // Exit child process successfully
	}
	return 0;
}
/* Function to receive a specific length of data */
int recv_len(int s, char *received_message, int len) {
    int total_bytes_received = 0;

    while (total_bytes_received < len) {
        int bytes_to_recv = len - total_bytes_received;
        int buf_len = (bytes_to_recv > (32 * MAX_HDR)) ? (32 * MAX_HDR) : bytes_to_recv;

        char *buf = (char *)malloc(buf_len * sizeof(char));
        if (buf == NULL) {
            perror("malloc");
            return -1;
        }

        /* Receive data into the buffer */
        int bytes_received = recv(s, buf, buf_len, 0);
        if (bytes_received < 0) {
            perror("recv");
            free(buf);
            return -1;
        } else if (bytes_received == 0) {
            break;
        }

        /* Copy the received data into the main buffer */
        memcpy(received_message + total_bytes_received, buf, bytes_received);
        total_bytes_received += bytes_received;

        free(buf);
    }

    /* Ensure that the received message ends with a NULL terminator */
    received_message[total_bytes_received] = '\0';

    return total_bytes_received;
}

/* Function to send a "Bad Request" response */
int send_bad_request(const int sock) {
    const char *bad_req_msg = "SIMPLE/1.0 400 Bad Request\r\n\r\n";
    return send(sock, bad_req_msg, strlen(bad_req_msg), 0);
}

/* Function to process each part of the header line */
int process_header_line_part(struct addrinfo *res, char *part, int part_id, int *line_id, int client_sock, int *read_error, int *i, int *cont_len, int sig) {
    /* First line of the header */
    if (*i == 0) {
        if ((part_id == 0 && strcmp(part, "POST") != 0) ||
            (part_id == 1 && strcmp(part, "message") != 0) ||
            (part_id == 2 && strcmp(part, "SIMPLE/1.0") != 0) ||
            (part_id > 2)) {
            send_bad_request(client_sock);
            *read_error = TRUE;
            return -1;
        }
    } else if (part_id == 0) {
        /* Header fields */
        if (strcasecmp(part, (sig ? "host" : "host:")) == 0) {
            *line_id = 0;
        } else if (strcasecmp(part, (sig ? "content-length" : "content-length:")) == 0) {
            *line_id = 1;
        } else {
            send_bad_request(client_sock);
            *read_error = TRUE;
            return -1;
        }
    } else if (*line_id == 1) {
        /* Content-Length field */
        if (part_id == 1) {
            *cont_len = atoi(part);
            if (*cont_len < 0) {
                send_bad_request(client_sock);
                *read_error = TRUE;
                return -1;
            }
        } else {
            send_bad_request(client_sock);
            *read_error = TRUE;
            return -1;
        }
    } else if (*line_id == 0) {
        /* Host field */
        if (part_id == 1) {
            char own_name[MAX_HDR - 42];
            if (getnameinfo(res->ai_addr, res->ai_addrlen, own_name, sizeof(own_name), NULL, 0, 0) < 0) {
                fprintf(stderr, "Could not get own name in process %d\n", getpid());
                *read_error = TRUE;
                return -1;
            }
            if (strcasecmp(part, own_name) != 0) {
                send_bad_request(client_sock);
                *read_error = TRUE;
                return -1;
            }
        } else {
            send_bad_request(client_sock);
            *read_error = TRUE;
            return -1;
        }
    }
    return 0;
}

/* Function to receive the header portion of the message */
int recv_header(const int sock, char *msg_recvd, const int len) {
    int all_bytes_recvd = 0;
    char buf[len];
    for (int bytes_recvd; all_bytes_recvd < len;) {
        bytes_recvd = recv(sock, buf, sizeof(buf), 0);
        if (bytes_recvd < 0) return -1;
        if (bytes_recvd == 0) {
            return all_bytes_recvd;
        }
        memcpy(msg_recvd + all_bytes_recvd, buf, bytes_recvd);
        all_bytes_recvd += bytes_recvd;
        if (strstr(msg_recvd, "\r\n\r\n") != NULL) {
            break;
        }
    }
    msg_recvd[all_bytes_recvd] = '\0'; // Ensure NULL termination
    return all_bytes_recvd;
}
