#include <stdio.h>
#include <sys/types.h>          /* See NOTES */
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>

#include "macro.h"
/*--------------------------------------------------------------------------------*/

int parse_header_line(const char* line, int line_num, int* cont_len);
int extract_headers(const char* recv_start, char* header_in, int recvd);
void handle_response_content(int s, char** cont, int cont_len, int header_in_len, int recvd, char* recv_start);
void parse_and_process_response(int s, char* recv_start, int recvd);
int recv_len(int s, char *received_message, int len);
void close_and_exit(int s);



int 
main(const int argc, const char** argv)
{
    const char *pserver = NULL;
    int port = -1;
    int i;

	/* argument processing */
	for (i = 1; i < argc; i++)  {
        if (strcmp(argv[i], "-p") == 0 && (i + 1) < argc) {
            port = atoi(argv[i+1]);
            i++;
        } else if (strcmp(argv[i], "-s") == 0 && (i + 1) < argc) {
            pserver = argv[i+1];
            i++;
        }
    }

	/* check arguments */
	if (port < 0 || pserver == NULL) {
        printf("usage: %s -p port -s server-ip\n", argv[0]);
        exit(-1);
    }
    if (port < 1024 || port > 65535) {
        printf("port number should be between 1024 ~ 65535.\n");
        exit(-1);
    }

	/* read the message from stdin */
    const int BUF_LEN = 1024;
    char BUF[BUF_LEN]; 
    int msg_mem_allocated = BUF_LEN;
    char *msg = malloc(msg_mem_allocated);
    if (msg == NULL) {
        fprintf(stderr, "Allocating memory error\n");
        exit(-1);
    }

    int msg_len = 0;
    int bytes_read;

    while ((bytes_read = fread(BUF, sizeof(char), BUF_LEN, stdin)) > 0) {
        if (msg_len + bytes_read > msg_mem_allocated) {
            while (msg_len + bytes_read > msg_mem_allocated) {
                msg_mem_allocated *= 2;
            }
            char *tmp = realloc(msg, msg_mem_allocated);
            if (tmp == NULL) {
                free(msg);
                fprintf(stderr, "Error when reallocating memory for msg\n");
                exit(EXIT_FAILURE);
            }
            msg = tmp;
        }

        // Copy new data into msg buffer
        memcpy(msg + msg_len, BUF, bytes_read);
        msg_len += bytes_read;
    }

    if (msg_len < msg_mem_allocated) {
        char *tmp = realloc(msg, msg_len);
        if (tmp != NULL) {
            msg = tmp;
        }
    }

	/* get serverinfo by specified server address */

    struct addrinfo hints, *serverinfo;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char pt_port[10];
    snprintf(pt_port, sizeof(pt_port), "%d", port);

    int status = getaddrinfo(pserver, pt_port, &hints, &serverinfo);
    if (status != 0) {
        fprintf(stderr, "Error occurred in getaddrinfo: %s\n", gai_strerror(status));
        exit(-1);
    }

    int s = socket(serverinfo->ai_family, serverinfo->ai_socktype, serverinfo->ai_protocol);
    if (s < 0) {
        fprintf(stderr, "Socket could not be created\n");
        close_and_exit(s);
    }

	/* connect the socket */

    if (connect(s, serverinfo->ai_addr, serverinfo->ai_addrlen) < 0) {
        fprintf(stderr, "Connection could not be made\n");
        close_and_exit(s);
    }

	char server_name[MAX_HDR - 42];
	if (getnameinfo(serverinfo->ai_addr, serverinfo->ai_addrlen, server_name, sizeof(server_name), NULL, 0,0) < 0) {
		fprintf(stderr, "Error ocurred when trying to get server name\n");
        close_and_exit(s);
    }

	char header_out[MAX_HDR];
    int header_length = snprintf(header_out, MAX_HDR, "POST message SIMPLE/1.0\r\n""Host: %s\r\n""Content-length: %i\r\n""\r\n", server_name, msg_len);
    
    if (header_length>=MAX_HDR) {
        fprintf(stderr, "Header exceeded %d characters\n", MAX_HDR);
	 	close_and_exit(s);
    }

    
    int total_bytes_sent = 0;
    int bytes_sent = 0;
    int header_len = strlen(header_out);
    while (total_bytes_sent < header_len) {
        bytes_sent = send(s, header_out + total_bytes_sent, header_len - total_bytes_sent, 0);
        if (bytes_sent == -1) {
            perror("send");
            fprintf(stderr, "Connection failed\n");
            close_and_exit(s);
        }
        if (bytes_sent == 0) {
            if(total_bytes_sent<0){
                fprintf(stderr, "Connection closed by peer\n");
                close_and_exit(s);
            }else{
                goto out1;
            }
        }
        total_bytes_sent += bytes_sent;
    }
    if(total_bytes_sent<0){
        perror("send");
        fprintf(stderr, "Connection failed\n");
        close_and_exit(s);
    }
    out1:
	
    /* send the message */
	total_bytes_sent = 0;
    bytes_sent = 0;
    while (total_bytes_sent < msg_len) {
        bytes_sent = send(s, msg + total_bytes_sent, msg_len - total_bytes_sent, 0);
        if (bytes_sent == -1) {
            perror("send");
            fprintf(stderr, "Data could not be sent\n");
            close_and_exit(s);
        }
        if (bytes_sent == 0) {
            if(total_bytes_sent<0){
                fprintf(stderr, "Connection closed by peer\n");
                close_and_exit(s);
            }else{
                goto out2;
            }
        }
        total_bytes_sent += bytes_sent;
    }
    if(total_bytes_sent<0){
        perror("send");
        fprintf(stderr, "Connection failed\n");
        close_and_exit(s);
    }

    out2:


	free(msg);

	/* receive response from server */
	char recv_start[MAX_HDR];
    int recvd = 0;
    char buffer[1024];

    while (recvd < MAX_HDR) {
        int received_length = recv(s, buffer, MAX_HDR - recvd, 0);
        if (received_length == -1) {
            perror("recv");
            fprintf(stderr, "Receive failed\n");
            close_and_exit(s);
        } else if (received_length == 0) {
            if (recvd < 0) {
                fprintf(stderr, "Receive failed\n");
                close_and_exit(s);
            }
            else{
                goto out3;
            }
        }

        memcpy(recv_start + recvd, buffer, received_length);
        recvd += received_length;

        /* check the end of header */
        if (strstr(recv_start, "\r\n\r\n") != NULL) {
            if (recvd != MAX_HDR) {
                recv_start[recvd] = '\0';
            }
            if (recvd < 0) {
                fprintf(stderr, "Receive failed\n");
                close_and_exit(s);
            }
            else{
                goto out3;
            }
        }
    }

    if (recvd != MAX_HDR) {
        recv_start[recvd] = '\0';
    }
    if (recvd < 0) {
        fprintf(stderr, "Receive failed\n");
        close_and_exit(s);
    }
    out3:

    parse_and_process_response(s, recv_start, recvd);

	close(s);
}

/* Parses and processes the response from the server */ 
void parse_and_process_response(int s, char* recv_start, int recvd) {
    char header_in[MAX_HDR];
    int header_in_len = extract_headers(recv_start, header_in, recvd);
    if (header_in_len == -1) {
        fprintf(stderr, "Error processing headers\n");
        close_and_exit(s);
    }

    int cont_len = 0;
    char* rest = header_in;
    char* token;
    int line_num = 0;
    while ((token = strtok_r(rest, "\r\n", &rest))) {
        if (parse_header_line(token, line_num++, &cont_len) == -1) {
            close_and_exit(s);
        }
    }

    if (line_num < 2 || cont_len == 0) {
        fprintf(stderr, "Incomplete or malformed headers\n");
        close_and_exit(s);
    }

    char* cont = NULL;
    handle_response_content(s, &cont, cont_len, header_in_len, recvd, recv_start);
    if (cont) {
        write(fileno(stdout), cont, cont_len);
    }

    free(cont);
}

/* Handles the content portion of the response based on header information and total received bytes */
void handle_response_content(int s, char** cont, int cont_len, int header_in_len, int recvd, char* recv_start) {
    int content_received = recvd - header_in_len;
    *cont = malloc(cont_len + 1); // +1 for null-termination
    if (*cont == NULL) {
        fprintf(stderr, "Failed to allocate memory for content\n");
        close_and_exit(s);
    }

    if (content_received > 0) {
        memcpy(*cont, recv_start + header_in_len, content_received);
    }

    if (content_received < cont_len) {
        if (recv_len(s, *cont + content_received, cont_len - content_received) != cont_len - content_received) {
            fprintf(stderr, "Couldn't receive all content bytes\n");
            free(*cont);
            close_and_exit(s);
        }
    }

    (*cont)[cont_len] = '\0';
}

/* Extracts headers from the received message and returns the length of headers */
int extract_headers(const char* recv_start, char* header_in, int recvd) {
    char *cont = strstr(recv_start, "\r\n\r\n");
    if (cont == NULL) {
        fprintf(stderr, "Headers not found or incomplete\n");
        return -1;
    }
    int header_len = cont - recv_start;
    if (header_len > MAX_HDR) {
        fprintf(stderr, "Header exceeds maximum length\n");
        return -1;
    }
    memcpy(header_in, recv_start, header_len);
    header_in[header_len] = '\0';
    return header_len + 4;
}

/* Parses a single header line and updates content length if necessary */
int parse_header_line(const char* line, int line_num, int* cont_len) {
    if (line_num == 0) {
        int status_code;
        char protocol[11], status_message[256];
        
        if (sscanf(line, "%10s %d %[^\r\n]", protocol, &status_code, status_message) < 3) {
            fprintf(stderr, "Invalid status line: %s\n", line);
            return -1;
        }

        if (strcmp(protocol, "SIMPLE/1.0") != 0) {
            fprintf(stderr, "Invalid protocol: expected SIMPLE/1.0, found %s\n", protocol);
            return -1;
        }

    } else {
        char key[256], value[256];

        if (sscanf(line, "%255[^:]: %255[^\r\n]", key, value) < 2) {
            fprintf(stderr, "Invalid header line: %s\n", line);
            return -1;
        }

        if (strcasecmp(key, "Content-Length") == 0) {
            *cont_len = atoi(value);
            if (*cont_len < 0) {
                fprintf(stderr, "Invalid Content-Length: %s\n", value);
                return -1;
            }
        }
    }

    return 0;
}


void close_and_exit(int s) {
    close(s);
    exit(-1);
}

/* Receives the specified length of data from the socket */
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

        int bytes_received = recv(s, buf, buf_len, 0);
        if (bytes_received == -1) {
            perror("recv");
            free(buf);
            return -1;
        } else if (bytes_received == 0) {
            break;
        }

        memcpy(received_message + total_bytes_received, buf, bytes_received);
        total_bytes_received += bytes_received;

        free(buf);
    }

    received_message[total_bytes_received] = '\0';

    return total_bytes_received;
}
