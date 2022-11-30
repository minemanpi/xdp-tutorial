// Server side implementation of UDP client-server model
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <pthread.h>

#define PORT 11211
#define MAXLINE 1024
#define NUM_THREADS 2

void *thread_fn(void *arg) {
    int sockfd;
    // Creating socket file descriptor
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(optval));
    if (sockfd < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Filling server information
    struct sockaddr_in servaddr = {.sin_family = AF_INET,
                                   .sin_addr.s_addr = INADDR_ANY,
                                   .sin_port = htons(PORT)};

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) <
        0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    char incoming_msg_buf[MAXLINE];
    char server_resp[] =
        "header00VALUE 0123456789012345 0 32\n"
        "01234567890123450123456789012345\n"
        "END";
    struct sockaddr_in cliaddr;
    socklen_t len;
    len = sizeof(cliaddr);

    printf("Starting server...\n");
    for (;;) {
        int nbytes =
            recvfrom(sockfd, (char *)incoming_msg_buf, sizeof(incoming_msg_buf),
                     0, (struct sockaddr *)&cliaddr, &len);
        if (nbytes < 0) {
            perror("Server: Error during recvfrom");
        };
        // printf("Number of bytes received: %d\n", nbytes);
        // printf("Printing client request as a buffer: %.*s\n", nbytes,
        // incoming_msg_buf); incoming_msg_buf[nbytes] = '\0'; printf("Client :
        // %s\n", incoming_msg_buf);
        memcpy(server_resp, incoming_msg_buf, 8);
        sendto(sockfd, (const char *)server_resp, sizeof(server_resp),
               MSG_CONFIRM, (const struct sockaddr *)&cliaddr, len);
    }
}

// Driver code
int main(int argc, char *argv[]) {
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_t threadId;
        int ret = pthread_create(&threadId, NULL, &thread_fn, NULL);
        if (ret) {
            perror("Error creating thread");
        }
    }
    sleep(99999999);
}
