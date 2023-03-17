#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>

#define MAXPOLLS 64
#define TIMEOUTS 50

// Store user information
struct user {
	char status[64];
	char name[64];
	char port[64];
	char host[64];
};

// Initialize a poll fd
void init_pfd(struct pollfd *pfd, int i, int fd) {
	pfd[i].fd = fd;
	pfd[i].events = POLLIN;
	pfd[i].revents = 0;
}

// Set up UDP
int init_presence_udp() {
	struct addrinfo hints;		// IPv4
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;	
	hints.ai_socktype = SOCK_DGRAM; // Datagram socket
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo *results;	// Array, allocated in gai()
	int rc = getaddrinfo(NULL, "8221", &hints, &results);
	if (rc != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		exit(-1);
	}
	// Error check for socket
	int fd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
	if (fd == -1)
		perror("socket");
	// Error check for sockopt's broadcast, reuseaddr, reuseport
	int enable = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) != 0) {
		perror("setsockopt for broadcast");
		exit(-1);
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		perror("setsockopt for reuseaddr");
		exit(-1);
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enable, sizeof(enable)) != 0) {
		perror("setsockopt for reuseport");
		exit(-1);
	}
	if (bind(fd, results->ai_addr, results->ai_addrlen) < 0) {
		perror("bind error");
		exit(-1);
	}
	freeaddrinfo(results);
	return fd;
}

// Write the presence message
void write_presence_udp(int fd, int status, char *username, char *port){
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	inet_pton(AF_INET, "10.10.13.255", &addr.sin_addr);
	addr.sin_port = htons(8221);
	char buff[64];
	
	if (status == 0) { // Online
		sprintf(buff, "%s online %s", username, port);
	} else { // Offline
		sprintf(buff, "%s offline %s", username, port);
	}
	sendto(fd, buff, 32, 0, (struct sockaddr*)&addr, sizeof(addr));
}

// Read and print other presence messages
void read_presence_udp(int fd, struct user *u, int *len) {
	struct user users;
	struct sockaddr_storage stg;
	char buff[128];
	socklen_t stg_len = sizeof(stg);
	//Error check if received
	int recvd = recvfrom(fd, buff, 128, 0, (struct sockaddr*)&stg, &stg_len);
	if (recvd == -1) {
		perror("recvfrom error");
		exit(-1);
	} else if (recvd == 0){
		return;
	}
	sscanf(buff, "%s %s %s", users.name, users.status, users.port);
	// Update the user struct to control printout's
	int found = -1;
	for (int i = 0; i < *len; i++) {
		if (!strcmp(users.name, u[i].name)) {
	 		if (!strcmp(users.status, u[i].status)) {
				found = 1;
				break;
			} else {
				strcpy(u[i].status, users.status);
				found = 0;
				break;
			}
		}
	}
	if (found == -1) { // Not found
		u[*len] = users;
		(*len) += 2;
		printf("%s is %s on port %s\n", users.name, users.status, users.port);
	} else if (found == 0) { // Found
		printf("%s is %s on port %s\n", users.name, users.status, users.port);
	}
 }

// Set up TCP 
int init_tcp(char *port) {
	struct addrinfo hints;	
	struct addrinfo *results;	
	hints.ai_family = AF_INET; // IPv4
	hints.ai_socktype = SOCK_STREAM; // Stream socket
	hints.ai_flags = AI_PASSIVE;
	hints.ai_protocol = IPPROTO_TCP;	
	int rc = getaddrinfo(NULL, port, &hints, &results);
	if (rc != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
		exit(-1);
	}
	// Error check socket
	int fd = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
	if (fd == -1) {
		perror("socket error");
	}
	// Error check sockopt reuseaddr
	int enable = 1;
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) != 0) {
		perror("setsockopt for reuseaddr");
		exit(-1);
	}
	// Error checl ioctl
	if (ioctl(fd, FIONBIO, (char *)&enable) !=  0) {
		perror("ioctl error");
		exit(-1);
	}
	// Error check socket binding
	if (bind(fd, results->ai_addr, results->ai_addrlen) != 0) {
		perror("bind error");
		exit(-1);
	}
	// Error checking socket listening
	if (listen(fd, MAXPOLLS) != 0) {
		perror("listen error");
		exit(-1);
	}
	freeaddrinfo(results);
	return fd;
}

char *host_lookup(char *host, struct user *u, int len) {
	// Loop through hosts
	for (int i = 0; i < len; i++) {
		if (!strncmp(host, u[i].host, strlen(host))){
			return u[i].name;
		}
	}
	perror("host error");
	exit(-1);
}

// Send messages
void write_tcp(int fd, struct user *u, int len){
	host_lookup(u->host, u, len);
	struct addrinfo hints;	
	struct addrinfo *results;	
	hints.ai_family = AF_INET;	
	hints.ai_socktype = SOCK_STREAM;
	getaddrinfo(u->host, u->port, &hints, &results);
	char *msg;

	int sock = socket(results->ai_family, results->ai_socktype, results->ai_protocol);
	if (sock == -1) {
		perror("socket error");
		exit(-1);
	} else if (sock == 0) {
		return;
	}
	int connection = connect(fd, results->ai_addr, results->ai_addrlen);
	if (connection == -1) {
		perror("connection error");
		exit(-1);
	}
	send(fd, msg, len, 0);
}

// Print incoming messages
void read_tcp(int fd, struct user *u, int len) {
	struct sockaddr_storage peer;
	socklen_t peer_len = sizeof(peer);
	char service[NI_MAXSERV];
	char buff[128];
	int recvd = recv(fd, buff, sizeof(buff), 0);
	// Error checking
	if (recvd == -1) {
		perror("recv error");
		exit(-1);
	} else if (recvd == 0){
		return;
	}
	if (getpeername(fd, (struct sockaddr*) &peer, &peer_len) != 0) {
		perror("getpeername error");
		exit(-1);
	}
	if (getnameinfo((struct sockaddr*) &peer, peer_len, u->host, sizeof(u->host), service, NI_MAXSERV, NI_NUMERICSERV) != 0) {
		perror("getnameinfo error");
		exit(-1);
	}
	// Get the vlab host
	host_lookup(u->host, u, len);
	printf("%s says %s\n", u->host, buff);
}

int main(int argc, char **argv) {
	if (argc != 3) {
		printf("usage: ./project05 username port\n");
		exit(-1);
	}
	bool eof = false;
	struct pollfd pfd[MAXPOLLS];
	struct user users;
	// Variables to keep track of polls
	int len = 0;
	int num_readable = 0;
	int num_polls = 0;
	int cnt = 0;
	init_pfd(pfd,0,0); // Init STDIN poll fd
	num_polls++; 
	init_pfd(pfd, 1, init_presence_udp()); // Init UDP poll fd
	write_presence_udp(pfd[1].fd, 0, argv[1], argv[2]); 
	num_polls++; 
	init_pfd(pfd, 2, init_tcp(argv[2])); // Init TCP poll fd
	num_polls++;
	// Loop until end of file
	while (!eof) {
		char *buff = malloc(64);
		num_readable = poll(pfd, num_polls, TIMEOUTS);
		if (num_readable == -1) {
			perror("poll failed");
			exit(-1);
		} else if (num_readable > 0) {
			for (int i = 0; i < num_polls; i++) {	
				if (pfd[i].revents & POLLIN) {
					switch(i) {
						case (0): // STDIN case
							int rv = read(num_readable, buff, 1);
							if (rv == 0) {
								eof = true;
								break;
							}
						case (1): // UDP case
							if (cnt > 20) {
								write_presence_udp(pfd[1].fd, 0, argv[1], argv[2]); 
								cnt = 0;
								cnt++;	
							}
							read_presence_udp(pfd[i].fd, &users, &len);
							break;
						case (2): // TCP case
							int chat_fd = accept(pfd[i].fd, NULL, NULL);
							if (chat_fd == -1) {
								perror("connection not accepted");
								exit(-1);
							}
							init_pfd(pfd, num_polls, chat_fd);
							num_polls++;
							break;
						default:
							read_tcp(pfd[i].fd, &users, len);
							break;
					}
				}	
			}
		} else {
			cnt++;
		}
	free(buff);
	}
	// Free file descriptors
	for (size_t i = 0; i < sizeof(pfd); i++) {
		close(pfd[i].fd);
	}
	return 0;
}
