#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PORT 9131

int extended = 0;

void error(char *msg)
{
	perror(msg);
	exit(1);
}

int main(int argc, char *argv[])
{
	int sockfd, newsockfd, portno, clilen;
	char line[4096];
	struct sockaddr_in serv_addr, cli_addr;
	int n;
	int yes = 1;
	int i;
	char *msg;
	char *addr;

	if (argc > 1) {
		if (strcmp(argv[1], "check") == 0) {
			printf("works\n");
			return 0;
		} else if (strcmp(argv[1], "ext") == 0) {
			extended = 1;
		}
	}

	setvbuf(stdout, NULL, _IONBF, 0);

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0)
		error("ERROR opening socket");

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1)
		error("ERROR on setsockopt");

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	if (extended) {
		serv_addr.sin_addr.s_addr = INADDR_ANY;
		serv_addr.sin_port = htons(PORT + 1);
	} else {
		serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
		serv_addr.sin_port = htons(PORT);
	}
	if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) 
		error("ERROR on binding");

	listen(sockfd, 100000);

	while (1) {
		clilen = sizeof(cli_addr);
		newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
		if (newsockfd < 0)
			error("ERROR on accept");

		n = read(newsockfd, line, sizeof line);
		if (n < 0)
			continue;

		for (i = 0; i < n; i++) {
			if (line[i] == '/')
				break;
		}
		msg = line + i + 1;

		for (; i < n; i++) {
			if (line[i] == '\n')
				break;
		}
		if (i < 9)
			continue;
		else
			line[i-9] = '\0';

		if (extended) {
			addr = inet_ntoa(cli_addr.sin_addr);
			printf("%s,", addr);
		}

		printf("%s\n", msg);

		n = write(newsockfd,
			"HTTP/1.0 200 OK\n"
			"Content-Type: text/plain\n"
			"Connection: close\n"
			"Content-Length: 2\n"
			"\n"
			"OK\n",
			16 + 25 + 18 + 18 + 1 + 3
		);
		if (n < 0)
			error("ERROR writing to socket");

		close(newsockfd);
	}

	return 0; 
}
