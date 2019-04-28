#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <string.h>

#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SSL_CLIENT_RSA_CERT	"./certs/client.crt"
#define SSL_CLIENT_RSA_KEY	"./certs/client.key"
#define SSL_CLIENT_RSA_CA_CERT	"./certs/ca.crt"

#define SSL_SERVER_ADDR		"/tmp/ssl_server"

#define OFF	0
#define ON	1

#define USE_AF_UNIX 0
#define MAX 80
#define IP  "127.0.0.1"
#define PORT 10001
#define SA struct sockaddr

int main(void)
{
	int verify_peer = ON;
	SSL_METHOD *client_meth;
	SSL_CTX *ssl_client_ctx;
	int clientsocketfd;
	int handshakestatus;
	SSL *clientssl;
	char buffer[1024] = "Client Hello World";
	int ret;

	SSL_library_init();
	SSL_load_error_strings();
	client_meth = TLSv1_2_client_method();
	ssl_client_ctx = SSL_CTX_new(client_meth);

	if(!ssl_client_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(verify_peer)
	{
		if(SSL_CTX_use_certificate_file(ssl_client_ctx, SSL_CLIENT_RSA_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}


		if(SSL_CTX_use_PrivateKey_file(ssl_client_ctx, SSL_CLIENT_RSA_KEY, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}

		if(SSL_CTX_check_private_key(ssl_client_ctx) != 1)
		{
			printf("Private and certificate is not matching\n");
			return -1;
		}
	}

	//See function man pages for instructions on generating CERT files
	if(!SSL_CTX_load_verify_locations(ssl_client_ctx, SSL_CLIENT_RSA_CA_CERT, NULL))
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	SSL_CTX_set_verify(ssl_client_ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_verify_depth(ssl_client_ctx, 4);

	#if USE_AF_UNIX
		struct sockaddr_un serveraddr;
		if((clientsocketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			printf("Error on socket creation\n");
			return -1;
		}
		memset(&serveraddr, 0, sizeof(struct sockaddr_un));
		serveraddr.sun_family = AF_UNIX;
		serveraddr.sun_path[0] = 0;
		strncpy(&(serveraddr.sun_path[1]), SSL_SERVER_ADDR, strlen(SSL_SERVER_ADDR) + 1);
		connect(clientsocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un));
	#else
		struct sockaddr_in serveraddr;
		// socket create and varification
		clientsocketfd = socket(AF_INET, SOCK_STREAM, 0);
		if (clientsocketfd == -1) {
			printf("socket creation failed...\n");
			exit(0);
		}
		else
			printf("Socket successfully created..\n");
		bzero(&serveraddr, sizeof(serveraddr));

		// assign IP, PORT
		serveraddr.sin_family = AF_INET;
		serveraddr.sin_addr.s_addr = inet_addr(IP);
		serveraddr.sin_port = htons(PORT);

		// connect the client socket to server socket
		if (connect(clientsocketfd, (SA*)&serveraddr, sizeof(serveraddr)) != 0) {
			printf("connection with the server failed...\n");
			exit(0);
		}
		else
			printf("connected to the server..\n");
	#endif


	clientssl = SSL_new(ssl_client_ctx);
	if(!clientssl)
	{
		printf("Error SSL_new\n");
		return -1;
	}
	SSL_set_fd(clientssl, clientsocketfd);

	if((ret = SSL_connect(clientssl)) != 1)
	{
		printf("Handshake Error %d\n", SSL_get_error(clientssl, ret));
		return -1;
	}

	X509 *ssl_client_cert = NULL;

	ssl_client_cert = SSL_get_peer_certificate(clientssl);

	if(ssl_client_cert)
	{
		long verifyresult;

		verifyresult = SSL_get_verify_result(clientssl);
		if(verifyresult == X509_V_OK)
			printf("Certificate Verify Success\n");
		else
			printf("Certificate Verify Failed\n");
		X509_free(ssl_client_cert);
	}
	else
		printf("There is no client certificate\n");

	SSL_write(clientssl, buffer, strlen(buffer));
	memset(buffer, 0, sizeof(buffer));
	SSL_read(clientssl, buffer, sizeof(buffer));
	printf("SSL server send %s\n", buffer);
	SSL_shutdown(clientssl);
	close(clientsocketfd);
	SSL_free(clientssl);
	SSL_CTX_free(ssl_client_ctx);
	return 0;
}
