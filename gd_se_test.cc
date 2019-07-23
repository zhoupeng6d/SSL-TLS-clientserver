/*
 * @Author: Dash Zhou
 * @Date: 2019-07-09 16:10:52
 * @Last Modified by: Dash Zhou
 * @Last Modified time: 2019-07-10 17:59:22
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <getopt.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <string>
#include <iostream>
#include <thread>
#include <memory>

#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/engine.h>
#include <openssl/e_os2.h>
#include <SeCrypt.h>
#include <halSciSPI.h>


#define USE_SE 1

#define OFF	0
#define ON	1
#define  VERIFY_PEER ON

#define USE_AF_UNIX 0
#define MAX 80
#define IP  "127.0.0.1"
#define PORT 10001
#define SA struct sockaddr




#if USE_SE
    #define SE_ENOVATE_ROOT_CA_CID   0x01
    #define SE_ENOVATE_SECOND_CA_CID 0x02
    #define SE_TBOX_CERT_CID         0x03
    #define SE_TBOX_PRIV_KEY_KID     0x03

    #define SE_ENOVATE_ROOT_CA_CERT   "/usrdata/test/root_ca.crt"
    #define SE_ENOVATE_SECOND_CA_CERT "/usrdata/test/second_ca.crt"

    #define SSL_CLIENT_RSA_CERT	    "/usrdata/test/client.crt"
    #define SSL_CLIENT_RSA_CA_CERT	"/usrdata/test/ca.crt"

    #define SSL_SERVER_RSA_CA_CERT	"/usrdata/test/certs/ca.crt"
    #define SSL_SERVER_RSA_CERT	    "/usrdata/test/certs/server.crt"
    #define SSL_SERVER_RSA_KEY	    "/usrdata/test/certs/server.key"
#else
    #define SSL_CLIENT_RSA_CERT	"./certs/client.crt"
    #define SSL_CLIENT_RSA_KEY	"./certs/client.key"
    #define SSL_CLIENT_RSA_CA_CERT	"./certs/ca.crt"
#endif
#define SSL_SERVER_ADDR		"/tmp/ssl_server"


#if 0
void libSciSPIFree(uint16_t fd)
{
    if(fd>0)
    {
        //close spi
        close(fd);
	}
}
#endif

static void pabort(const char *s)
{
	perror(s);
	abort();
}


static void hex_dump(unsigned char *buf, int len)
{
    int i;

    for (i = 0; i < len; i++)
    {
        if (i && (i % 16 == 0))
        {
            printf("\n");
        }

        printf("%02X ", buf[i]);
        //printf("%c", buf[i]);
    }
    printf("\n");
}

int libSciSPIInit(void)
{
#if 0
	int fd =-1;
    const char *device = "/dev/spidev5.0";

    const uint8_t bits = 8;
    const uint32_t speed = 5000000;  //960000;4000000
    static uint32_t mode;

//	//insmod spi device module into kernel
//	if(0 != spi_try_dev_mount(device)){
//		printf("try get spidev error\n");
//		return -1;
//	}

    /* reset se */
    system("echo 0 > /sys/class/gpio/gpio1018/value");
    system("sleep 0.2");
    system("echo 1 > /sys/class/gpio/gpio1018/value");
    system("sleep 1");

	fd = open(device, O_RDWR);
	if (fd < 0)
		pabort("can't open device");

	/*
	 * spi mode
	 */
	int ret = ioctl(fd, SPI_IOC_WR_MODE, &mode);
	if (ret == -1)
		pabort("can't set spi mode");

	ret = ioctl(fd, SPI_IOC_RD_MODE, &mode);
	if (ret == -1)
		pabort("can't get spi mode");

	/*
	 * bits per word
	 */
	ret = ioctl(fd, SPI_IOC_WR_BITS_PER_WORD, &bits);
	if (ret == -1)
		pabort("can't set bits per word");

	ret = ioctl(fd, SPI_IOC_RD_BITS_PER_WORD, &bits);
	if (ret == -1)
		pabort("can't get bits per word");

	/*
	 * max speed hz
	 */
	ret = ioctl(fd, SPI_IOC_WR_MAX_SPEED_HZ, &speed);
	if (ret == -1)
		pabort("can't set max speed hz");

	ret = ioctl(fd, SPI_IOC_RD_MAX_SPEED_HZ, &speed);
	if (ret == -1)
		pabort("can't get max speed hz");

	printf("/************************************************************/\n");
	printf("spi init succeed!\n");
	printf("spi mode: 0x%x\n", mode);
	printf("bits per word: %d\n", bits);
	printf("max speed: %d Hz (%d KHz)\n", speed, speed/1000);
	printf("/************************************************************/\n");

	return (uint16_t)fd;
#else
	uint16_t len;
    unsigned char  buf [4096];

	static unsigned char select_ssla[] = // select ssl applet
	{
		0x00,0xA4,0x04,0x00,0x0E,0xA0,0x00,0x00,0x00,0x41,0x6c,0x69,0x59,0x75,0x6e,0x2e,0x49,0x44,0x32
	};

    if (libSciSPIInit(3) < 0)
    {
        printf("libSciSPIInit failed\n");
        return -1;
    }

	/* select SSL applet */
	memset(buf, 0, sizeof(buf));
	if (libSciSPIIccCommand(select_ssla, sizeof(select_ssla), buf, &len) < 0)
	{
		return -1;
	}
	printf("===select SSL applet response:\n");
	hex_dump(buf, len);

	return 0;
#endif
}

//get public key from RSA Certificate file
//return 0 is OK
int getRSA_PK_fromCertFile(int cid, EVP_PKEY **pkey) {
         //2. read x509 cert file from arm development board to memory.
         FILE *fp = fopen(SSL_CLIENT_RSA_CERT, "r");
         X509 *cert = PEM_read_X509(fp, NULL, NULL, NULL);

         //3. get pubkey
         *pkey = X509_get_pubkey(cert);

         fclose(fp);

         return 0;
}

int SSL_CTX_use_SE_RSAPrivateKey(SSL_CTX *ctx , unsigned char kid)
{
#if 0
	RSA *rsa = RSA_new();

    //temp rsa key,keysize=2048
    int kl = 256; //key size = 2048
    const unsigned char myD1[] =
    {
        0x6A,0x94,0xB2,0x5B,0x32,0xA3,0x12,0xE2,0x53,
        0x99,0x08,0x57,0xCC,0xAA,0x0C,0xA7,0x9B,0x03,0x0F,0xC7,0x62,0x49,0x48,0x9A,0x20,
        0xAD,0xC4,0x5A,0x68,0x7D,0x8D,0x7C,0xB2,0x04,0x4B,0x16,0x2A,0x81,0x36,0x4B,0x4C,
        0x96,0x6B,0x84,0x58,0xDE,0xB9,0x3B,0xC1,0x55,0x7E,0x92,0x3E,0x8A,0xCD,0x98,0x78,
        0xA0,0x19,0xC6,0xBB,0xCE,0x19,0x3A,0xBE,0xFB,0x70,0x1F,0xFB,0x19,0xF2,0x3F,0x55,
        0x41,0x58,0xED,0x43,0xA1,0x3F,0x02,0x9B,0xFC,0x8B,0x81,0xE0,0xEB,0xB4,0xA3,0x7E,
        0x21,0x29,0x8A,0x95,0x96,0x6C,0x63,0xEE,0xF3,0x1A,0xAE,0xAC,0xD1,0xEC,0x07,0xD2,
        0xB8,0xAF,0xA8,0x7B,0xB3,0xB6,0xAF,0x9A,0xD3,0x4D,0xF5,0x69,0x7B,0x0B,0x97,0xE2,
        0x47,0x33,0x02,0xE4,0xDC,0x51,0x3C,0x87,0xC8,0x07,0x72,0x1E,0x7E,0xEA,0x1D,0xE4,
        0x9E,0x68,0xC0,0x76,0x96,0xA6,0x72,0xEF,0xEC,0x5F,0x52,0x82,0xBE,0x77,0x71,0x9B,
        0x8C,0xF3,0x64,0xAE,0xB9,0xB9,0xB0,0x12,0xB9,0x2E,0x04,0xAE,0x26,0x74,0x44,0x69,
        0x22,0xC8,0x54,0xBD,0x6B,0x00,0x41,0x9C,0xB9,0x0A,0xC1,0xB1,0x2D,0x18,0x23,0xBE,
        0x91,0xD7,0x9D,0x91,0x95,0x1B,0xA5,0x5E,0x47,0x76,0xD4,0x03,0x9D,0xF2,0xAA,0x00,
        0x6D,0x6E,0x74,0x55,0xDB,0xDE,0x1F,0x75,0x37,0x22,0x0F,0xD0,0x64,0x90,0x36,0x9E,
        0x67,0xAC,0x8D,0xCD,0x8D,0x7C,0x78,0x28,0x52,0xAE,0x5F,0x65,0x6C,0xBF,0x48,0x6D,
        0xB3,0x62,0xA9,0xE2,0xB4,0x62,0x32,0xC1,0x04,0x5D,0xE0,0x64,0xF8,0x01,0x8A,0xB3,
        0x40,0x44,0x63,0x51,0xA8,0xF4,0x8D
    };

    const unsigned char myN1[] =
    {
        0x89,0x98,0x36,0x80,0xA5,0xE1,0x75,0x47,0x45,
        0xE0,0x1E,0x6C,0x31,0xBB,0x55,0x4C,0x48,0x0B,0xA1,0xFE,0x58,0xA5,0x80,0x24,0x08,
        0x54,0x8B,0x1F,0x74,0xDB,0x8E,0x24,0xD7,0x2C,0x4E,0x94,0x75,0x93,0x69,0x52,0x87,
        0xD5,0x28,0x11,0xBB,0x8B,0x32,0xBA,0x77,0x92,0x78,0x0C,0x73,0x8C,0x03,0xE8,0xDA,
        0xBD,0xC6,0x3B,0xBE,0xD9,0xC3,0xEC,0x7E,0xCE,0xEC,0x6F,0x95,0x8B,0x91,0x49,0x27,
        0x6E,0xF5,0x68,0x77,0x1F,0xE8,0xC8,0x32,0x24,0x4B,0xBC,0x4E,0x98,0x7E,0x4F,0x22,
        0xDD,0x4F,0x01,0x45,0x7D,0x8D,0x34,0xDC,0x5E,0x11,0x3E,0xD3,0x87,0xB8,0xEC,0xC3,
        0xED,0x5A,0x7D,0x5A,0x0F,0xA7,0xAA,0x85,0x75,0x5B,0x22,0x02,0xDB,0x47,0x43,0xDE,
        0xF9,0x8E,0x84,0x2C,0x1C,0x5F,0x1E,0x44,0xF4,0x4A,0x33,0x02,0x55,0x10,0x4F,0x03,
        0x13,0x83,0xC2,0x0E,0x20,0x23,0x4C,0x4D,0xD7,0x7D,0x34,0x58,0xA6,0xD0,0x89,0xD8,
        0xDC,0x6A,0xEB,0x7D,0x17,0x4E,0xC0,0x62,0x91,0xEE,0x79,0x31,0x98,0x9C,0xE7,0xCD,
        0x69,0x48,0xED,0xB5,0xDF,0xD8,0x93,0x8A,0x7E,0x3C,0xE4,0xAF,0x93,0xCD,0xBD,0xB5,
        0xA0,0xEF,0xC3,0xBA,0xCC,0x2E,0xE5,0x5A,0xC9,0xAE,0x57,0xEF,0xE3,0x3C,0xAC,0x69,
        0x3A,0x7B,0x43,0x56,0xBB,0xC2,0x00,0x25,0x4D,0xA8,0x59,0xCE,0xE6,0x26,0x75,0x70,
        0x18,0xAB,0xA4,0xDA,0x85,0xBF,0x13,0xAA,0x3E,0x47,0x21,0x02,0xEB,0x96,0x1C,0xBC,
        0x75,0x32,0xB3,0xD3,0x02,0xB2,0x1C,0xE2,0xA6,0xAC,0xF0,0x02,0xE5,0x9B,0xC2,0xBE,
        0x68,0xEE,0x21,0xB3,0xD8,0x56,0x9D
    };

    const unsigned char myE1[] = {0x03};

#ifdef GD_DEBUG
    printf("\nSSL_CTX_use_SE_RSAPrivateKey: set \"c->key = &(c->pkeys[0])\"\n");
#endif
    rsa->n = BN_bin2bn(myN1, kl, rsa->n);
    rsa->d = BN_bin2bn(myD1, kl, rsa->d);
    rsa->e = BN_bin2bn(myE1, 1, rsa->e);
    rsa->version  = kid;//add by zyj

    return SSL_CTX_use_RSAPrivateKey(ctx,rsa);
#else

    EVP_PKEY *pkey=NULL;
    RSA * rsa =NULL;

    if(getRSA_PK_fromCertFile(SE_TBOX_PRIV_KEY_KID, &pkey) !=0 ) {
        printf("get public key from ClientCertFile Error ---------------XXXXXXXXXXXXXXXXXXXXXXX \n");
        return -1;
    }

    rsa = EVP_PKEY_get1_RSA(pkey);
    rsa->version  = SE_TBOX_PRIV_KEY_KID;
#endif

	return SSL_CTX_use_RSAPrivateKey(ctx,rsa);
}

int ssl_server_thread()
{
	const SSL_METHOD *server_meth;
	SSL_CTX *ssl_server_ctx;
	int serversocketfd;
	int clientsocketfd;
	int handshakestatus;

	SSL_library_init();
	SSL_load_error_strings();
	server_meth = TLSv1_2_server_method();
	ssl_server_ctx = SSL_CTX_new(server_meth);

	if(!ssl_server_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_use_certificate_file(ssl_server_ctx, SSL_SERVER_RSA_CERT, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_use_PrivateKey_file(ssl_server_ctx, SSL_SERVER_RSA_KEY, SSL_FILETYPE_PEM) <= 0)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(SSL_CTX_check_private_key(ssl_server_ctx) != 1)
	{
		printf("Private and certificate is not matching\n");
		return -1;
	}

	if(VERIFY_PEER)
	{
		//See function man pages for instructions on generating CERT files
		if(!SSL_CTX_load_verify_locations(ssl_server_ctx, SSL_SERVER_RSA_CA_CERT, NULL))
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}

		SSL_CTX_set_verify(ssl_server_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

		SSL_CTX_set_verify_depth(ssl_server_ctx, 4);
	}

	#if USE_AF_UNIX
		struct sockaddr_un serveraddr;

		if((serversocketfd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
		{
			printf("Error on socket creation\n");
			return -1;
		}
		memset(&serveraddr, 0, sizeof(struct sockaddr_un));
		serveraddr.sun_family = AF_UNIX;
		serveraddr.sun_path[0] = 0;
		strncpy(&(serveraddr.sun_path[1]), SSL_SERVER_ADDR, strlen(SSL_SERVER_ADDR) + 1);
		if(bind(serversocketfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_un)))
		{
			printf("server bind error\n");
			return -1;
		}
	#else
		struct sockaddr_in serveraddr;

		if((serversocketfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		{
			printf("Error on socket creation\n");
			return -1;
		}

		memset(&serveraddr, 0, sizeof(struct sockaddr_in));

		// assign IP, PORT
    	serveraddr.sin_family = AF_INET;
    	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    	serveraddr.sin_port = htons(PORT);

		if ((bind(serversocketfd, (SA*)&serveraddr, sizeof(serveraddr))) != 0)
		{
			printf("server bind error\n");
			return -1;
		}
	#endif


	if(listen(serversocketfd, SOMAXCONN))
	{
		printf("Error on listen\n");
		return -1;
	}

	while(1)
	{
		SSL *serverssl;
		char buffer[1024] = {0};
		int bytesread = 0;
		int addedstrlen;
		int ret;

		clientsocketfd = accept(serversocketfd, NULL, 0);
		serverssl = SSL_new(ssl_server_ctx);
		if(!serverssl)
		{
			printf("Error SSL_new\n");
			return -1;
		}
		SSL_set_fd(serverssl, clientsocketfd);

		if((ret = SSL_accept(serverssl))!= 1)
		{
			printf("Handshake Error %d\n", SSL_get_error(serverssl, ret));
			return -1;
		}

		if(VERIFY_PEER)
		{
			X509 *ssl_client_cert = NULL;

			ssl_client_cert = SSL_get_peer_certificate(serverssl);

			if(ssl_client_cert)
			{
				long verifyresult;

				verifyresult = SSL_get_verify_result(serverssl);
				if(verifyresult == X509_V_OK)
					printf("Certificate Verify Success\n");
				else
					printf("Certificate Verify Failed\n");
				X509_free(ssl_client_cert);
			}
			else
				printf("There is no client certificate\n");
		}
		bytesread = SSL_read(serverssl, buffer, sizeof(buffer));
		addedstrlen = strlen("Appended by SSL server");
		printf("%s\n", buffer);
		strncpy(&buffer[bytesread], " Appended by SSL server", addedstrlen);
		SSL_write(serverssl, buffer, bytesread + addedstrlen);
		SSL_shutdown(serverssl);
		close(clientsocketfd);
		clientsocketfd = -1;
		SSL_free(serverssl);
		serverssl = NULL;
	}
	close(serversocketfd);
	SSL_CTX_free(ssl_server_ctx);
	return 0;
}

int openssl_engine_init()
{
    ENGINE *engine = NULL;
    ENGINE_load_builtin_engines();

    if(engine == NULL)
    {
        engine = ENGINE_by_id("dynamic");
        if (engine)
        {
            if (!ENGINE_ctrl_cmd_string(engine, "SO_PATH", "GDEngine", 0))
            {
                printf("set GDEngine PATH error!\n");
                goto engineLoad_failed;
            }
            else
                printf("set GDEngine PATH OK\n");

            if(!ENGINE_ctrl_cmd_string(engine, "ID", "GDHWEngine", 0))
            {
                printf("set GDEngine ID error!\n");
                goto engineLoad_failed;
            }
            else
                printf("set GDEngine ID OK\n");

            if(!ENGINE_ctrl_cmd_string(engine, "LOAD", NULL, 0))
            {
                printf("Load engine \"%s\" : error!\n", "GDHWEngine");
engineLoad_failed:
                ENGINE_free(engine);
                engine = NULL;
                return -1;
            }
            else
                printf("Load engine OK\n");

        }
        else
        {
            printf("Dynamic Engine Get failed!\n");
            return -1;
        }
    }

    int init_res = ENGINE_init(engine);
    printf("Engine name: %s \ninit result : %d \n",ENGINE_get_name(engine), init_res);

    init_res = ENGINE_set_default_ciphers(engine);
	printf("ENGINE_set_default_ciphers=gdEngine : result=%d \n",init_res);

	if(1 != ENGINE_set_default(engine, ENGINE_METHOD_ALL)){
		//printf("ENGINE_set_default_=gdEngine : result=%d \n",init_res);
		printf("ENGINE_set_default Error XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
	}

    return 0;
}

int ssl_client_thread()
{
	const SSL_METHOD *client_meth;
	SSL_CTX *ssl_client_ctx;
	int clientsocketfd;
	int handshakestatus;
	SSL *clientssl;
	char buffer[1024] = "Client Hello World";
	int ret;

	if (openssl_engine_init() != 0)
	{
		printf("openssl engine init failed!");
		return -1;
	}

	SSL_library_init();
	SSL_load_error_strings();
	client_meth = TLSv1_2_client_method();
	ssl_client_ctx = SSL_CTX_new(client_meth);

	if(!ssl_client_ctx)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if(VERIFY_PEER)
	{
    #if USE_SE
        if(readCert(SSL_CLIENT_RSA_CERT, CLIENT_TYPE, SE_TBOX_CERT_CID) == 0)
        {
            printf("read client Cert Error!!\n");
            exit(2);
        }
    #endif

        if(SSL_CTX_use_certificate_file(ssl_client_ctx, SSL_CLIENT_RSA_CERT, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}

    #if !USE_SE
		if(SSL_CTX_use_PrivateKey_file(ssl_client_ctx, SSL_CLIENT_RSA_KEY, SSL_FILETYPE_PEM) <= 0)
		{
			ERR_print_errors_fp(stderr);
			return -1;
		}

		if(SSL_CTX_check_private_key(ssl_client_ctx) != 1)  // not ok in SE mode
		{
			printf("Private and certificate is not matching\n");
			return -1;
		}
    #else
		if (SSL_CTX_use_SE_RSAPrivateKey(ssl_client_ctx, SE_TBOX_PRIV_KEY_KID) <= 0){
			ERR_print_errors_fp(stderr);
			return -1;
		}
    #endif
	}

#if USE_SE
    if( readCert(SE_ENOVATE_ROOT_CA_CERT, CA_TYPE, SE_ENOVATE_ROOT_CA_CID) ==0) //read root CA
    {
        printf("read CA Cert Error!!\n");
        exit(2);
    }

    if( readCert(SE_ENOVATE_SECOND_CA_CERT, CA_TYPE, SE_ENOVATE_SECOND_CA_CID) ==0) //read second CA
    {
        printf("read CA Cert Error!!\n");
        exit(2);
    }

    /* merge root and second certs to one */
    std::string merge_cmd = "cat ";
    merge_cmd += SE_ENOVATE_ROOT_CA_CERT;
    merge_cmd += " >> ";
    merge_cmd += SSL_CLIENT_RSA_CA_CERT;
    system(merge_cmd.c_str());

    merge_cmd = "cat ";
    merge_cmd += SE_ENOVATE_SECOND_CA_CERT;
    merge_cmd += " >> ";
    merge_cmd += SSL_CLIENT_RSA_CA_CERT;
    system(merge_cmd.c_str());
#endif

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

int main()
{
    int ret = -1;

    system("rm " SE_ENOVATE_ROOT_CA_CERT);
    system("rm " SE_ENOVATE_SECOND_CA_CERT);
    system("rm " SSL_CLIENT_RSA_CA_CERT);
    system("rm " SSL_CLIENT_RSA_CERT);

    /* init se-spi */
    ret = libSciSPIInit();
    if(ret != 0){
        printf("spi init failed!\n");
		return -1;
    }


    /* start ssl server thread */
    std::cout << "ssl server starting..." << std::endl;
    std::unique_ptr<std::thread> p_thd_ssl_server(new std::thread(ssl_server_thread));
    std::this_thread::sleep_for(std::chrono::seconds(3));

    openssl_engine_init();
    /* start ssl client thread */
    std::cout << "ssl client starting..." << std::endl;
    std::unique_ptr<std::thread> p_thd_ssl_client(new std::thread(ssl_client_thread));

    p_thd_ssl_server->join();
    p_thd_ssl_client->join();

	libSciSPIFree();

    return 0;
}
