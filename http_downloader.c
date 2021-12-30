#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <pthread.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT "443"
#define URL_LENGTH 200

void init_openssl(){
    SSL_library_init(); 
    SSL_load_error_strings();	
    OpenSSL_add_ssl_algorithms();
}

struct address_information{
	struct addrinfo server_addr_info;
	char server_ip[INET6_ADDRSTRLEN];
	char server_url[URL_LENGTH];
	char output_file_name[200];
	char file_path[URL_LENGTH];
	char output_extension[20];
	int range_start;
	int range_end;
	int part;
};

void init_addr_info(struct address_information *serv1, char *url)
{
	struct addrinfo server, *server1;
    char delim[] = "//";
	// copied to a new string as strtok gives segfault error on constant string (pointer)
	char s_url[URL_LENGTH], dupl_url[URL_LENGTH], *p_url;
	strcpy(s_url, url);
	strcpy(dupl_url, url);
	char *ptr = strtok(dupl_url, delim);
	int i =0;
	while(i<1)
	{	
		ptr = strtok(NULL, delim);
		i +=1;
	}

	char *result;
	result = strstr(s_url, ptr);
	int position = result - s_url + strlen(ptr);
	int substringLength = strlen(s_url) - position ;
	p_url = malloc(substringLength+1);
	int k, j;
	for(k=position,j=0;k<=strlen(s_url);k++,j++){
		p_url[j]=s_url[k];
	}
	memset(&server, 0, sizeof(server));
	server.ai_family = AF_INET;
    server.ai_socktype = SOCK_STREAM;
    
	int s = getaddrinfo(ptr, PORT, &server, &server1);
	
    if (s != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
        exit(-1);
    }
	serv1->server_addr_info = *server1;
	strcpy(serv1->file_path, p_url);
    for (struct addrinfo *addr = server1; addr != NULL; addr = addr->ai_next) {
        void *numericAddress; // Pointer to binary address
        char addrBuffer[INET6_ADDRSTRLEN];
        numericAddress = &((struct sockaddr_in *) addr->ai_addr)->sin_addr;
        if (inet_ntop(addr->ai_addr->sa_family, numericAddress, addrBuffer,
                        sizeof(addrBuffer)) == NULL)
             printf("%s", "invalid"); // Unable to convert
        else {
			strcpy(serv1->server_ip, addrBuffer);
			break;
        }
  	}
}

// function to get the file size from HTTP header
int get_file_size(struct address_information *serv1){
	struct addrinfo *server1 = &(serv1->server_addr_info);
	char *ip = serv1->server_ip;
	char *file_path = serv1->file_path;
	SSL_CTX *ctx;
    SSL *ssl;
	int file_size=0;
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0){
		printf("%s", "Socket Connection Failed");
		exit(1);
	}
	server1->ai_family = AF_INET;
	connect(sock, server1->ai_addr, server1->ai_addrlen);

	// initialize ssl context and add server SNI.
	const SSL_METHOD *method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
	ssl = SSL_new(ctx);
	SSL_set_tlsext_host_name(ssl, serv1->server_ip);
	SSL_set_fd(ssl, sock);

	if(SSL_connect(ssl)<0){
        perror("Error on SSL_connect");
        ERR_print_errors_fp(stderr);
        close(sock);
        exit(EXIT_FAILURE);
    }
	else{
		char http_query[200];
		sprintf(http_query, "HEAD %s HTTP/1.1\r\nHost: %s\r\n\r\n", file_path, ip);
		int numbytes;  
		char buf[2000], *token, *match;
		SSL_write(ssl, http_query, sizeof(http_query)+1);
		SSL_read(ssl, buf, sizeof(buf)+1);
		match = strstr(buf, "Content-Length");
		match = strtok(match,"\r\n");
		token = strtok(match," :");
		token = strtok(NULL, " ");
		file_size = atoi(token);
	}
	return file_size;
}

// open client side tls session
void *create_tls_session(void *serv_info){
	static int counter = 0;
	struct address_information *serv1 = serv_info;
	struct addrinfo *server1 = &(serv1->server_addr_info);
	char *ip = serv1->server_ip;
	char *output = serv1->output_file_name;
	char *file_path = serv1->file_path;
	int range_start = serv1->range_start;
	int range_end = serv1->range_end;
	int part = serv1->part;
	SSL_CTX *ctx;
    SSL *ssl;

	// initialize a tcp socket descriptor
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0)
	{
		printf("%s", "Socket Connection Failed");
		exit(1);
	}
	server1->ai_family = AF_INET;
	if (connect(sock, server1->ai_addr, server1->ai_addrlen) == 0)
	{
		printf("Server got connected\n");
	}
	else
	{
		printf("Connection Failed\n");
        exit(-1);
	}

	// initialize ssl context and add server SNI.
	const SSL_METHOD *method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
	if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
	ssl = SSL_new(ctx);
    if (SSL_set_tlsext_host_name(ssl, serv1->server_ip) <=0){
        perror("Unable to set TLS server-name-indication");
    }
	if (SSL_set_fd(ssl, sock) ==0 ){
		perror("Unable to set tcp socket descriptor to ssl session");
	}
	printf("Socket descriptor set to ssl session: %d\n",part);

	//connect SSL session to server
	if(SSL_connect(ssl)<0){
        perror("Error on SSL_connect");
        ERR_print_errors_fp(stderr);
        close(sock);
        exit(EXIT_FAILURE);
    }
	else{
		FILE *file = NULL;
		char filename[100];
		sprintf(filename, "part_%d", part);
		file = fopen(filename, "wb");
		if(file == NULL){
			printf("File could not opened");
		}
		fclose(file);
		char http_query[200];
		sprintf(http_query, "GET %s HTTP/1.1\r\nHost: %s\r\nRange: bytes=%d-%d\r\n\r\n", file_path, ip, range_start, range_end);
		int total_bytes, numbytes;  
		char buf[1280000];
		char total_buff[range_end-range_start];
		SSL_write(ssl, http_query, sizeof(http_query)+1);
		
		 /* get reply & decrypt */
		while((numbytes = SSL_read(ssl, buf, sizeof(buf)+1))>0)
		{
			char *b = strstr(buf , "\r\n\r\n");
			int offset = b - buf + 5;
			if ((offset < range_end-range_start) & offset > 0){
			    char *t = buf + offset;
			}
			else{
				file = fopen(filename, "ab");
				fwrite(buf, numbytes, 1, file);
				fclose(file);
			}
			memset(buf, 0, sizeof(buf)+1);			
		}
	}

	//closing functions
	SSL_free(ssl);
	SSL_CTX_free(ctx);
	close(sock);
}


int main(int argc, char **argv)
{
	char *url = NULL;
	char *num = NULL;
	char *dir = NULL;
	int i=0;
	// parsing arguments from the command line.
	while (( i = getopt(argc, argv, "u:n:o:")) != -1){
		switch (i)
		{
			case 'u':
			     url = optarg;
			     break;
			case 'n':
			     num = optarg;
			     break;
			case 'o':
			     dir = optarg;
			     break;
			case '?':
			     break;
			default:
				break;
		}}
	
	struct address_information *serv1 = malloc(sizeof(struct address_information));
	strcpy(serv1->output_file_name, dir);
	const char *dot = strrchr(dir, '.');
    if (!(!dot || dot == dir)){
		strcpy(serv1->output_extension, dot+1);
	}

	init_addr_info(serv1, url);
	int file_size = get_file_size(serv1);

	// create multiple threads to create tls session.
    int NUM_THREADS = atoi(num);
    pthread_t id[NUM_THREADS];
    int ret, each_size;
	each_size = file_size/NUM_THREADS;
	
	struct address_information *serv[NUM_THREADS];
	for(int j=0; j < NUM_THREADS; j++){
		serv[j] = malloc(sizeof(struct address_information));
		strcpy(serv[j]->output_file_name, dir);
		init_addr_info(serv[j], url);
		serv[j]->part = j+1;
		serv[j]->range_start = j * each_size;
		if (j != NUM_THREADS-1)
			serv[j]->range_end = ((j+1)* each_size) - 1;
		else
			serv[j]->range_end = file_size;
	}

    for(int j = 0; j < NUM_THREADS; j++ ) {
		ret = pthread_create(&id[j], NULL, create_tls_session, serv[j]);
		if (ret!=0) {
			printf("Error:unable to create thread, %d\n", ret);
			exit(-1);
    	}
	}
	FILE *output_file_fd = NULL;
	output_file_fd = fopen(dir, "wb");
	
	int range;
    for(int j = 0 ; j < NUM_THREADS; ++j){  
		if (j==NUM_THREADS-1)
			range = serv[j]->range_end-serv[j]->range_start;
	   else
			range = (serv[j]->range_end-serv[j]->range_start)+1;
		
        void* status;
        int t = pthread_join(id[j], &status);
        if (t != 0)
        {
            printf("Execution of thread failed, %d\n", j);
            exit(-1);
        }
		FILE *fp = NULL;
		char filename[100], c, data[range];
		sprintf(filename, "part_%d", (j+1));
		fp = fopen(filename, "rb");
        if ( fp == NULL )
         {
                 printf( "Could not open file %s", filename ) ;
         }
        fread(data,range, 1, fp);
		fwrite(data, range, 1, output_file_fd);
		 
        fclose(fp) ;
    }
	fclose(output_file_fd);
   
	return 0;
}