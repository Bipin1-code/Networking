
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <conio.h>
#include <stdint.h>

#define PORT 9090

static int ExtractMessageClient(char *buffer, int *buf_len,
                            char *msg_out, int *msg_len){

    if(*buf_len < 4) return 0;

    uint32_t len;
    memcpy(&len, buffer, 4);
    len = ntohl(len);

    if(*buf_len < 4 + len) return 0;
    memcpy(msg_out, buffer + 4, len);
    msg_out[len] = '\0';
    *msg_len = len;

    int total = 4 + len;
    memmove(buffer, buffer + total, *buf_len - total);
    *buf_len -= total;

    return 1;
}

static void SafeSSLWrite(SSL *ssl, char *data) {
    uint32_t len = strlen(data);
    uint32_t net_len = htonl(len);
    
    int w1 = SSL_write(ssl, (char *)&net_len, 4);
    int w2 = SSL_write(ssl, data, len);
    
    if (w1 <= 0 || w2 <= 0) {
        printf("SSL_write failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
    } else {
        printf("Sent %d bytes\n", 4 + w2);
    }
}

int main(){
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0){
        printf("ERROR=%d, WSAStartup failed.\n",
               WSAGetLastError());
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    SOCKET sock_h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock_h == INVALID_SOCKET){
        printf("Failed to create socket, ERROR=%d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);

    int r = inet_pton(AF_INET,
                      "127.0.0.1",
                      &addr.sin_addr);
    if(r <= 0) puts("IP conversion to binary failed\n");

    
    int c = connect(sock_h, (struct sockaddr *)&addr, sizeof(addr));
    if(c != 0){
        printf("Failed to connect ERROR=%d\n", WSAGetLastError());
    }
    puts("Connection Established");

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock_h);

    if(SSL_connect(ssl) != 1){
        printf("TLS handshake failed: %s\n",
               ERR_error_string(ERR_get_error(), NULL));

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(sock_h);
        WSACleanup();
        return 1;
    }
    puts("TLS handshake success");

    u_long mode = 1;
    ioctlsocket(sock_h, FIONBIO, &mode);

    char recv_buffer[4096];
    int recv_len = 0;
    
    char send_buffer[4096];
    
    while(1){
        int space = sizeof(recv_buffer) - recv_len;
        int ret = SSL_read(ssl, recv_buffer + recv_len, space);
        if(ret > 0){
            recv_len += ret;
            char msg[4096];
            int msg_len;
            while(ExtractMessageClient(recv_buffer, &recv_len, msg, &msg_len)){
                printf("Message: %s\n", msg);
            }
        }else{
            int err = SSL_get_error(ssl, ret);
            if(err == SSL_ERROR_WANT_READ ||
               err == SSL_ERROR_WANT_WRITE){

            }else if(err == SSL_ERROR_ZERO_RETURN){
                puts("Disconnected (clean)");
                break;
            }else{
                printf("SSL error: %s\n",
                       ERR_error_string(ERR_get_error(), NULL));
                break;
            }
        }
        
        if(kbhit()){
            printf("DEBUG: kbhit triggered\n");
            fgets(send_buffer, sizeof(send_buffer), stdin);
            if(strlen(send_buffer) <= 1) continue;
            SafeSSLWrite(ssl, send_buffer);
        }
        Sleep(10);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    closesocket(sock_h);
    WSACleanup();
    
    return 0;
}
