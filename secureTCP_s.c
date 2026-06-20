
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <ws2tcpip.h>
#include <winsock2.h>
#include <stdio.h>
#include <stdint.h>

#define MAX_CLIENTS 10
#define MAX_NAME 32
#define PORT 9090

typedef struct {
    SOCKET socket;
    SSL *ssl;
    char name[MAX_NAME];
    char buffer[4096];
    int buffer_len;
} CLIENT;

CLIENT clients[MAX_CLIENTS];
int client_count = 0;

fd_set master;

static int FindBySocket(SOCKET s){
    for(int i = 0; i < client_count; i++){
        if(clients[i].socket == s) return i;
    }
    return -1;
}

static int ExtractMessage(CLIENT *client, char *msg_out, int *msg_len){
    if(client->buffer_len < 4) return 0;

    uint32_t len;
    memcpy(&len, client->buffer, 4);
    len = ntohl(len);

    if(client->buffer_len < 4 + len) return 0;

    memcpy(msg_out, client->buffer + 4, len);
    msg_out[len] = '\0';
    *msg_len = len;

    int total = 4 + len;
    memmove(client->buffer, client->buffer + total,
            client->buffer_len - total);

    client->buffer_len -= total;
    return 1;
}

static int FindByName(char *name){
    for(int i = 0; i < client_count; i++)
        if(strcmp(clients[i].name, name) == 0) return i;

    return -1;
}

static void RemoveClient(int index){
    if(clients[index].ssl){
        SSL_free(clients[index].ssl); 
    }
    closesocket(clients[index].socket);
    FD_CLR(clients[index].socket, &master);

    for(int i = index; i < (client_count - 1); i++){
        clients[i] = clients[i + 1];
    }
    client_count--;
}

static void ProcessMessage(int sender_idx, char *msg){
    SOCKET sender_sock = clients[sender_idx].socket;

    if(strncmp(msg, "/name ", 6) == 0){
        char *name = msg + 6;
        name[strcspn(name, "\r\n")] = '\0';
        strcpy(clients[sender_idx].name, name);
        printf("Client %d is now '%s'\n", (int)sender_sock, name);

        char response[256];
        sprintf(response, "Your name is now '%s'\n", name);
        uint32_t response_len = strlen(response);
        uint32_t net_resp_len = htonl(response_len);
        SSL_write(clients[sender_idx].ssl, (char *)&net_resp_len, 4);
        SSL_write(clients[sender_idx].ssl, response, response_len);

    }else if(strncmp(msg, "/msg ", 5) == 0){
        char *rest = msg + 5;
        char target_name[MAX_NAME];
        int i = 0;
        while(rest[i] != ' ' && rest[i] != '\0') i++;
        strncpy(target_name, rest, i);
        target_name[i] = '\0';

        char *pm_msg = rest + i + 1;
        int target_idx = FindByName(target_name);
        if(target_idx != -1){
            char formatted[4096];
            sprintf(formatted, "[PM from %s]: %s\n",
                    clients[sender_idx].name, pm_msg);

            uint32_t formatted_len = strlen(formatted);
            uint32_t net_frm_len = htonl(formatted_len);
            SSL_write(clients[target_idx].ssl, (char *)&net_frm_len, 4);
            SSL_write(clients[target_idx].ssl, formatted, formatted_len);
        }else{
            char error[256];
            sprintf(error, "User '%s' not found\n", target_name);

            uint32_t error_len = strlen(error);
            uint32_t net_err_len = htonl(error_len);
            SSL_write(clients[target_idx].ssl, (char *)&net_err_len, 4);
            SSL_write(clients[target_idx].ssl, error, error_len);
        }   
    }else if(strncmp(msg, "/list", 5) == 0){
        char list[4096] = "Online: ";
        for(int i = 0; i < client_count; i++){
            strcat(list, clients[i].name);
            strcat(list, " ");
        }
        strcat(list, "\n");

        uint32_t list_len = strlen(list);
        uint32_t net_list_len = htonl(list_len);
        SSL_write(clients[sender_idx].ssl, (char *)&net_list_len, 4);
        SSL_write(clients[sender_idx].ssl, list, list_len);           

    }else{
         for(int i = 0; i < client_count; i++){
            if(i == sender_idx) continue;
            
            char formatted[4096];
            sprintf(formatted, "[%s]: %.4000s",
                              clients[sender_idx].name, msg);

            uint32_t formatted_len = strlen(formatted);
            uint32_t net_frm_len = htonl(formatted_len);
            SSL_write(clients[i].ssl, (char *)&net_frm_len, 4);
            SSL_write(clients[i].ssl, formatted, formatted_len);              
         }
    }
}

int main(){
    puts("**** TCP-TLS server ****");
    WSADATA wsa;
    if(WSAStartup(MAKEWORD(2, 2), &wsa) != 0){
        printf("ERROR=%d, WSAStartup failed\n", WSAGetLastError());
        return 1;
    }

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    SOCKET sock_h = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(sock_h == INVALID_SOCKET){
        printf("ERROR=%d, Failed to create socket\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    struct sockaddr_in server = {0};
    server.sin_family = AF_INET;
    server.sin_port = htons(PORT);
    server.sin_addr.s_addr = INADDR_ANY;

    int n = bind(sock_h, (struct sockaddr *)&server, sizeof(server));
    if(n == SOCKET_ERROR){
        printf("ERROR=%d, Failed to bind\n", WSAGetLastError());
        closesocket(sock_h);
        WSACleanup();
        return 1;
    }

    listen(sock_h, 5);
    printf("Server port %d is running...\n", PORT);
  
    fd_set temp_fds;
    FD_ZERO(&master);
    FD_SET(sock_h, &master);

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if(!ctx){
        puts("Failed to create SSL context");
        closesocket(sock_h);
        WSACleanup();
        return 1;
    }
    SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM);

    while(1){
        temp_fds = master;
        int activity = select(0, &temp_fds, NULL, NULL, NULL);
        if(activity > 0){
            for(u_int i = 0; i < temp_fds.fd_count; i++){
                SOCKET sock = temp_fds.fd_array[i];
                if(sock == sock_h){
                    SOCKET client_socket = accept(sock_h,
                                                  NULL, NULL);
                    if(client_socket != INVALID_SOCKET){
                        FD_SET(client_socket, &master);
                        clients[client_count].socket = client_socket;
                        strcpy(clients[client_count].name, "unnamed");
                        clients[client_count].buffer_len = 0;
                        memset(clients[client_count].buffer, 0,
                               sizeof(clients[client_count].buffer));

                        SSL *ssl = SSL_new(ctx);
                        SSL_set_fd(ssl, client_socket);

                        int ssl_ret = SSL_accept(ssl);
                        if(ssl_ret != 1){
                            printf("SSL_accept failed: %s\n",
                                   ERR_error_string(ERR_get_error(), NULL));
                            closesocket(client_socket);
                            SSL_free(ssl);
                            FD_CLR(client_socket, &master);
                            continue;
                        }
                        printf("TLS handshake complete for socket %d\n",
                               (int)client_socket);
                        clients[client_count].ssl = ssl;
                        client_count++;
                    }
                }else{
                    int idx = FindBySocket(sock);
                    CLIENT *c = &clients[idx];
                    int space = sizeof(c->buffer) - (c->buffer_len);
                    int ret = SSL_read(c->ssl, c->buffer + c->buffer_len, space);
                    if(ret <= 0){
                        puts("SSL_read failed\n");
                        int err = SSL_get_error(c->ssl, ret);
                        switch(err){
                            case SSL_ERROR_ZERO_RETURN:
                                printf("%s disconnected (clean)\n", c->name);
                                break;

                            case SSL_ERROR_SYSCALL:
                                printf("%s disconnected (socket error: %d)\n",
                                       c->name, WSAGetLastError());
                                break;

                            case SSL_ERROR_SSL:
                                printf("%s TLS error: %s\n", c->name,
                                       ERR_error_string(ERR_get_error(), NULL));
                                break;
                            default:
                                printf("%s SSL_read error: %d\n", c->name, err);
                                break;    
                        }
                        SSL_shutdown(c->ssl);
                        RemoveClient(idx);
                    }else{
                        c->buffer_len += ret;
                        char msg[4096];
                        int msg_len;
                        while(ExtractMessage(c, msg, &msg_len)){
                            ProcessMessage(idx, msg);
                        }
                    }
                }
            }
        }
    }

    closesocket(sock_h);
    WSACleanup();
    return 0;
}
