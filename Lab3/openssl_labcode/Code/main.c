#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#define PORT 22222
#define BUFFER_SIZE 4096
#define BACKLOG 10

// 客户端数据结构
typedef struct 
{
    int client_fd;
    SSL_CTX *ctx;
    struct sockaddr_in client_addr;
} client_info_t;

// 获取文件大小
long get_file_size(const char *filename) 
{
    struct stat st;
    if(stat(filename, &st) == 0)
    {
        return st.st_size;
    }
    return -1;
}

// 获取文件MIME类型
const char* get_mime_type(const char *filename) 
{
    const char *ext = strrchr(filename, '.');
    if(!ext) return "text/plain";
    
    if(strcmp(ext, ".html") == 0 || strcmp(ext, ".htm") == 0) return "text/html; charset=UTF-8";
    if(strcmp(ext, ".css") == 0) return "text/css";
    if(strcmp(ext, ".js") == 0) return "application/javascript";
    if(strcmp(ext, ".jpg") == 0 || strcmp(ext, ".jpeg") == 0) return "image/jpeg";
    if(strcmp(ext, ".png") == 0) return "image/png";
    if(strcmp(ext, ".gif") == 0) return "image/gif";
    
    return "text/plain";
}

// 初始化SSL上下文
SSL_CTX* init_ssl_context() 
{
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if(!ctx) 
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // 加载服务器证书
    if(SSL_CTX_use_certificate_file(ctx, "../server/server.crt", SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // 加载服务器私钥
    if(SSL_CTX_use_PrivateKey_file(ctx, "../server/server.key", SSL_FILETYPE_PEM) <= 0) 
    {
        ERR_print_errors_fp(stderr);
        return NULL;
    }
    // 检查私钥是否匹配证书
    if(!SSL_CTX_check_private_key(ctx)) 
    {
        fprintf(stderr, "Private key does not match certificate!\n");
        return NULL;
    }
    
    printf("SSL Context initialized successfully\n");
    return ctx;
}

// 处理HTTP请求
void handle_request(SSL *ssl, const char *request) 
{
    char method[16] = {0};
    char path[256] = {0};
    char version[16] = {0};
    // 解析请求行
    sscanf(request, "%s %s %s", method, path, version);
    printf("Method: %s, Path: %s\n", method, path);
    // 默认首页
    if(strcmp(path, "/") == 0)
    {
        strcpy(path, "/index.html");
    }
    // 构建文件路径
    char filepath[512] = "WWW";
    strcat(filepath, path);
    printf("Looking for file: %s\n", filepath);
    // 检查文件是否存在
    long file_size = get_file_size(filepath);
    FILE *fp = fopen(filepath, "rb");
    
    if(fp && file_size > 0) 
    {
        // 读取文件内容
        char *content = (char*)malloc(file_size);
        if(content) 
        {
            fread(content, 1, file_size, fp);
            fclose(fp);
            // 发送HTTP响应头
            char header[BUFFER_SIZE];
            const char *mime_type = get_mime_type(filepath);
            sprintf(header, 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: %s\r\n"
                "Content-Length: %ld\r\n"
                "Connection: close\r\n"
                "\r\n",
                mime_type, file_size);
            
            SSL_write(ssl, header, strlen(header));
            SSL_write(ssl, content, file_size);
            
            printf("Sent: %s (%ld bytes)\n", filepath, file_size);
            free(content);
        } 
        else 
        {
            const char *error = "HTTP/1.1 500 Internal Error\r\n\r\n";
            SSL_write(ssl, error, strlen(error));
        }
    } 
    else 
    {
        // 文件不存在，返回404
        const char *not_found = 
            "HTTP/1.1 404 Not Found\r\n"
            "Content-Type: text/html\r\n"
            "\r\n"
            "<html><body><h1>404 Not Found</h1><p>File not found</p></body></html>";
        SSL_write(ssl, not_found, strlen(not_found));
        printf("404 Not Found: %s\n", filepath);
        
        if(fp) fclose(fp);
    }
}

// 客户端线程函数
void* client_thread(void* arg) 
{
    client_info_t *info = (client_info_t*)arg;
    
    printf("Thread %lu handling connection from: %s:%d\n", 
           pthread_self(),
           inet_ntoa(info->client_addr.sin_addr), 
           ntohs(info->client_addr.sin_port));
    // 创建SSL对象
    SSL *ssl = SSL_new(info->ctx);
    SSL_set_fd(ssl, info->client_fd);
    // SSL握手
    if(SSL_accept(ssl) <= 0) 
    {
        ERR_print_errors_fp(stderr);
    } 
    else 
    {
        char buffer[BUFFER_SIZE] = {0};
        int bytes = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
        
        if(bytes > 0) 
        {
            printf("\n--- Request from thread %lu ---\n", pthread_self());
            printf("%s\n", buffer);
            printf("--- End Request ---\n\n");
            
            handle_request(ssl, buffer);
        }
    }
    // 清理
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(info->client_fd);
    free(info);
    
    printf("Thread %lu connection closed\n", pthread_self());
    
    return NULL;
}

int main() 
{
    // 忽略SIGPIPE信号
    signal(SIGPIPE, SIG_IGN);
    // 初始化SSL
    SSL_CTX *ctx = init_ssl_context();
    if(!ctx) 
    {
        fprintf(stderr, "Failed to initialize SSL\n");
        return -1;
    }
    // 创建socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0) 
    {
        perror("socket");
        return -1;
    }
    // 设置socket选项，允许端口重用
    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    // 绑定地址
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    if(bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) 
    {
        perror("bind");
        return -1;
    }
    // 监听
    if(listen(sockfd, BACKLOG) < 0) 
    {
        perror("listen");
        return -1;
    }
    
    printf("\n========================================\n");
    printf("HTTPS Server Started (Concurrent)\n");
    printf("Port: %d\n", PORT);
    printf("Access: https://localhost:%d\n", PORT);
    printf("========================================\n\n");
    
    // 为每个请求创建新线程
    while(1) 
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_fd = accept(sockfd, (struct sockaddr*)&client_addr, &client_len);
        if(client_fd < 0) 
        {
            perror("accept");
            continue;
        }
        
        // 创建客户端信息结构
        client_info_t *info = (client_info_t*)malloc(sizeof(client_info_t));
        info->client_fd = client_fd;
        info->ctx = ctx;
        memcpy(&info->client_addr, &client_addr, sizeof(client_addr));
        
        // 创建线程处理请求
        pthread_t tid;
        if(pthread_create(&tid, NULL, client_thread, info) != 0) 
        {
            perror("pthread_create");
            close(client_fd);
            free(info);
        } 
        else 
        {
            pthread_detach(tid);  // 分离线程，自动回收资源
        }
    }
    
    close(sockfd);
    SSL_CTX_free(ctx);
    
    return 0;
}