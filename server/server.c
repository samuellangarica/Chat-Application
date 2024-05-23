#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>

#define PORT 5004
#define BUFFER_SIZE 1024
#define CIPHER_KEY 3  // Basic displacement key for the Caesar cipher

typedef int Socket;
typedef struct sockaddr_in InternetAddress;
typedef struct sockaddr Address;

typedef struct {
    int authenticated;
    char username[BUFFER_SIZE];
} ClientState;

void handle_signal(int signal) {
    wait(NULL);  // Clean up the terminated child process
}

Socket server_setup(int port) {
    Socket server;
    if ((server = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("[-] Error creating server socket");
        exit(EXIT_FAILURE);
    }

    InternetAddress server_address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)
    };

    if (bind(server, (Address *)&server_address, sizeof(server_address)) == -1) {
        perror("[-] Error binding socket");
        close(server);
        exit(EXIT_FAILURE);
    }

    if (listen(server, SOMAXCONN) == -1) {
        perror("[-] Error in socket listen");
        close(server);
        exit(EXIT_FAILURE);
    }

    printf("[+] Server started. Listening on port %d...\n", port);
    return server;
}

Socket server_accept(Socket server) {
    Socket client;
    InternetAddress client_address;
    socklen_t client_address_size = sizeof(client_address);

    if ((client = accept(server, (Address *)&client_address, &client_address_size)) == -1) {
        perror("[-] Error accepting client connection");
        return -1;
    }

    printf("[+] Accepted connection from %s:%d\n",
           inet_ntoa(client_address.sin_addr),
           ntohs(client_address.sin_port));
    return client;
}

// Modified Caesar cipher to handle only alphabetic characters
char* caesar_cipher(char* text, int key) {
    int length = strlen(text);
    char* result = malloc(length + 1); // Allocate memory for the result
    for (int i = 0; i < length; i++) {
        if (text[i] >= 'a' && text[i] <= 'z') {
            result[i] = ((text[i] - 'a' + key) % 26) + 'a';
        } else if (text[i] >= 'A' && text[i] <= 'Z') {
            result[i] = ((text[i] - 'A' + key) % 26) + 'A';
        } else {
            result[i] = text[i]; // Non-alphabetic characters remain unchanged
        }
    }
    result[length] = '\0';
    return result;
}

// Use the same logic as caesar_cipher but with a reversed key
char* caesar_decipher(char* text, int key) {
    return caesar_cipher(text, 26 - key); // Reverse the key for decryption
}

void handle_auth(char* username, char* password, ClientState* client_state, char* response) {
    print("Handling -> Authentication attempt from anonymous user\n");
    client_state->authenticated = 1;  // Mark client as authenticated
    strcpy(client_state->username, username);
    sprintf(response, "Authentication successful for user %s", username);
}

void handle_send_message(char* username, char* message, char* response) {
    sprintf(response, "%s: %s", username, message);
}

void handle_create_group(char* username, char* group_name, char* response) {
    print("Handling -> Create Group for user: %s\n", username);
    char group_path[BUFFER_SIZE];
    snprintf(group_path, sizeof(group_path), "groups/%s", group_name);

    printf("[SERVER] Creating group directory: %s\n", group_path);
    if (mkdir(group_path, 0777) == -1) {
        if (errno == EEXIST) {
            snprintf(response, BUFFER_SIZE, "Group '%s' already exists.", group_name);
        } else {
            snprintf(response, BUFFER_SIZE, "Error creating group '%s': %s", group_name, strerror(errno));
        }
        return;
    }

    char messages_path[BUFFER_SIZE];
    char users_path[BUFFER_SIZE];
    snprintf(messages_path, sizeof(messages_path), "%s/messages.txt", group_path);
    snprintf(users_path, sizeof(users_path), "%s/users.txt", group_path);

    printf("[SERVER] Creating file: %s\n", messages_path);
    FILE *messages_file = fopen(messages_path, "w");
    if (!messages_file) {
        snprintf(response, BUFFER_SIZE, "Error creating messages.txt: %s", strerror(errno));
        return;
    }
    fclose(messages_file);

    printf("[SERVER] Creating file: %s\n", users_path);
    FILE *users_file = fopen(users_path, "w");
    if (!users_file) {
        snprintf(response, BUFFER_SIZE, "Error creating users.txt: %s", strerror(errno));
        return;
    }
    fprintf(users_file, "%s\n", username);
    fclose(users_file);

    snprintf(response, BUFFER_SIZE, "Group '%s' created successfully.", group_name);
}

void handle_client_connection(Socket client) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    ClientState client_state = {.authenticated = 0};

    while ((bytes_read = recv(client, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        printf("----------------------------Received from client----------------------------\n");
        printf("-> Encrypted: %s\n", buffer);

        char* decrypted_request = caesar_decipher(buffer, CIPHER_KEY);
        printf("-> Decrypted: %s\n", decrypted_request);

        // Process the request
        char* lines[BUFFER_SIZE / 2];
        int line_count = 0;
        char* token = strtok(decrypted_request, "\n");
        while (token != NULL) {
            lines[line_count++] = token;
            token = strtok(NULL, "\n");
        }

        char response[BUFFER_SIZE];
        if (strcmp(lines[0], "Auth") == 0) {
            handle_auth(lines[1], lines[2], &client_state, response);
        } else {
            if (!client_state.authenticated) {
                snprintf(response, BUFFER_SIZE, "Not authenticated");
            } else if (strcmp(lines[0], "send_message") == 0) {
                handle_send_message(client_state.username, lines[1], response);
            } else if (strcmp(lines[0], "create_group") == 0) {
                handle_create_group(client_state.username, lines[2], response);
            } else {
                snprintf(response, BUFFER_SIZE, "Unknown service: %s", lines[0]);
            }
        }

        printf("----------------------------Sending to client----------------------------\n");
        char* encrypted_response = caesar_cipher(response, CIPHER_KEY);
        printf("-> Encrypted: %s\n\n\n\n", encrypted_response);

        if (send(client, encrypted_response, strlen(encrypted_response), 0) == -1) {
            perror("Error sending response to client");
        }

        free(decrypted_request); // Free the allocated memory for decrypted request
        free(encrypted_response); // Free the allocated memory for encrypted response
    }

    close(client);
    printf("Client connection closed.\n");
}

void print_working_directory() {
    char cwd[PATH_MAX];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
        printf("[DEBUG] Current working directory: %s\n", cwd);
    } else {
        perror("getcwd() error");
    }
}

int main() {
    // Handle SIGCHLD to clean up zombie processes
    signal(SIGCHLD, handle_signal);

    // Print the current working directory
    print_working_directory();

    // Ensure the base "groups" directory exists
    char base_path[BUFFER_SIZE] = "groups";
    printf("[DEBUG] Creating base directory: %s\n", base_path);
    if (mkdir(base_path, 0777) == -1 && errno != EEXIST) {
        fprintf(stderr, "Error creating base directory '%s': %s\n", base_path, strerror(errno));
        exit(EXIT_FAILURE);
    }

    Socket server = server_setup(PORT);

    while (1) {
        Socket client = server_accept(server);
        if (client != -1) {
            pid_t pid = fork();
            if (pid == -1) {
                perror("[-] Error forking process");
                close(client);
            } else if (pid == 0) {  // Child process
                close(server);  // Close the listening socket in the child process
                handle_client_connection(client);
                exit(EXIT_SUCCESS);
            } else {  // Parent process
                close(client);  // Close the client socket in the parent process
            }
        }
    }

    close(server);
    return 0;
}
