#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>

#define PORT 5004
#define BUFFER_SIZE 1024
#define BROADCAST_PORT 5005
#define CIPHER_KEY 3  

typedef int Socket;
typedef struct sockaddr_in InternetAddress;
typedef struct sockaddr Address;

typedef struct {
    int authenticated;
    char username[BUFFER_SIZE];
} ClientState;

void handle_signal(int signal) {
    wait(NULL);  
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

    printf("Connection accepted from %s:%d\n",
           inet_ntoa(client_address.sin_addr),
           ntohs(client_address.sin_port));
    return client;
}

char* caesar_cipher(char* text, int key) {
    int length = strlen(text);
    char* result = malloc(length + 1); 
    for (int i = 0; i < length; i++) {
        if (text[i] >= 'a' && text[i] <= 'z') {
            result[i] = ((text[i] - 'a' + key) % 26) + 'a';
        } else if (text[i] >= 'A' && text[i] <= 'Z') {
            result[i] = ((text[i] - 'A' + key) % 26) + 'A';
        } else {
            result[i] = text[i]; 
        }
    }
    result[length] = '\0';
    return result;
}

char* caesar_decipher(char* text, int key) {
    return caesar_cipher(text, 26 - key); // Reverse the key for decryption
}

void handle_auth(char* username, char* password, ClientState* client_state, char* response) {
    printf("Handling -> Authentication attempt from user: %s\n", username);

    char user_file_path[BUFFER_SIZE];
    snprintf(user_file_path, sizeof(user_file_path), "users/%s.txt", username);

    FILE *user_file = fopen(user_file_path, "r");
    if (user_file == NULL) {
        snprintf(response, BUFFER_SIZE, "Authentication failed: User %s not found", username);
        return;
    }

    char stored_password[BUFFER_SIZE];
    if (fgets(stored_password, sizeof(stored_password), user_file) == NULL) {
        snprintf(response, BUFFER_SIZE, "Authentication failed: Error reading password for user %s", username);
        fclose(user_file);
        return;
    }
    fclose(user_file);

    // Remove newline character from stored_password if it exists
    stored_password[strcspn(stored_password, "\n")] = '\0';

    if (strcmp(stored_password, password) == 0) {
        client_state->authenticated = 1;
        strcpy(client_state->username, username);
        snprintf(response, BUFFER_SIZE, "Authentication successful for user %s", username);
    } else {
        snprintf(response, BUFFER_SIZE, "Authentication failed: Incorrect password for user %s", username);
    }
}

void handle_signup(char* username, char* password, char* response) {
    printf("Handling -> Signup attempt for user: %s\n", username);

    char user_file_path[BUFFER_SIZE];
    snprintf(user_file_path, sizeof(user_file_path), "users/%s.txt", username);

    FILE *user_file = fopen(user_file_path, "r");
    if (user_file != NULL) {
        fclose(user_file);
        snprintf(response, BUFFER_SIZE, "Signup failed: User %s already exists", username);
        return;
    }

    user_file = fopen(user_file_path, "w");
    if (user_file == NULL) {
        snprintf(response, BUFFER_SIZE, "Signup failed: Error creating user %s", username);
        return;
    }

    fprintf(user_file, "%s\n", password);
    fclose(user_file);

    snprintf(response, BUFFER_SIZE, "Signup successful for user %s", username);
}

void handle_send_message(char* username, char* message, char* response) {
    sprintf(response, "%s: %s", username, message);
}

void handle_create_group(char* username, char* group_name, char* response) {
    printf("Handling -> Create Group for user: %s\n", username);
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

void broadcast_update() {
    char update_message[] = "update";

    Socket udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == -1) {
        perror("Error creating UDP socket");
        return;
    }

    int broadcast_enable = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) == -1) {
        perror("Error enabling broadcast option");
        close(udp_socket);
        return;
    }

    InternetAddress broadcast_address;
    broadcast_address.sin_family = AF_INET;
    broadcast_address.sin_port = htons(BROADCAST_PORT);
    broadcast_address.sin_addr.s_addr = inet_addr("255.255.255.255");

    if (sendto(udp_socket, update_message, strlen(update_message), 0, (Address *)&broadcast_address, sizeof(broadcast_address)) == -1) {
        perror("Error sending broadcast update");
    }

    printf("********************************************************************************\n");
    printf("Broadcasting update to all clients\n");
    printf("********************************************************************************\n");

    close(udp_socket);
}


void broadcast_group_message(char* group_name) {
    char messages_path[BUFFER_SIZE];
    snprintf(messages_path, sizeof(messages_path), "groups/%s/messages.txt", group_name);

    FILE *messages_file = fopen(messages_path, "r");
    if (!messages_file) {
        printf("Error: Group '%s' does not exist or unable to read messages file.\n", group_name);
        return;
    }

    char message_contents[BUFFER_SIZE * 10] = "";  // Assuming message file is not larger than 10 KB
    char line[BUFFER_SIZE];

    while (fgets(line, sizeof(line), messages_file)) {
        strcat(message_contents, line);
    }
    fclose(messages_file);

    char broadcast_message[BUFFER_SIZE * 10 + BUFFER_SIZE];
    snprintf(broadcast_message, sizeof(broadcast_message), "%s\n%s", group_name, message_contents);

    Socket udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udp_socket == -1) {
        perror("Error creating UDP socket");
        return;
    }

    int broadcast_enable = 1;
    if (setsockopt(udp_socket, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable)) == -1) {
        perror("Error enabling broadcast option");
        close(udp_socket);
        return;
    }

    InternetAddress broadcast_address;
    broadcast_address.sin_family = AF_INET;
    broadcast_address.sin_port = htons(BROADCAST_PORT);
    broadcast_address.sin_addr.s_addr = inet_addr("255.255.255.255");

    if (sendto(udp_socket, broadcast_message, strlen(broadcast_message), 0, (Address *)&broadcast_address, sizeof(broadcast_address)) == -1) {
        perror("Error sending broadcast message");
    }

    printf("********************************************************************************\n");
    printf("Broadcasting messages to group: %s\n", group_name);
    printf("********************************************************************************\n");

    close(udp_socket);
}

void handle_add_user_to_group(char* group_name, char* username_to_add, char* response) {
    printf("Handling -> Add user to group %s\n", group_name);

    char user_file_path[BUFFER_SIZE];
    snprintf(user_file_path, sizeof(user_file_path), "groups/%s/users.txt", group_name);

    FILE *user_file = fopen(user_file_path, "a+");
    if (!user_file) {
        snprintf(response, BUFFER_SIZE, "Error: Group '%s' does not exist.", group_name);
        return;
    }

    // Check if the user is already in the group
    char line[BUFFER_SIZE];
    while (fgets(line, sizeof(line), user_file)) {
        line[strcspn(line, "\n")] = '\0'; // Remove newline character
        if (strcmp(line, username_to_add) == 0) {
            snprintf(response, BUFFER_SIZE, "User '%s' is already in the group '%s'.", username_to_add, group_name);
            fclose(user_file);
            return;
        }
    }

    // Add the user to the group
    fprintf(user_file, "%s\n", username_to_add);
    fclose(user_file);

    snprintf(response, BUFFER_SIZE, "User '%s' added to group '%s' successfully.", username_to_add, group_name);

    // Broadcast update to all clients
    broadcast_update();
}


void handle_get_messages_from_group(char* group_name, char* response) {
    printf("Handling -> Get messages from group %s\n", group_name);
    char messages_path[BUFFER_SIZE];
    snprintf(messages_path, sizeof(messages_path), "groups/%s/messages.txt", group_name);

    FILE *messages_file = fopen(messages_path, "r");
    if (!messages_file) {
        snprintf(response, BUFFER_SIZE, "Error: Group '%s' does not exist or unable to read messages file.", group_name);
        return;
    }

    char message_contents[BUFFER_SIZE * 10] = "";  // Assuming message file is not larger than 10 KB
    char line[BUFFER_SIZE];

    while (fgets(line, sizeof(line), messages_file)) {
        strcat(message_contents, line);
    }
    fclose(messages_file);

    snprintf(response, sizeof(message_contents) + BUFFER_SIZE, "%s\n%s", group_name, message_contents);
}



void handle_send_message_to_group(char* username, char* group_name, char* message, char* response) {
    printf("Handling -> Send message to group %s from user: %s\n", group_name, username);
    char group_path[BUFFER_SIZE];
    snprintf(group_path, sizeof(group_path), "groups/%s/messages.txt", group_name);

    FILE *messages_file = fopen(group_path, "a");
    if (!messages_file) {
        snprintf(response, BUFFER_SIZE, "Error: Group '%s' does not exist.", group_name);
        return;
    }

    fprintf(messages_file, "\n%s: %s\n", username, message);
    fclose(messages_file);

    snprintf(response, BUFFER_SIZE, "Message sent to group '%s' successfully.", group_name);
    broadcast_group_message(group_name);  // Broadcast the updated messages to the group members
}

void handle_get_user_group_names(char* username, char* response) {
    printf("Handling -> Get groups for user: %s\n", username);

    DIR *d;
    struct dirent *dir;
    char group_path[BUFFER_SIZE];
    char user_file_path[BUFFER_SIZE];
    char group_names[BUFFER_SIZE] = "";
    int group_count = 0;
    
    d = opendir("groups");

    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_DIR && strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0) {
                snprintf(user_file_path, sizeof(user_file_path), "groups/%s/users.txt", dir->d_name);
                FILE *user_file = fopen(user_file_path, "r");
                if (user_file != NULL) {
                    char user[BUFFER_SIZE];
                    while (fgets(user, sizeof(user), user_file)) {
                        user[strcspn(user, "\n")] = '\0';
                        if (strcmp(user, username) == 0) {
                            strcat(group_names, dir->d_name);
                            strcat(group_names, "\n");
                            group_count++;
                            break;
                        }
                    }
                    fclose(user_file);
                }
            }
        }
        closedir(d);
    }

    if (group_count == 0) {
        snprintf(response, BUFFER_SIZE, "No groups found for user %s", username);
    } else {
        snprintf(response, BUFFER_SIZE, "%s", group_names);
    }
}

void handle_client_connection(Socket client) {
    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;
    ClientState client_state = {.authenticated = 0};

    while ((bytes_read = recv(client, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_read] = '\0';
        
        // Separate each request with a long line of "-"
        printf("--------------------------------------------------------------------------------\n");
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
            printf("Service requested: Auth by user %s\n", lines[1]);
            handle_auth(lines[1], lines[2], &client_state, response);
        } else if (strcmp(lines[0], "Signup") == 0) {
            printf("Service requested: Signup by user %s\n", lines[1]);
            handle_signup(lines[1], lines[2], response);
        } else {
            if (!client_state.authenticated) {
                snprintf(response, BUFFER_SIZE, "Not authenticated");
            } else if (strcmp(lines[0], "send_message") == 0) {
                printf("Service requested: Send message by user %s\n", client_state.username);
                handle_send_message(client_state.username, lines[1], response);
            } else if (strcmp(lines[0], "create_group") == 0) {
                printf("Service requested: Create group by user %s\n", client_state.username);
                handle_create_group(client_state.username, lines[2], response);
            } else if (strcmp(lines[0], "send_message_to_group") == 0) {
                printf("Service requested: Send message to group by user %s\n", client_state.username);
                // Combine the remaining lines into a single message with line breaks
                char message[BUFFER_SIZE] = "";
                for (int i = 3; i < line_count; i++) {
                    strcat(message, lines[i]);
                    if (i < line_count - 1) {
                        strcat(message, "\n");
                    }
                }
                handle_send_message_to_group(client_state.username, lines[2], message, response);
            } else if (strcmp(lines[0], "get_user_group_names") == 0) {
                printf("Service requested: Get user group names by user %s\n", client_state.username);
                handle_get_user_group_names(client_state.username, response);
            } else if (strcmp(lines[0], "add_user_to_group") == 0) {
                printf("Service requested: Add user to group by user %s\n", client_state.username);
                handle_add_user_to_group(lines[1], lines[2], response);
            } else if (strcmp(lines[0], "get_messages_from_group") == 0) {
                printf("Service requested: Get messages from group %s\n", lines[1]);
                handle_get_messages_from_group(lines[1], response);
            }
            else {
                snprintf(response, BUFFER_SIZE, "Unknown service: %s", lines[0]);
            }
        }

        printf("----------------------------Sending to client----------------------------\n");
        char* encrypted_response = caesar_cipher(response, CIPHER_KEY);
        printf("-> Encrypted: %s\n\n", encrypted_response);

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

    // Ensure the base "users" directory exists
    char users_base_path[BUFFER_SIZE] = "users";
    printf("[DEBUG] Creating base directory: %s\n", users_base_path);
    if (mkdir(users_base_path, 0777) == -1 && errno != EEXIST) {
        fprintf(stderr, "Error creating base directory '%s': %s\n", users_base_path, strerror(errno));
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
