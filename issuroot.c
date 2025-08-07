#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pty.h>
#include <string.h>
#include <sys/wait.h>
#include <errno.h>

#define BUF_SIZE 512

int main() {
    int master_fd;
    pid_t pid = forkpty(&master_fd, NULL, NULL, NULL);
    if (pid < 0) {
        perror("forkpty");
        return 3;
    }

    if (pid == 0) {
        // Child: execute su -c "whoami"
        execlp("su", "su", "-c", "whoami", NULL);
        if (errno == ENOENT) {
            fprintf(stderr, "SUCMDNOTFND\n");
            exit(1);   // 1 = su not found
        } else {
            perror("execlp");
            exit(3);
        }
    }

    char buf[BUF_SIZE + 1];
    ssize_t nread;
    const char *password = "root\n"; // replace with your password

    int sent_password = 0;
    int auth_failed = 0;
    int got_whoami = 0;
    int notfound = 0;
    char output[4096] = {0};
    size_t output_len = 0;

    while ((nread = read(master_fd, buf, BUF_SIZE)) > 0) {
        buf[nread] = '\0';

        // Accumulate output for analysis
        if (output_len + nread < sizeof(output) - 1) {
            strcat(output, buf);
            output_len += nread;
        }

        // Detect password prompt and send password once
        if (!sent_password && strstr(buf, "Password:") != NULL) {
            write(master_fd, password, strlen(password));
            sent_password = 1;
        }

        // Detect authentication failure messages (case-insensitive)
        if (strcasestr(buf, "incorrect password") != NULL ||
            strcasestr(buf, "authentication failure") != NULL) {
            auth_failed = 1;
            }

        if (strcasestr(buf, "SUCMDNOTFND") != NULL) {
            notfound = 1;
        }

        // Detect success output (whoami should output "root\n")
        if (strstr(buf, "root") != NULL) {
            got_whoami = 1;
        }
    }

    int status;
    waitpid(pid, &status, 0);

    if (auth_failed) {
        fprintf(stderr, "FLI68: Authentication failed\n");
        return 2;  // 2 = incorrect password
    } else if (WIFEXITED(status)) {
        int exit_status = WEXITSTATUS(status);
        if (exit_status == 0 && got_whoami) {
            printf("FLI00: Success: running as root\n");
            return 0;
        }
        if (exit_status == 1 && notfound) {
            fprintf(stderr, "FLI22: Not su rooted.\n");
        } else {
            fprintf(stderr, "FLI82: su exited with status %d\n", exit_status);
            return 3;
        }
    } else {
        fprintf(stderr, "FLI32: su terminated abnormally\n");
        return 3;
    }
}
