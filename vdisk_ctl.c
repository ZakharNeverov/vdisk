#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VDISK_IOCTL_MAGIC 'v'
#define VDISK_IOCTL_SAVE    _IO(VDISK_IOCTL_MAGIC, 1)
#define VDISK_IOCTL_RESTORE _IO(VDISK_IOCTL_MAGIC, 2)

void usage(const char *progname) {
    fprintf(stderr, "Usage: %s <save|restore|both>\n", progname);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
    int fd, ret;
    
    if (argc != 2)
        usage(argv[0]);

    fd = open("/dev/vdisk", O_RDWR);
    if (fd < 0) {
        perror("open");
        exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "save") == 0) {
        ret = ioctl(fd, VDISK_IOCTL_SAVE, 0);
        if (ret < 0)
            perror("ioctl SAVE");
        else
            printf("Сохранение образа прошло успешно.\n");
    } else if (strcmp(argv[1], "restore") == 0) {
        ret = ioctl(fd, VDISK_IOCTL_RESTORE, 0);
        if (ret < 0)
            perror("ioctl RESTORE");
        else
            printf("Восстановление образа прошло успешно.\n");
    } else if (strcmp(argv[1], "both") == 0) {
        ret = ioctl(fd, VDISK_IOCTL_SAVE, 0);
        if (ret < 0)
            perror("ioctl SAVE");
        else
            printf("Сохранение образа прошло успешно.\n");
        ret = ioctl(fd, VDISK_IOCTL_RESTORE, 0);
        if (ret < 0)
            perror("ioctl RESTORE");
        else
            printf("Восстановление образа прошло успешно.\n");
    } else {
        usage(argv[0]);
    }

    close(fd);
    return 0;
}

