#include <unistd.h>

int bv1() {
    char message[] = "you're on branch 1\n";
    write(1, message, sizeof(message) - 1);
    return 1;
}

int bv2() {
    char message[] = "you're on branch 2\n";
    write(1, message, sizeof(message) - 1);
    return 2;
}

int bv3() {
    char message[] = "you're on branch 3\n";
    write(1, message, sizeof(message) - 1);
    return 3;
}

int main (int v) {
    if (v < 10) return bv1();
    char message[] = "you're not on branch 1\n";
    write(1, message, sizeof(message) - 1);
    if (v < 15) return bv2();
    char message2[] = "you're not on branch 2\n";
    write(1, message2, sizeof(message2) - 1);
    if (v < 17) return bv3();
    char message3[] = "you're on branch 4\n";
    write(1, message3, sizeof(message3) - 1);
    return 0;
}
