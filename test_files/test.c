#include <stdio.h>
#include <unistd.h>

int main() {
  printf("Hello, world!");
  int i = 0;
  for (i = 0; i < 5; i++) {
    sleep(1);
    printf("WTF");
  }

  return 0;
}
