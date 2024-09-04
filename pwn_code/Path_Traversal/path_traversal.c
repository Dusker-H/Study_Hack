// Name: path_traversal.c
// Compile: gcc -o path_traversal path_traversal.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const int kMaxNameLen = 0x100;
const int kMaxPathLen = 0x200;
const int kMaxDataLen = 0x1000;
const char *kBasepath = "/tmp";

int main() {
  char file_name[kMaxNameLen];
  char file_path[kMaxPathLen];
  char data[kMaxDataLen];
  FILE *fp = NULL;

  // Initialize local variables
  memset(file_name, '\0', kMaxNameLen);
  memset(file_path, '\0', kMaxPathLen);
  memset(data, '\0', kMaxDataLen);

  // Receive input from user
  printf("File name: ");
  fgets(file_name, kMaxNameLen, stdin);

  // Trim trailing new line
  file_name[strcspn(file_name, "\n")] = '\0';

  // Construct the `file_path`
  snprintf(file_path, kMaxPathLen, "%s/%s", kBasepath, file_name);

  // Read the file and print its content
  if ((fp = fopen(file_path, "r")) == NULL) {
    fprintf(stderr, "No file named %s", file_name);
    return -1;
  }

  fgets(data, kMaxDataLen, fp);
  printf("%s", data);

  fclose(fp);

  return 0;
}