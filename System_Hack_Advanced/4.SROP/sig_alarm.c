// Name: sig_alarm.c
// Compile: gcc -o sig_alarm sig_alarm.c 
#include<stdio.h>
#include<unistd.h>
#include<signal.h>
#include<stdlib.h>
 
void sig_handler(int signum){
  printf("sig_handler called.\n");
  exit(0);
}
int main(){
  signal(SIGALRM,sig_handler);
  alarm(5);
  getchar();
  return 0;
}