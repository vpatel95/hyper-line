#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/stat.h>
#include <pthread.h>
#include <string.h>

int pipe1[2];
int pipe2[2];
char str[100];

void *user(void *ptr) {
   while(1) {

      int size;

      size = read(STDIN_FILENO, str, sizeof(str));

      if(size < 0) {
         perror("error in reading");
         close(pipe1[1]);
         exit(2);
      }

      if(write(pipe1[1], str, size) != size) {
         perror("error in writing");
         exit(2);
      }
   }
}

void *worker1(void *ptr) {
   int size, count = 0;

   while(1) {
      size = read(pipe1[0], str, sizeof(str));

      if(size < 0) {
         perror("error in reading");
         close(pipe1[0]);
         close(pipe2[1]);
         exit(2);
      }

      write(STDOUT_FILENO, "\n\tIn worker 1...\n\tWorker 1 reads following string from user: ",sizeof("\n\tIn worker1...\n\tWorker 1 reads following string from user: "));
      write(STDOUT_FILENO, str, size) ;

      while(str[count] != '\n') // count number of characters in string
         {count++;}

      write(pipe2[1], &count, sizeof(count));

      count = 0;
   }
}


void *worker2(void *ptr) {

   int count = 0;
   while(1) {
      read(pipe2[0], &count, sizeof(count));
      printf("\n\tIn worker 2...\n\tNo of characters in the string are: %d\n", count);
      printf("\n");
      write(STDOUT_FILENO, "Input the string: ",sizeof("Input the string: "));
   }

}

int main() {
   pthread_t sid, uid, w1, w2;

   if(pipe(pipe1) == -1) {
      printf("First pipe error");
      exit(1);
   }

   if(pipe(pipe2) == -1) {
      printf("Second pipe error");
      exit(1);
   }

   pthread_create(&uid, NULL, user, NULL);
   pthread_create(&w1, NULL, worker1, NULL);
   pthread_create(&w2, NULL, worker2, NULL);

   pthread_join(uid, NULL);
   pthread_join(w1, NULL);
   pthread_join(w2, NULL);

   return 0;
}
