#include "diskplan_test_support.h"

#include <unistd.h>

pid_t diskplan_test_fork_and_pause(void) {
  pid_t process_id = fork();
  if (process_id != 0) {
    return process_id;
  }
  for (;;) {
    (void)pause();
  }
}
