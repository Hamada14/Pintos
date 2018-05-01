#ifndef THREADS_SYNCH_H
#define THREADS_SYNCH_H

#include <list.h>
#include <stdbool.h>

#define max(n1, n2) ((n1) > (n2) ? (n1) : (n2))
#define min(n1, n2) ((n1) < (n2) ? (n1) : (n2))
#define NESTED_DONATION_MAX_DEPTH 8

/* A counting semaphore. */
struct semaphore {
  unsigned value;      /* Current value. */
  struct list waiters; /* List of waiting threads. */

  int is_lock; /* True in case the semaphore is actually a lock */
  int priority; /* Inherited priority in case of a lock */

  struct list_elem thread_key; /* List element used by threads to obtain a list of acquired locks by a thread based
                                    on the assumption that a lock is only acquired by one thread */

  struct thread *holder; /* Holder of the semaphore */
};

void sema_init(struct semaphore *, unsigned value);
void sema_down(struct semaphore *);
bool sema_try_down(struct semaphore *);
void sema_up(struct semaphore *);
void sema_self_test(void);

void execute_priority_donation(struct thread *, struct semaphore *);
bool thread_priority_comp_block(const struct list_elem *,const struct list_elem *, void * UNUSED);

/* Lock. */
struct lock {
  struct thread *holder;      /* Thread holding lock (for debugging). */
  struct semaphore semaphore; /* Binary semaphore controlling access. */
};

void lock_init(struct lock *);
void lock_acquire(struct lock *);
bool lock_try_acquire(struct lock *);
void lock_release(struct lock *);
bool lock_held_by_current_thread(const struct lock *);

/* Condition variable. */
struct condition {
  struct list waiters; /* List of waiting threads. */
};

void cond_init(struct condition *);
void cond_wait(struct condition *, struct lock *);
void cond_signal(struct condition *, struct lock *);
void cond_broadcast(struct condition *, struct lock *);

bool semaphore_comp(
    const struct list_elem *, const struct list_elem *,
    void *); /* Comparator to find the minimum Semaphore based on the waiters */

/* Optimization barrier.

   The compiler will not reorder operations across an
   optimization barrier.  See "Optimization Barriers" in the
   reference guide for more information.*/
#define barrier() asm volatile("" : : : "memory")

#endif /* threads/synch.h */
