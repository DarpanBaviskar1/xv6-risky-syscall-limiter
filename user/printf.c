#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/budget.h"
#include "user/user.h"

#include <stdarg.h>

static char digits[] = "0123456789ABCDEF";

// One output destination for the formatter. Either a file descriptor -- where
// each character becomes its own write() call, the historical xv6 behaviour
// and the one the budget charges for -- or a caller-supplied buffer.
struct sink {
  int fd; // >= 0 to emit to a descriptor, -1 to emit to buf
  char *buf;
  int pos; // characters produced, including ones a too-small buf dropped
  int cap;
};

static void
putc(struct sink *s, char c)
{
  if (s->fd >= 0) {
    write(s->fd, &c, 1);
    s->pos++;
    return;
  }
  if (s->pos + 1 < s->cap) // keep a slot for the nul
    s->buf[s->pos] = c;
  s->pos++;
}

static void
printint(struct sink *s, long long xx, int base, int sgn)
{
  char buf[20];
  int i, neg;
  unsigned long long x;

  neg = 0;
  if (sgn && xx < 0) {
    neg = 1;
    x = -xx;
  } else {
    x = xx;
  }

  i = 0;
  do {
    buf[i++] = digits[x % base];
  } while ((x /= base) != 0);
  if (neg)
    buf[i++] = '-';

  while (--i >= 0)
    putc(s, buf[i]);
}

static void
printptr(struct sink *s, uint64 x)
{
  int i;
  putc(s, '0');
  putc(s, 'x');
  for (i = 0; i < (sizeof(uint64) * 2); i++, x <<= 4)
    putc(s, digits[x >> (sizeof(uint64) * 8 - 4)]);
}

// Only understands %d, %x, %p, %c, %s and the l/ll length prefixes. Widths and
// flags are NOT supported: a %3d is printed literally to draw attention.
static void
vfmt(struct sink *s, const char *fmt, va_list ap)
{
  char *str;
  int c0, c1, c2, i, state;

  state = 0;
  for (i = 0; fmt[i]; i++) {
    c0 = fmt[i] & 0xff;
    if (state == 0) {
      if (c0 == '%') {
        state = '%';
      } else {
        putc(s, c0);
      }
    } else if (state == '%') {
      c1 = c2 = 0;
      if (c0)
        c1 = fmt[i + 1] & 0xff;
      if (c1)
        c2 = fmt[i + 2] & 0xff;
      if (c0 == 'd') {
        printint(s, va_arg(ap, int), 10, 1);
      } else if (c0 == 'l' && c1 == 'd') {
        printint(s, va_arg(ap, uint64), 10, 1);
        i += 1;
      } else if (c0 == 'l' && c1 == 'l' && c2 == 'd') {
        printint(s, va_arg(ap, uint64), 10, 1);
        i += 2;
      } else if (c0 == 'u') {
        printint(s, va_arg(ap, uint32), 10, 0);
      } else if (c0 == 'l' && c1 == 'u') {
        printint(s, va_arg(ap, uint64), 10, 0);
        i += 1;
      } else if (c0 == 'l' && c1 == 'l' && c2 == 'u') {
        printint(s, va_arg(ap, uint64), 10, 0);
        i += 2;
      } else if (c0 == 'x') {
        printint(s, va_arg(ap, uint32), 16, 0);
      } else if (c0 == 'l' && c1 == 'x') {
        printint(s, va_arg(ap, uint64), 16, 0);
        i += 1;
      } else if (c0 == 'l' && c1 == 'l' && c2 == 'x') {
        printint(s, va_arg(ap, uint64), 16, 0);
        i += 2;
      } else if (c0 == 'p') {
        printptr(s, va_arg(ap, uint64));
      } else if (c0 == 'c') {
        putc(s, va_arg(ap, uint32));
      } else if (c0 == 's') {
        if ((str = va_arg(ap, char *)) == 0)
          str = "(null)";
        for (; *str; str++)
          putc(s, *str);
      } else if (c0 == '%') {
        putc(s, '%');
      } else {
        // Unknown % sequence.  Print it to draw attention.
        putc(s, '%');
        putc(s, c0);
      }

      state = 0;
    }
  }
}

void
vprintf(int fd, const char *fmt, va_list ap)
{
  struct sink s = {fd, 0, 0, 0};
  vfmt(&s, fmt, ap);
}

void
fprintf(int fd, const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(fd, fmt, ap);
}

void
printf(const char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vprintf(1, fmt, ap);
}

// Format into buf of size sz. Returns the length the text WOULD have needed;
// anything past sz-1 is dropped, so callers that must not lose output should
// check the return value against sz.
int
snprintf(char *buf, int sz, const char *fmt, ...)
{
  va_list ap;
  struct sink s = {-1, buf, 0, sz};

  if (sz <= 0)
    return 0;
  va_start(ap, fmt);
  vfmt(&s, fmt, ap);
  buf[s.pos + 1 <= sz ? s.pos : sz - 1] = 0;
  return s.pos;
}

#define RBUF 1024

// Format, then emit through the free reporting path in chunks. Costs no
// budget, which is the point: a throttled process must still be able to say
// it was throttled. Text longer than RBUF loses its tail.
void
rprintf(const char *fmt, ...)
{
  static char buf[RBUF];
  va_list ap;
  struct sink s = {-1, buf, 0, RBUF};
  int off;

  va_start(ap, fmt);
  vfmt(&s, fmt, ap);
  // pos counts everything produced, including bytes past the buffer; the
  // stored text is at most RBUF-1 bytes long.
  if (s.pos > RBUF - 1)
    s.pos = RBUF - 1;
  buf[s.pos] = 0;

  for (off = 0; off < s.pos; off += REPORT_MAX) {
    int n = s.pos - off;
    if (n > REPORT_MAX)
      n = REPORT_MAX;
    if (report(buf + off, n) < 0)
      break;
  }
}
