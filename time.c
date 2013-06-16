#include "h/struct.h"
#include "h/proto.h"

#ifdef __APPLE__
#	include<sys/time.h>
#endif 
#include <stdio.h>
#include <limits.h>
#include <assert.h>


/**
 * It seems that cats' OSes cannot provide non-decreasing time. :-(
 * Good job Mr. Jobs.
 */
#ifdef __APPLE__
static long long get_uptime(void)
{
	struct timeval tmval;
	if (gettimeofday(&tmval, NULL) == -1) {
		return 0LL;
	}
	return (long long)(tmval.tv_sec*1000LL + tmval.tv_usec/1000);
}
#else
/**
 * Time that is provided with gettimeofday(.) can be decreasing.
 *   Let's have a look at /proc/... .
 */
static long long get_uptime(void)
{
	static const char file_name[] = "/proc/uptime";
	double duptime;
	FILE *f = fopen(file_name, "r");
	if (!f)
		return 0ULL;
	const int ret = fscanf(f, "%lf", &duptime);
        fclose(f);
        if (ret != 1)
		return 0ULL;
	return (long long)(duptime * 1000.0);
}
#endif

static long long birth;
static void init_birth(void) __attribute__ ((constructor));
static void init_birth(void)
{
	birth = get_uptime();
}

/**
 * vrati pocet milisekund od spusteni programu
 */
int get_time_int(void)
{
	const long long now = get_uptime();
	assert(birth <= now);
	assert(now - birth < INT_MAX);
	return now != birth ? (int)(now - birth) : 1;
}

/**
 * Let's use some good hash function.
 *   Good hashing is important, otherwise we will perform
 *   redundant waiting.
 */
static unsigned hash_uns(const unsigned key)
{
	return 13*(key >> 16 | key << 16) ^ 113*(key >> 20 | key << 10) ^ key;
}

#define HASH_SIZE 64
int hash_table[] = { [0 ... (HASH_SIZE - 1)]=INT_MIN, };

/**
 * Returns slot that is assigned to the supplied key.
 */
unsigned get_time_slot(const unsigned key)
{
	return hash_uns(key) % HASH_SIZE;
}

/**
 * Returns hash item that is assigned to the supplied key.
 */
static int *get_hash_item(const unsigned key)
{
	return &hash_table[get_time_slot(key)];
}

/**
 * Calculates slot that is assigned to the particular ip.
 * If the slot is free, then actual time is assigned to it and the time is returned.
 * Zero is returned otherwise.
 */
int test_free_channel(const unsigned u_ip, const unsigned milis, const int force)
{
	const int now = get_time_int();
	int *slot = get_hash_item(u_ip);
	debugf("%d; 0x%x => %d [%p]\n", now, u_ip, (int)milis <= 0 || *slot + (int)milis <= now, slot);
	if (force || (int)milis <= 0 || *slot + (int)milis <= now) {
		return *slot = now;
	}
        else {
		return 0;
	}
}
