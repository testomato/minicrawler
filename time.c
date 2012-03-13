#include "h/global.h"
#include "h/struct.h"
#include "h/proto.h"

#include <stdio.h>
#include <limits.h>
#include <assert.h>

static long long get_uptime(void)
{
	static const char file_name[] = "/proc/uptime";
	float fuptime;
	FILE *f = fopen(file_name, "r");
	if (!f)
		return 0ULL;
	const int ret = fscanf(f, "%f", &fuptime);
        fclose(f);
        if (ret != 1)
		return 0ULL;
	return (long long)(fuptime * 1000.0);
}

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

static unsigned hash_uns(const unsigned key)
{
	return 13*(key >> 16 | key << 16) ^ 113*(key >> 20 | key << 10) ^ key;
/*
	// See: http://www.concentric.net/~ttwang/tech/inthash.htm
	unsigned key = input_key;
	key = ~key + (key << 15); // key = (key << 15) - key - 1;
	key = key ^ (key >> 12);
	key = key + (key << 2);
	key = key ^ (key >> 4);
	key = key * 2057; // key = (key + (key << 3)) + (key << 11);
	key = key ^ (key >> 16);
	return key;
*/
}

#define HASH_SIZE 64
int hash_table[] = { [0 ... (HASH_SIZE - 1)]=INT_MIN, };

unsigned get_time_slot(const unsigned key)
{
	return hash_uns(key) % HASH_SIZE;
}

static int *get_hash_item(const unsigned key)
{
	return &hash_table[get_time_slot(key)];
}

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
