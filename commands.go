
// Code generated by commandgen.go; DO NOT EDIT.
// ts=2023-06-05 07:02:57.933696 +0000 UTC
// redisVer=7.0.11
package main

// RestrictedRWCommands lists commands that are not allowed for rw users
var RestrictedRWCommands = map[string]int{
	"acl": 0,
	"asking": 1,
	"auth": 2,
	"bgrewriteaof": 3,
	"bgsave": 4,
	"blmove": 5,
	"blmpop": 6,
	"blpop": 7,
	"brpop": 8,
	"brpoplpush": 9,
	"bzmpop": 10,
	"bzpopmax": 11,
	"bzpopmin": 12,
	"client": 13,
	"client-evict": 14,
	"cluster": 15,
	"cluster-config-epoch": 16,
	"cluster-failure-reports": 17,
	"command": 18,
	"config": 19,
	"debug": 20,
	"discard": 21,
	"exec": 22,
	"failover": 23,
	"flushall": 24,
	"flushdb": 25,
	"hello": 26,
	"info": 27,
	"lastsave": 28,
	"latency": 29,
	"migrate": 30,
	"module": 31,
	"monitor": 32,
	"multi": 33,
	"pfdebug": 34,
	"pfselftest": 35,
	"psubscribe": 36,
	"psync": 37,
	"pubsub": 38,
	"punsubscribe": 39,
	"quit": 40,
	"readonly": 41,
	"readwrite": 42,
	"replconf": 43,
	"replicaof": 44,
	"reset": 45,
	"restore": 46,
	"restore-asking": 47,
	"role": 48,
	"save": 49,
	"select": 50,
	"shutdown": 51,
	"slaveof": 52,
	"slowlog": 53,
	"sort": 54,
	"sort_ro": 55,
	"spublish": 56,
	"ssubscribe": 57,
	"subscribe": 58,
	"sunsubscribe": 59,
	"swapdb": 60,
	"sync": 61,
	"unsubscribe": 62,
	"unwatch": 63,
	"wait": 64,
	"watch": 65,
	"xread": 66,
	"xreadgroup": 67,
}

// RestrictedROCommands lists commands that are not allowed for ro users
var RestrictedROCommands = map[string]int{
	"acl": 0,
	"asking": 1,
	"auth": 2,
	"bgrewriteaof": 3,
	"bgsave": 4,
	"blmove": 5,
	"blmpop": 6,
	"blpop": 7,
	"brpop": 8,
	"brpoplpush": 9,
	"bzmpop": 10,
	"bzpopmax": 11,
	"bzpopmin": 12,
	"client": 13,
	"client-evict": 14,
	"cluster": 15,
	"cluster-config-epoch": 16,
	"cluster-failure-reports": 17,
	"command": 18,
	"config": 19,
	"debug": 20,
	"discard": 21,
	"exec": 22,
	"failover": 23,
	"flushall": 24,
	"flushdb": 25,
	"hello": 26,
	"info": 27,
	"lastsave": 28,
	"latency": 29,
	"migrate": 30,
	"module": 31,
	"monitor": 32,
	"multi": 33,
	"pfdebug": 34,
	"pfselftest": 35,
	"psubscribe": 36,
	"psync": 37,
	"pubsub": 38,
	"punsubscribe": 39,
	"quit": 40,
	"readonly": 41,
	"readwrite": 42,
	"replconf": 43,
	"replicaof": 44,
	"reset": 45,
	"restore": 46,
	"restore-asking": 47,
	"role": 48,
	"save": 49,
	"select": 50,
	"shutdown": 51,
	"slaveof": 52,
	"slowlog": 53,
	"sort": 54,
	"sort_ro": 55,
	"spublish": 56,
	"ssubscribe": 57,
	"subscribe": 58,
	"sunsubscribe": 59,
	"swapdb": 60,
	"sync": 61,
	"unsubscribe": 62,
	"unwatch": 63,
	"wait": 64,
	"watch": 65,
	"xread": 66,
	"xreadgroup": 67,
}

// AllowedRWCommands lists all the commands allowed for rw users
var AllowedRWCommands = map[string]int{
	"append": 0,
	"bitcount": 1,
	"bitfield": 2,
	"bitfield_ro": 3,
	"bitop": 4,
	"bitpos": 5,
	"copy": 6,
	"dbsize": 7,
	"decr": 8,
	"decrby": 9,
	"del": 10,
	"dump": 11,
	"echo": 12,
	"eval": 13,
	"eval_ro": 14,
	"evalsha": 15,
	"evalsha_ro": 16,
	"exists": 17,
	"expire": 18,
	"expireat": 19,
	"expiretime": 20,
	"fcall": 21,
	"fcall_ro": 22,
	"function": 23,
	"geoadd": 24,
	"geodist": 25,
	"geohash": 26,
	"geopos": 27,
	"georadius": 28,
	"georadius_ro": 29,
	"georadiusbymember": 30,
	"georadiusbymember_ro": 31,
	"geosearch": 32,
	"geosearchstore": 33,
	"get": 34,
	"getbit": 35,
	"getdel": 36,
	"getex": 37,
	"getrange": 38,
	"getset": 39,
	"hdel": 40,
	"hexists": 41,
	"hget": 42,
	"hgetall": 43,
	"hincrby": 44,
	"hincrbyfloat": 45,
	"hkeys": 46,
	"hlen": 47,
	"hmget": 48,
	"hmset": 49,
	"hrandfield": 50,
	"hscan": 51,
	"hset": 52,
	"hsetnx": 53,
	"hstrlen": 54,
	"hvals": 55,
	"incr": 56,
	"incrby": 57,
	"incrbyfloat": 58,
	"keys": 59,
	"lcs": 60,
	"lindex": 61,
	"linsert": 62,
	"llen": 63,
	"lmove": 64,
	"lmpop": 65,
	"lolwut": 66,
	"lpop": 67,
	"lpos": 68,
	"lpush": 69,
	"lpushx": 70,
	"lrange": 71,
	"lrem": 72,
	"lset": 73,
	"ltrim": 74,
	"memory": 75,
	"memory-stats": 76,
	"mget": 77,
	"move": 78,
	"mset": 79,
	"msetnx": 80,
	"object": 81,
	"persist": 82,
	"pexpire": 83,
	"pexpireat": 84,
	"pexpiretime": 85,
	"pfadd": 86,
	"pfcount": 87,
	"pfmerge": 88,
	"ping": 89,
	"psetex": 90,
	"pttl": 91,
	"publish": 92,
	"randomkey": 93,
	"rename": 94,
	"renamenx": 95,
	"rpop": 96,
	"rpoplpush": 97,
	"rpush": 98,
	"rpushx": 99,
	"sadd": 100,
	"scan": 101,
	"scard": 102,
	"script": 103,
	"sdiff": 104,
	"sdiffstore": 105,
	"set": 106,
	"setbit": 107,
	"setex": 108,
	"setnx": 109,
	"setrange": 110,
	"sinter": 111,
	"sintercard": 112,
	"sinterstore": 113,
	"sismember": 114,
	"smembers": 115,
	"smismember": 116,
	"smove": 117,
	"spop": 118,
	"srandmember": 119,
	"srem": 120,
	"sscan": 121,
	"strlen": 122,
	"substr": 123,
	"sunion": 124,
	"sunionstore": 125,
	"time": 126,
	"touch": 127,
	"ttl": 128,
	"type": 129,
	"unlink": 130,
	"xack": 131,
	"xadd": 132,
	"xautoclaim": 133,
	"xclaim": 134,
	"xdel": 135,
	"xgroup": 136,
	"xinfo": 137,
	"xlen": 138,
	"xpending": 139,
	"xrange": 140,
	"xrevrange": 141,
	"xsetid": 142,
	"xtrim": 143,
	"zadd": 144,
	"zcard": 145,
	"zcount": 146,
	"zdiff": 147,
	"zdiffstore": 148,
	"zincrby": 149,
	"zinter": 150,
	"zintercard": 151,
	"zinterstore": 152,
	"zlexcount": 153,
	"zmpop": 154,
	"zmscore": 155,
	"zpopmax": 156,
	"zpopmin": 157,
	"zrandmember": 158,
	"zrange": 159,
	"zrangebylex": 160,
	"zrangebyscore": 161,
	"zrangestore": 162,
	"zrank": 163,
	"zrem": 164,
	"zremrangebylex": 165,
	"zremrangebyrank": 166,
	"zremrangebyscore": 167,
	"zrevrange": 168,
	"zrevrangebylex": 169,
	"zrevrangebyscore": 170,
	"zrevrank": 171,
	"zscan": 172,
	"zscore": 173,
	"zunion": 174,
	"zunionstore": 175,
}

// AllowedROCommands lists all the commands allowed for ro users
var AllowedROCommands = map[string]int{
	"bitcount": 0,
	"bitfield_ro": 1,
	"bitpos": 2,
	"dbsize": 3,
	"dump": 4,
	"echo": 5,
	"eval": 6,
	"eval_ro": 7,
	"evalsha": 8,
	"evalsha_ro": 9,
	"exists": 10,
	"expiretime": 11,
	"fcall": 12,
	"fcall_ro": 13,
	"geodist": 14,
	"geohash": 15,
	"geopos": 16,
	"georadius_ro": 17,
	"georadiusbymember_ro": 18,
	"geosearch": 19,
	"get": 20,
	"getbit": 21,
	"getrange": 22,
	"hexists": 23,
	"hget": 24,
	"hgetall": 25,
	"hkeys": 26,
	"hlen": 27,
	"hmget": 28,
	"hrandfield": 29,
	"hscan": 30,
	"hstrlen": 31,
	"hvals": 32,
	"lcs": 33,
	"lindex": 34,
	"llen": 35,
	"lolwut": 36,
	"lpos": 37,
	"lrange": 38,
	"memory": 39,
	"memory-stats": 40,
	"mget": 41,
	"object": 42,
	"pexpiretime": 43,
	"pfcount": 44,
	"ping": 45,
	"pttl": 46,
	"randomkey": 47,
	"scard": 48,
	"script": 49,
	"sdiff": 50,
	"sinter": 51,
	"sintercard": 52,
	"sismember": 53,
	"smembers": 54,
	"smismember": 55,
	"srandmember": 56,
	"sscan": 57,
	"strlen": 58,
	"substr": 59,
	"sunion": 60,
	"time": 61,
	"touch": 62,
	"ttl": 63,
	"type": 64,
	"xinfo": 65,
	"xlen": 66,
	"xpending": 67,
	"xrange": 68,
	"xrevrange": 69,
	"zcard": 70,
	"zcount": 71,
	"zdiff": 72,
	"zinter": 73,
	"zintercard": 74,
	"zlexcount": 75,
	"zmscore": 76,
	"zrandmember": 77,
	"zrange": 78,
	"zrangebylex": 79,
	"zrangebyscore": 80,
	"zrank": 81,
	"zrevrange": 82,
	"zrevrangebylex": 83,
	"zrevrangebyscore": 84,
	"zrevrank": 85,
	"zscan": 86,
	"zscore": 87,
	"zunion": 88,
}
