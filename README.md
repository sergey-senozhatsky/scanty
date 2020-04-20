# SCANTY

What is SCANTY? ``tl;dr;`` scanty is a POC "just for fun" project.


A slightly more detailed explanation:
Have you ever looked at lengthy C-header and source files with tens, if not hundreds, of ``struct``-s and ``union``-s
definitions and wondered if all of ``struct`` and ``union`` members are actually used in the code or are there any
abandoned members that simply add up to the sizeof() (IOW consume memory)? This question cannot be answered on a
per-translation unit basis. It requires analysis of the entire code base, of every header and source files. That's why
traditional compiler warnings don't help here - they work on a translation unit level. So how does scanty help then?

Scanty is a simple (POC WIP) tool chain, which consists of a GCC plugin, a trivial database and a simple database client
application. The plug-in does the bulk of the work, it walks GIMPLE tree, parses SSA, etc. and records (accounts) all
loads and stores to all struct-s and union-s members within the current translation unit. Once GCC is done compiling C
file, scanty prints recorded stats to stdout. Let's consider a simple example.

### Example
```C
// header file
struct rb_node {
        unsigned long  __rb_parent_color;
        struct rb_node *rb_right;
        struct rb_node *rb_left;
} __attribute__((aligned(sizeof(long))));

struct rb_root {
        struct rb_node *rb_node;
};

struct rb_root_cached {
        struct rb_root rb_root;
        struct rb_node *rb_leftmost;
};

#define INIT_CACHE(r)                           \
        do {                                    \
                (r).rb_leftmost         = NULL; \
                (r).rb_root.rb_node     = NULL; \
        } while (0)

// source file
int main()
{
        struct rb_root_cached rb;

        INIT_CACHE(rb);
        return 0;
}
```
When compiled with ``gcc -fplugin=${LIB_PATH}/libscanty.so -c ....``
```
[plugin/26877]: INFO:                     struct rb_root_cached
[plugin/26877]: INFO: ld:0     st:1          field rb_leftmost
[plugin/26877]: INFO:                        struct rb_root
[plugin/26877]: INFO: ld:0     st:1              field rb_node
[plugin/26877]: INFO: ---------------------------------------------
```

The format is pretty easy to follow. Sort of. ``ld:`` is the number of loads (reads), ``st:`` is the number
of stores (writes). From the output we can see that scanty recorded 1 store to ``rb_leftmost`` member of
``rb_root_cached`` and one store to ``rb_node`` member of ``rb_root``, which is a member of ``rb_root_cached``.
This means that scanty also "unfolds" struct-s and uninon-s -- it recursively walks struct and union members
of struct-s and union-s. This feature seems to be quite useful. In highly configurable, multi architecture,
large code base struct-s and union-s can contain numerous ``#ifdef``-s and tweaks, so it might be hard to
tell what's being used and what is pre-processed away. For instance, Linux kernel ``spinlock_t`` on my
x86_64 config contains the following members:

```C
[client/20403]: INFO:                     struct spinlock_t
[client/20403]: INFO:                        union  <anon::0x54e60731494082ef>
[client/20403]: INFO:                            struct raw_spinlock
[client/20403]: INFO:                                struct arch_spinlock_t
[client/20403]: INFO:                                    union  <anon::0xd3a531dd9e7370c>
[client/20403]: INFO:                                        struct <anon::0x312a9e3d6c3ffb3b>
[client/20403]: INFO: ld:0     st:0                              field tail
[client/20403]: INFO: ld:0     st:0                              field locked_pending
[client/20403]: INFO:                                        struct <anon::0xb86bdadc37b45d2c>
[client/20403]: INFO: ld:0     st:0                              field pending
[client/20403]: INFO: ld:0     st:0                              field locked
[client/20403]: INFO:                                        struct atomic_t
[client/20403]: INFO: ld:0     st:0                              field counter
```

Exploring those things is pretty fun. Scanty sees exact struct-s and union-s, after all the pre-processing and
ifdef-ery magic.

One might have noticed those <anon::hex> members. For anon struct-s and union-s scanty generates dummy names,
so it can distinguish multiple anon members on the same levels of nesting. Note that members are not shown in
the order they are appear in corresponding header or source files (this needs to be fixed).

That concludes "what is scanty" introduction.

### Tool chain

As already was mentioned, scanty consists of
- plugin
- trivial database
- simple client

Plugin works on translation unit level (just like the compiler), it can record only loads and stores which are
accessible to it at the memont (via GCC GIMPLE trees). Thus on a large code base scanty needs to accumulate all
all stats in order to provide more or less full picture. E.g. suppose file a.c writes to member ``a`` of struct
``foo``, file b.c write to member ``b`` of struct ``foo`` and reads from member ``a``. To get full picture we
need to merge stats of both source files. Database to the rescue. When GCC is about to finish source file
compilation scanty will push recorded stats to scanty database. Database will parse stats and either create
new types or update load/store counters if the type is already known. Easy to guess that scanty client is a
small tool that reads data from scanty database.

By default scanty plugin does not push stats to the database, but dumps them to stdout instead.

### Configuration

Scanty plugin, database and client share a lot of code and thus use same env variables for configuration:

-- SCANTY_DB_BACKEND    = 1  
When this env variable set, scanty plugin will attempt to store stats in the database. Needless to mention
that database should be running and should be accessible to scanty plugin.

-- SCANTY_DB_HOST       = <host>  
Host on which dabatase is running. Default is localhost (127.0.0.1)

-- SCANTY_DB_PORT       = <port>  
Port number database is listening on. Default is 22122


### Example
```sh
$ ./db/scantydb
[db/56143]: INFO: Starting scantydb on 127.0.0.1 : 22122
```
run tests and store stats in database
```sh
$ SCANTY_DB_BACKEND=1 ./t/test.sh 7
$ SCANTY_DB_BACKEND=1 ./t/test.sh 5
```
read accumulated (merged) stats
```
$ ./client/scantyclient
[client/58244]: INFO:                     struct foo
[client/58244]: INFO: ld:1     st:1          field buzz
[client/58244]: INFO: ld:3     st:3          field bar
[client/58244]: INFO: ---------------------------------------------
[client/58244]: INFO:                     struct rb_root_cached
[client/58244]: INFO: ld:0     st:1          field rb_leftmost
[client/58244]: INFO:                        struct rb_root
[client/58244]: INFO: ld:0     st:1              field rb_node
[client/58244]: INFO: ---------------------------------------------
```

Time to introduce scanty client tool.

```sh
$ scantyclient -h
[client/71478]: INFO: Usage: scantyclient [-c CMD [options]]
[client/71478]: INFO: 	-c|--command $CMD	request command
[client/71478]: INFO: 		0		print db contents (stdout)
[client/71478]: INFO: 		1		print particular type stats
[client/71478]: INFO: 		2		save database to a file
[client/71478]: INFO: 		3		load database from a file
[client/71478]: INFO: 		4		debug database dump on the server (stdout)
[client/71478]: INFO: 	-f|--file $NAME		db file name
[client/71478]: INFO: 	-t|--type $NAME		declaration type
[client/71478]: INFO: 	-h|--help		print this message
```

When executed without parameters ``$ scantyclient`` or with ``$ scantyclient -c 0`` command, scanty client will
print contents of the database to stdout. Depending on the code base size this can be thousands of lines,
therefore scanty client has an option to lookup and print only particular type ``$ scantyclient -c 1 -t $TYPE_NAME``.
Commands ``-c 2 -f $FILE_NAME`` and ``-c 3 -f $FILE_NAME`` will save contents of scanty database to a file or
load database from a file correspondingly.

## TODO

There are too many things TODO, hardly can even list all of them:
- take a look at t/test10.c and run ``t/test.sh 10`` to get some idea about what's missing, functionality-wise
- bug fixes, bug fixes, bug fixes
- ...
- profit

For the time being scanty implementation is rather trivial. It *does only 20-25% of what is needed* in order
to achieve its goal. I'd say that 100% coverage of all of the cases is hardly reachable at all. A more feasible
target is to be just "good enough".
