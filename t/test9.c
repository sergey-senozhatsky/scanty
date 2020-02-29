struct rw_semaphore {
	int dummy;
};

struct key_user;

struct rb_node {
	struct rb_node *left, *right;
	void *value;
};

struct list_head {
	struct list_head *prev, *next;
};

struct keyring_index_key {
	int value;
};

union key_payload {
	void *__rcu_data;
	void *data[4];
};

struct assoc_ptr;

struct assoc_array {
	struct assoc_ptr *root;
	int value;
};

typedef int key_serial_t;
typedef int atomic_t;
typedef int refcount_t;
typedef int kuid_t;
typedef int kgid_t;
typedef int key_perm_t;
typedef unsigned long long time64_t;

struct key {
	refcount_t		usage;		/* number of references */
	key_serial_t		serial;		/* key serial number */
	union {
		struct list_head graveyard_link;
		struct rb_node	serial_node;
	};
#ifdef CONFIG_KEY_NOTIFICATIONS
	struct watch_list	*watchers;	/* Entities watching this key for changes */
#endif
	struct rw_semaphore	sem;		/* change vs change sem */
	struct key_user		*user;		/* owner of this key */
	void			*security;	/* security data for this key */
	union {
		time64_t	expiry;		/* time at which key expires (or 0) */
		time64_t	revoked_at;	/* time at which key was revoked */
	};
	time64_t		last_used_at;	/* last time used for LRU keyring discard */
	kuid_t			uid;
	kgid_t			gid;
	key_perm_t		perm;		/* access permissions */
	unsigned short		quotalen;	/* length added to quota */
	unsigned short		datalen;	/* payload data length
						 * - may not match RCU dereferenced payload
						 * - payload should contain own length
						 */
	short			state;		/* Key state (+) or rejection error (-) */

#ifdef KEY_DEBUGGING
	unsigned		magic;
#define KEY_DEBUG_MAGIC		0x18273645u
#endif

	unsigned long		flags;		/* status flags (change with bitops) */
#define KEY_FLAG_DEAD		0	/* set if key type has been deleted */
#define KEY_FLAG_REVOKED	1	/* set if key had been revoked */
#define KEY_FLAG_IN_QUOTA	2	/* set if key consumes quota */
#define KEY_FLAG_USER_CONSTRUCT	3	/* set if key is being constructed in userspace */
#define KEY_FLAG_ROOT_CAN_CLEAR	4	/* set if key can be cleared by root without permission */
#define KEY_FLAG_INVALIDATED	5	/* set if key has been invalidated */
#define KEY_FLAG_BUILTIN	6	/* set if key is built in to the kernel */
#define KEY_FLAG_ROOT_CAN_INVAL	7	/* set if key can be invalidated by root without permission */
#define KEY_FLAG_KEEP		8	/* set if key should not be removed */
#define KEY_FLAG_UID_KEYRING	9	/* set if key is a user or user session keyring */

	/* the key type and key description string
	 * - the desc is used to match a key against search criteria
	 * - it should be a printable string
	 * - eg: for krb5 AFS, this might be "afs@REDHAT.COM"
	 */
	union {
		struct keyring_index_key index_key;
		struct {
			unsigned long	hash;
			unsigned long	len_desc;
			struct key_type	*type;		/* type of key */
			struct key_tag	*domain_tag;	/* Domain of operation */
			char		*description;
		};
	};

	/* key data
	 * - this is used to hold the data actually used in cryptography or
	 *   whatever
	 */
	union {
		union key_payload payload;
		struct {
			/* Keyring bits */
			struct list_head name_link;
			struct assoc_array keys;
		};
	};

	/* This is set on a keyring to restrict the addition of a link to a key
	 * to it.  If this structure isn't provided then it is assumed that the
	 * keyring is open to any addition.  It is ignored for non-keyring
	 * keys. Only set this value using keyring_restrict(), keyring_alloc(),
	 * or key_alloc().
	 *
	 * This is intended for use with rings of trusted keys whereby addition
	 * to the keyring needs to be controlled.  KEY_ALLOC_BYPASS_RESTRICTION
	 * overrides this, allowing the kernel to add extra keys without
	 * restriction.
	 */
	struct key_restriction *restrict_link;
};

int main()
{
	struct key k = {0, };

	k.len_desc = 111;
	return 0;
}
