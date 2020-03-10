#ifdef DEBUG
# define DEBUG_PRINT(x) printf x
#else
# define DEBUG_PRINT(x) do {} while (0)
#endif

/* Hash to generate symmetric key from block (256 bits) */
#define _BLOCK_HASH		"SHA256"
#define _BLOCK_HASH_SIZE	32

/* Hash to produce challenge with (160 bits) */
#define _CHALLENGE_HASH		"SHA1"
#define _CHALLENGE_SIZE		20

/* Hash type and size for the auth buffer (512 bits) */
#define _AUTH_HASH		"SHA512"
#define _AUTH_SIZE		64

/* Symmetric cipher to use (256 bit key size, 128 bit IV size) */
#define _SYMMETRIC_CIPHER	"AES-256-CBC"