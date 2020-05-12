-- module containing waflz to be used

local ffi = require("ffi")

ffi.cdef[[

typedef struct waflz_profile_t waflz_profile_t;
typedef struct waflz_transaction_t waflz_transaction_t;

waflz_profile_t* waflz_profile_new_load(const char* rule_dir, const char* profile_file_name);
int waflz_profile_process(waflz_transaction_t* tx);
void waflz_profile_clean(waflz_profile_t* wp);

waflz_transaction_t *waflz_new_transaction(waflz_profile_t *profile);
int waflz_transaction_add_connection(waflz_transaction_t *t, const char *client_ip, const char *host, int port, const char* method, const char *scheme);
int waflz_transaction_add_uri(waflz_transaction_t *t, const char *url, const char *uri, const char *path, const char *query, const char *protocol, const char *http_version);
int waflz_transaction_add_request_header(waflz_transaction_t *transaction, const char *key, const char *value);
void waflz_transaction_clean(waflz_transaction_t *transaction);

]]

--local waflz = ffi.load("/usr/local/waflz/lib/libwaflzts.so")
local waflz = ffi.load("./libwaflzts.so.0")

return waflz
