/**********************************************************\
|                                                          |
| main.c                                                   |
|                                                          |
| XXTEA image encrypt/decrypt tool.                        |
|                                                          |
| Recursively processes .png/.jpg/.jpeg files in a        |
| directory, encrypting or decrypting them with XXTEA.     |
| Encrypted files are marked with a magic header.         |
|                                                          |
| Usage: encode-png encrypt <dir> <key>                    |
|        encode-png decrypt <dir> <key>                    |
|                                                          |
\**********************************************************/

#include "xxtea.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Magic header written before encrypted data so we can identify
   which files have been encrypted. 4 bytes + 1 byte version. */
#define MAGIC_HEADER "ENCP"
#define MAGIC_HEADER_LEN 4
#define MAGIC_VERSION 1

enum cli_mode {
    CLI_MODE_ENCRYPT,
    CLI_MODE_DECRYPT
};

static const char *program_name;

/* ── helpers ────────────────────────────────────────── */

static int is_image_file(const char *name) {
    const char *ext = strrchr(name, '.');
    if (!ext) return 0;
    return (strcasecmp(ext, ".png") == 0 ||
            strcasecmp(ext, ".jpg") == 0 ||
            strcasecmp(ext, ".jpeg") == 0);
}

static int has_magic_header(const unsigned char *data, size_t len) {
    if (len < MAGIC_HEADER_LEN + 1) return 0;
    if (memcmp(data, MAGIC_HEADER, MAGIC_HEADER_LEN) != 0) return 0;
    return (data[MAGIC_HEADER_LEN] == MAGIC_VERSION);
}

/* Read a file into a malloc'd buffer.  Returns NULL on error. */
static unsigned char *read_file(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    /* Get file size */
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return NULL;
    }
    rewind(fp);

    unsigned char *buf = (unsigned char *)malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t nread = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);

    if ((long)nread != sz) {
        free(buf);
        return NULL;
    }

    *out_len = (size_t)sz;
    return buf;
}

/* Write data to a file, overwriting.  Returns 0 on success. */
static int write_file(const char *path, const unsigned char *data, size_t len) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;

    size_t nwritten = fwrite(data, 1, len, fp);
    fclose(fp);

    return (nwritten == len) ? 0 : -1;
}

/* ── encrypt / decrypt a single file ────────────────── */

static int process_file_encrypt(const char *path, const char *key) {
    size_t orig_len;
    unsigned char *orig = read_file(path, &orig_len);
    if (!orig) {
        fprintf(stderr, "error: cannot read '%s': %s\n", path, strerror(errno));
        return -1;
    }

    size_t enc_len;
    void *enc = xxtea_encrypt(orig, orig_len, key, &enc_len);
    if (!enc) {
        fprintf(stderr, "error: xxtea_encrypt failed on '%s'\n", path);
        free(orig);
        return -1;
    }
    free(orig);

    /* Build output: magic header (4 bytes) + version (1 byte) + encrypted data. */
    size_t out_len = MAGIC_HEADER_LEN + 1 + enc_len;
    unsigned char *out = (unsigned char *)malloc(out_len);
    if (!out) {
        fprintf(stderr, "error: out of memory\n");
        free(enc);
        return -1;
    }

    memcpy(out, MAGIC_HEADER, MAGIC_HEADER_LEN);
    out[MAGIC_HEADER_LEN] = MAGIC_VERSION;
    memcpy(out + MAGIC_HEADER_LEN + 1, enc, enc_len);
    free(enc);

    int ret = write_file(path, out, out_len);
    free(out);

    if (ret != 0) {
        fprintf(stderr, "error: cannot write '%s': %s\n", path, strerror(errno));
        return -1;
    }

    printf("encrypted: %s\n", path);
    return 0;
}

static int process_file_decrypt(const char *path, const char *key) {
    size_t enc_len;
    unsigned char *enc = read_file(path, &enc_len);
    if (!enc) {
        fprintf(stderr, "error: cannot read '%s': %s\n", path, strerror(errno));
        return -1;
    }

    /* Skip files that don't carry the magic header. */
    if (!has_magic_header(enc, enc_len)) {
        free(enc);
        return 0;  /* silently skip */
    }

    /* Strip header+version: feed the raw encrypted payload to xxtea_decrypt. */
    size_t payload_len = enc_len - MAGIC_HEADER_LEN - 1;
    void *dec = xxtea_decrypt(enc + MAGIC_HEADER_LEN + 1, payload_len, key, &enc_len);
    if (!dec) {
        fprintf(stderr, "error: xxtea_decrypt failed on '%s' (wrong key?)\n", path);
        free(enc);
        return -1;
    }
    free(enc);

    int ret = write_file(path, (const unsigned char *)dec, enc_len);
    free(dec);

    if (ret != 0) {
        fprintf(stderr, "error: cannot write '%s': %s\n", path, strerror(errno));
        return -1;
    }

    printf("decrypted: %s\n", path);
    return 0;
}

/* ── directory traversal ────────────────────────────── */

static int traverse(const char *dir_path, int mode, const char *key) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "error: cannot open directory '%s': %s\n",
                dir_path, strerror(errno));
        return -1;
    }

    int err_count = 0;
    struct dirent *entry;

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path.  PATH_MAX should be plenty. */
        char full_path[4096];
        int n = snprintf(full_path, sizeof(full_path), "%s/%s",
                         dir_path, entry->d_name);
        if (n < 0 || (size_t)n >= sizeof(full_path)) {
            fprintf(stderr, "warning: path too long, skipping '%s/%s'\n",
                    dir_path, entry->d_name);
            continue;
        }

        struct stat st;
        if (stat(full_path, &st) != 0) continue;

        if (S_ISDIR(st.st_mode)) {
            /* Recurse into subdirectories. */
            err_count += traverse(full_path, mode, key);
        } else if (S_ISREG(st.st_mode) && is_image_file(entry->d_name)) {
            int rc;
            if (mode == CLI_MODE_ENCRYPT)
                rc = process_file_encrypt(full_path, key);
            else
                rc = process_file_decrypt(full_path, key);
            if (rc != 0) err_count++;
        }
    }

    closedir(dir);
    return err_count;
}

/* ── CLI ────────────────────────────────────────────── */

static void print_usage(void) {
    fprintf(stderr, "Usage: %s encrypt <dir> <key>\n", program_name);
    fprintf(stderr, "       %s decrypt <dir> <key>\n", program_name);
}

static int parse_mode(const char *value, enum cli_mode *mode) {
    if (strcmp(value, "encrypt") == 0) {
        *mode = CLI_MODE_ENCRYPT;
        return 0;
    }
    if (strcmp(value, "decrypt") == 0) {
        *mode = CLI_MODE_DECRYPT;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    enum cli_mode mode;

    program_name = argv[0];

    if (argc != 4) {
        print_usage();
        return 1;
    }

    if (parse_mode(argv[1], &mode) != 0) {
        fprintf(stderr, "error: unknown command '%s' (expected encrypt|decrypt)\n",
                argv[1]);
        print_usage();
        return 1;
    }

    const char *dir   = argv[2];
    const char *key   = argv[3];

    /* Validate key is not empty. */
    if (strlen(key) == 0) {
        fprintf(stderr, "error: key cannot be empty\n");
        return 1;
    }

    /* Check directory exists. */
    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "error: '%s' is not a valid directory\n", dir);
        return 1;
    }

    int err_count = traverse(dir, mode, key);

    if (err_count > 0) {
        fprintf(stderr, "completed with %d error(s)\n", err_count);
        return 1;
    }

    return 0;
}
