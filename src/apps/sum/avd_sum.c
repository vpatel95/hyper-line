#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <inttypes.h>

int processed = 0;

int32_t add_three(FILE *in, FILE *op, int32_t offset) {
    int32_t     i = 0, rc;
    size_t      len;
    char        *line = NULL;
    if (in == NULL || op == NULL) {
        return EXIT_FAILURE;
    }

    fseek(in, offset, SEEK_SET);

    while (i < 500) {
        rc = getline(&line, &len, in);
        if (rc < 0) {
            fflush(op);
            return 0;
        }
        fprintf(op, "%d\n", atoi(line)+3);
        i++;
    }
    fflush(op);
    return (int32_t)(ftell(in));
}

int32_t mul_three(FILE *in, FILE *op, int32_t offset) {
    (void)(offset);
    int32_t     rc;
    size_t      len;
    char        *line = NULL;
    if (in == NULL || op == NULL) {
        return EXIT_FAILURE;
    }

    while (0 < (rc = getline(&line, &len, in))) {
        fprintf(op, "%d\n", atoi(line)*3);
    }
    fflush(op);

    return 0;
}

int32_t mul_ten(FILE *in, FILE *op, int32_t offset) {
    (void)(offset);
    int32_t     rc;
    size_t      len;
    char        *line = NULL;
    if (in == NULL || op == NULL) {
        return EXIT_FAILURE;
    }

    while (0 < (rc = getline(&line, &len, in))) {
        fprintf(op, "%d\n", atoi(line)*10);
    }
    fflush(op);

    return 0;
}
