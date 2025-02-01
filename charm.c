#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>



//////////// UTILS ///////////////

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

static void *mustmalloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        exit(1);
    }
    return ptr;
}

//////////// ARG PARSING ////////////

struct Args {
    const char *input_file_path;
    const char *output_file_path;
};

static void print_usage()
{
    printf("Usage: charm [options] <input_file> <output_file>\n");
    printf("Options:\n");
    printf("  -h, --help     Display this help message\n");
    printf("  -v, --version  Display version information\n");
}

static void parse_args(int argc, char *argv[], struct Args *arguments)
{
    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage();
            exit(0);
        }
    }

    if (argc < 3) {
        printf("Error: Missing input and/or output file.\n");
        print_usage();
        exit(-1);
    }

    arguments->input_file_path = argv[1];
    arguments->output_file_path = argv[2];
}

static void read_file(const char *path, char **contents)
{
    FILE *file = fopen(path, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Failed to open file '%s'\n", path);
        exit(1);
    }

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    rewind(file);

    *contents = mustmalloc(file_size + 1);
    fread(*contents, 1, file_size, file);
    (*contents)[file_size] = '\0';
    fclose(file);
}

//////////// CODE GENERATION ////////////

enum Opcode {
    NOP, ADD, MOV, B
};

//////////// CODE PARSING ////////////

static bool emit_error(int lineidx, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "Error, at line %d\n", lineidx);
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);

    return false;
}

static const char *skip_whitespace(const char *line)
{
    while (*line && isspace(*line))
        line++;
    return line;
}

static bool consume(const char **line, const char *str)
{
    if (strncmp(*line, str, strlen(str)) == 0) {
        *line += strlen(str);
        return true;
    }
    return false;
}

/**
 * Extracts an identifier from the input string and advances the pointer.
 *
 * An identifier is defined as a sequence of alphanumeric characters
 * and underscores, starting with an alphabetic character or an underscore.
 * If a valid identifier is found, this function allocates memory for the
 * identifier string, copies it, and updates the input pointer to point to
 * the character immediately after the identifier.
 *
 * @param line Pointer to the input string. This pointer is advanced past
 *             the identifier if one is successfully consumed.
 * @param str  Pointer to a string where the extracted identifier will be
 *             stored. Memory is allocated for this string, and the caller
 *             is responsible for freeing it.
 *
 * @return 0 on success, indicating that an identifier was found and extracted.
 *         -1 on failure, indicating that no valid identifier was found
 *         at the current position in the input string.
 */
static bool consume_identifier(const char **line, char **str)
{
#define is_valid_identifier_char(c) (isalnum(c) || (c) == '_' || (c) == '.')
    const char *start = *line;

    // We don't want identifiers to start with a digit, otherwise
    // they become ambiguous with numbers
    if (!is_valid_identifier_char(*start) || isdigit(*start))
        return false;
    
    // Advance to the end of the identifier
    while (is_valid_identifier_char(*start)) {
        start++;
    }

    // Calculate the length of the identifier
    size_t length = start - *line;
    if (length == 0)
        return true;

    // Allocate memory for the identifier and copy it
    *str = mustmalloc(length + 1);
    strncpy((char *)*str, *line, length);
    ((char *)*str)[length] = '\0';

    *line = start;
    return true;
#undef is_valid_identifier_char
}

static bool consume_string(const char **line, char **str)
{
    const char *start = *line;
    if (*start != '"')
        return false;

    // Advance to the end of the string
    start++;
    while (*start && (*start != '"' || *(start - 1) == '\\')) {
        start++;
    }

    // Check that the string is properly terminated
    if (*start != '"')
        return false;

    // Calculate the length of the string (excluding quotes)
    size_t length = start - *line - 1;
    *str = mustmalloc(length + 1);
    strncpy(*str, *line + 1, length);
    (*str)[length] = '\0';

    *line = start + 1;
    return true;
}

static bool consume_integer(const char **line, int *integer)
{
    const char *start = *line;
    int base;
    int value = 0, parsed_digits = 0;
    bool negative = false;

    while (*start == '+' || *start == '-') {
        if (*start == '-')
            negative = !negative;
        start++;
    }

    if (*start == '0' && (*(start+1) == 'x' || *(start+1) == 'X')) {
        base = 16;
        start += 2;
    } else {
        base = 10;
    }

    while (isdigit(*start) || (base == 16 && isxdigit(*start))) {
        int digit = isdigit(*start) ? *start - '0' : toupper(*start) - 'A' + 10;
        value = value * base + digit;
        start++;
        parsed_digits++;
    }

    if (negative)
        value = -value;
    
    if (parsed_digits == 0)
        return false;

    *integer = value;
    *line = start;

    return true;
}

struct OpcodeArg {
    enum { REGISTER, IMMEDIATE, LABEL } type;
    union {
        int register_index;
        int immediate;
        const char *label;
    };
};

struct ParsedProgram {
    size_t sections_length;
    struct Section {
        const char *name;
        union {
            unsigned read: 1;
            unsigned write: 1;
            unsigned exec: 1;
        } flags;

        struct Item {
            enum { INSTRUCTION, DATA } type;
            union {
                struct Instruction {
                    enum Opcode opcode;
                    size_t argc;
                    struct OpcodeArg args[4];
                } instruction;
                struct DataBlock {
                    uint8_t *data;
                    size_t length;
                } data;
            };
        } *items;
        size_t items_length;
    } *sections;
};

static bool parse_section(int lineidx, const char *line, struct ParsedProgram *program)
{
    char *section_name = NULL;
    char *flags = NULL;

    line = skip_whitespace(line);
    if (!consume(&line, "section"))
        goto parse_failed;
    line = skip_whitespace(line);

    if (!consume_identifier(&line, &section_name)) {
        emit_error(lineidx, "Expected section name, found '%s' instead", line);
        goto parse_failed;
    }

    line = skip_whitespace(line);
    if (!consume(&line, ","))
        goto parse_failed;
    line = skip_whitespace(line);

    if (!consume_string(&line, &flags)) {
        emit_error(lineidx, "Expected section flags (eg: \"arx\"), found '%s' instead", line);
        goto parse_failed;
    }

    for (const char *flag = flags; *flag; flag++) {
        switch (*flag) {
        case 'a':
            // section->flags.allocatable = 1;
            break;
        case 'r':
            // section->flags.read = 1;
            break;
        case 'w':
            // section->flags.write = 1;
            break;
        case 'x':
            // section->flags.exec = 1;
            break;
        default:
            emit_error(lineidx, "Invalid flag: %c", *flag);
            goto parse_failed;
        }
    }
    free(flags);

    return true;

parse_failed:
    free(section_name);
    free(flags);
    return false;
}

static bool parse_asciiz(int lineidx, const char *line, struct ParsedProgram *program)
{
    char *string = NULL;

    if (!consume(&line, "asciiz"))
        goto parse_failed;
    line = skip_whitespace(line);

    if (!consume_string(&line, &string)) {
        emit_error(lineidx, "Invalid string literal");
        goto parse_failed;
    }

    /* TODO: Push the string into the current section */

    return true;

parse_failed:
    free(string);
    return false;
}

static bool parse_preprocessor_directive(int lineidx, const char *line, struct ParsedProgram *program)
{
    line = skip_whitespace(line);
    if (!consume(&line, "."))
        goto parse_failed;

    return (
        parse_section(lineidx, line, program) ||
        parse_asciiz(lineidx, line, program) ||
        emit_error(lineidx, "Unknown preprocessor directive: %s", line)
    );

parse_failed:
    return false;
}

static bool parse_label_decl(const char *line, struct ParsedProgram *program)
{
    char *label = NULL;

    line = skip_whitespace(line);
    if (!consume_identifier(&line, &label))
        goto parse_failed;
    if (!consume(&line, ":"))
        goto parse_failed;

    /* TODO: Create entry in the label table*/
    return true;

parse_failed:
    free(label);
    return false;
}

static bool parse_register_arg(const char **line, struct OpcodeArg *arg)
{
    char *iden = NULL;
    bool found = false;
    const char *start = *line;

    if (!consume_identifier(&start, &iden))
        goto parse_failed;

    static const struct { const char *name; int idx; } REGISTERS[] = {
        { "r0", 0 },    { "r1", 1 },    { "r2", 2 },    { "r3", 3 },
        { "r4", 4 },    { "r5", 5 },    { "r6", 6 },    { "r7", 7 },
        { "r8", 8 },    { "r9", 9 },    { "r10", 10 },  { "r11", 11 },
        { "r12", 12 },  { "r13", 13 },  { "sp", 13 },   { "r14", 14 },
        { "lr", 14 },   { "r15", 15 },  { "pc", 15 },
    };
    for (size_t i = 0; i < ARRAY_SIZE(REGISTERS); i++) {
        if (strcmp(iden, REGISTERS[i].name) == 0) {
            arg->type = REGISTER;
            arg->register_index = REGISTERS[i].idx;
            found = true;
            break;
        }
    }

    *line = start;
    free(iden);
    return found;

parse_failed:
    free(iden);
    return false;
}

static bool parse_label_arg(const char **line, struct OpcodeArg *arg)
{
    char *label = NULL;
    const char *start = *line;

    if (!consume_identifier(&start, &label))
        goto parse_failed;

    arg->type = LABEL;
    arg->label = label;
    *line = start;
    return true;

parse_failed:
    free(label);
    return false;
}

static bool parse_immediate_value_arg(int lineidx, const char **line, struct OpcodeArg *arg)
{
    const char *temp = *line;
    if (!consume(&temp, "#"))
        goto parse_failed;

    arg->type = IMMEDIATE;
    if (!consume_integer(&temp, &arg->immediate)) {
        emit_error(lineidx, "Expected an integer after '#'");
        goto parse_failed;
    }

    if (*temp != '\0') {
        emit_error(lineidx, "Unexpected character after integer");
        goto parse_failed;
    }

    *line = temp;
    return true;

parse_failed:
    return false;
}

static bool parse_opcode_arg(int lineidx, const char *line, struct OpcodeArg *arg)
{
    line = skip_whitespace(line);
    return (
        parse_register_arg(&line, arg) ||
        parse_label_arg(&line, arg) ||
        parse_immediate_value_arg(lineidx, &line, arg)
    );
}

static bool parse_instruction(int lineidx, const char *line, struct ParsedProgram *program)
{
    struct OpcodeArg args[4];
    int argc = 0;
    char *instruction_name = NULL;

    if (!consume_identifier(&line, &instruction_name))
        goto parse_failed;

    if (parse_opcode_arg(lineidx, line, &args[argc])) {
        argc++;

        line = skip_whitespace(line);
        while (consume(&line, ",")) {
            if (argc >= 4) {
                emit_error(lineidx, "Too many arguments");
                goto parse_failed;
            }

            
            if (!parse_opcode_arg(lineidx, line, &args[argc])) {
                emit_error(lineidx, "Failed to parse an argument after ','");
                goto parse_failed;
            }
            argc++;
            line = skip_whitespace(line);
        }
    }

    /* TODO: Check that the instruction is valid */
    /* TODO: Check that the argument count is correct */
    /* TODO: Convert the instruction to enum Opcode*/
    /* TODO: Push the instruction into the current section */

    return true;

parse_failed:
    free(instruction_name);
    return false;
}

static bool parse_line(int lineidx, char *line, struct ParsedProgram *program)
{
    // Trim leading whitespace
    while (*line && isspace(*line))
        line++;
    // Trim trailing whitespace and comments
    line[strcspn(line, "#\r\n")] = '\0';

    return (
        parse_preprocessor_directive(lineidx, line, program) ||
        parse_label_decl(line, program) ||
        parse_instruction(lineidx, line, program)
    );
}

static bool parse_program(char *source, struct ParsedProgram *program)
{
    bool parsing_failed = false;

    char *line = source;
    for (int lineidx = 0; line != NULL; lineidx++) {
        char *nextline = line;
        while (*nextline && *nextline != '\n')
            nextline++;
        if (*nextline == '\n') {
            *nextline = '\0';
            nextline++;
        } else {
            *nextline = '\0';
            nextline = NULL;
        }

        printf("% 3d: %s\n", lineidx, line);
        parsing_failed |= parse_line(lineidx, line, program);

        line = nextline;
    }

    return !parsing_failed;
}

int main(int argc, char *argv[])
{
    struct Args arguments;
    struct ParsedProgram program;
    char *source;

    parse_args(argc, argv, &arguments);
    read_file(arguments.input_file_path, &source);

    if (!parse_program(source, &program))
        exit(-1);

    free(source);

    return 0;
}
