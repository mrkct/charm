#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include "elf.h"


const char *__asan_default_options() { return "detect_leaks=0"; }

#define MAX_SECTIONS 16
#define SECTION_ALIGNMENT 4096
#define ROUND_UP(x, y) (((x) + (y) -1) & ~((y) -1))
#define HASH_SIZE 1024

enum OpcodeArgType {
    REGISTER = 1 << 0,
    IMMEDIATE = 1 << 1,
    LABEL = 1 << 2,
    REGISTER_LIST = 1 << 3,
#define ARG(i, x) ((x) << (8 * (i)))
#define ARG0(x) ARG(0, x)
#define ARG1(x) ARG(1, x)
#define ARG2(x) ARG(2, x)
#define ARG3(x) ARG(3, x)
#define REG_OR_IMM (REGISTER | IMMEDIATE)
#define REG_OR_LABEL (REGISTER | LABEL)
#define REG_OR_IMM_OR_LABEL (REGISTER | IMMEDIATE | LABEL)
};
enum Opcode {
    ADD,
    AND,
    ASR,
    B,
    BL,
    CMP,
    LDR,
    LSL,
    LSR,
    MOV,
    MUL,
    ORR,
    POP,
    PUSH,
    SMULL,
    STR,
    SUB,
    SWI
};
struct SupportedInstruction {
    enum Opcode opcode;
    const char *name;
    int argc;
    uint32_t argtypes;
} SUPPORTED_INSTRUCTIONS[] = {
    { ADD, "ADD", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { AND, "AND", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { ASR, "ASR", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { B, "B", 1, ARG0(REG_OR_LABEL) },
    { BL, "BL", 1, ARG0(REG_OR_LABEL) },
    { CMP, "CMP", 2, ARG0(REGISTER) | ARG1(REG_OR_IMM) },
    { LDR, "LDR", 2, ARG0(REGISTER) | ARG1(LABEL) },
    { LSL, "LSL", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { LSR, "LSR", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { MOV, "MOV", 2, ARG0(REGISTER) | ARG1(REG_OR_IMM) },
    { MUL, "MUL", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REGISTER) },
    { ORR, "ORR", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { POP, "POP", 1, ARG0(REGISTER_LIST) },
    { PUSH, "PUSH", 1, ARG0(REGISTER_LIST) },
    { STR, "STR", 2, ARG0(REGISTER) | ARG1(LABEL) },
    { SMULL, "SMULL", 4, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REGISTER) | ARG3(REGISTER) },
    { SUB, "SUB", 3, ARG0(REGISTER) | ARG1(REGISTER) | ARG2(REG_OR_IMM) },
    { SWI, "SWI", 1, ARG0(IMMEDIATE) },
    { SWI, "SVC", 1, ARG0(IMMEDIATE) }, // SVC is the same as SWI
};

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

static void *mustrealloc(void *ptr, size_t size)
{
    void *new_ptr = realloc(ptr, size);
    if (new_ptr == NULL) {
        fprintf(stderr, "Error: Out of memory\n");
        exit(1);
    }
    return new_ptr;
}

struct HashTableEntry {
    const char *key;
    uint32_t value;
    struct HashTableEntry *next;
};

struct HashMap {
    struct HashTableEntry *entries[HASH_SIZE];
};

static uint32_t hash(const char *str)
{
    uint32_t hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash % HASH_SIZE;
}

static bool hashmap_get(struct HashMap *table, const char *key, uint32_t *value)
{
    uint32_t index = hash(key);
    struct HashTableEntry *entry = table->entries[index];
    while (entry) {
        if (strcmp(entry->key, key) == 0) {
            *value = entry->value;
            return true;
        }
        entry = entry->next;
    }
    return false;
}

static void hashmap_insert(struct HashMap *table, const char *key, uint32_t value)
{
    // This assumes that the key was not already in the table
    uint32_t index = hash(key);
    struct HashTableEntry *entry = mustmalloc(sizeof(struct HashTableEntry));
    entry->key = key;
    entry->value = value;
    entry->next = table->entries[index];
    table->entries[index] = entry;
}

static bool hashmap_contains(struct HashMap *table, const char *key)
{
    uint32_t useless;
    return hashmap_get(table, key, &useless);
}

static struct HashMap *hashmap_alloc()
{
    struct HashMap *table = mustmalloc(sizeof(struct HashMap));
    for (size_t i = 0; i < HASH_SIZE; i++)
        table->entries[i] = NULL;
    return table;
}

//////////// ARG PARSING ////////////

struct Args {
    const char *input_file_path;
    const char *output_file_path;
    uint32_t link_address;
    bool is_output_obj;
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

    // Check if the output file ends with either ".obj" or ".bin"
    size_t len = strlen(argv[2]);
    if (len >= 4 && (0 == strcmp(argv[2] + len - 4, ".obj") || 0 == strcmp(argv[2] + len - 4, ".bin"))) {
        arguments->is_output_obj = true;
        arguments->link_address = 0x0;
    } else {
        arguments->is_output_obj = false;
        arguments->link_address = 0x8000;
    }
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

//////////// CODE PARSING ////////////

static bool emit_error(int lineidx, const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    fprintf(stderr, "\033[1;31merror, at line %d\033[0m: ", lineidx);
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
    strncpy((char *) *str, *line, length);
    ((char *) *str)[length] = '\0';

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

    if (*start == '0' && (*(start + 1) == 'x' || *(start + 1) == 'X')) {
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
    enum OpcodeArgType type;
    union {
        uint32_t register_index;
        int32_t immediate;
        const char *label;
        struct {
            uint8_t regs[16];
            uint8_t count;
        } register_list;
    };
};

struct Instruction {
    int lineidx;
    uint32_t condition_flag;
    enum Opcode opcode;
    size_t argc;
    struct OpcodeArg args[4];
};

struct Item {
    enum { INSTRUCTION, DATA } type;
    size_t length;
    union {
        struct Instruction instruction;
        struct {
            enum { RAW_DATA, LABEL_ADDR } type;
            union {
                const uint8_t *raw_data;
                const char *label;
            };
        } data;
    };
};

struct Section {
    const char *name;
    uint32_t start;
    size_t size;
    union {
        struct {
            unsigned write : 1;
            unsigned exec : 1;
        };
        unsigned raw;
    } flags;

    struct Item *items;
    size_t items_length, items_capacity;
};

struct ParsedProgram {
    struct HashMap *labels;
    struct Section sections[MAX_SECTIONS];
    size_t sections_length;
};

static void push_item(struct ParsedProgram *program, struct Item item)
{
    struct Section *section = &program->sections[program->sections_length - 1];
    if (section->items_length == section->items_capacity) {
        section->items_capacity = section->items_capacity ? section->items_capacity * 2 : 1;
        section->items = mustrealloc(section->items,
            section->items_capacity * sizeof(*section->items));
    }
    section->items[section->items_length++] = item;
    section->size += ROUND_UP(item.length, 4);
}

static bool parse_section(int lineidx, const char *line, struct ParsedProgram *program)
{
    char *section_name = NULL;
    char *flags = NULL;

    line = skip_whitespace(line);
    if (!consume(&line, "section"))
        goto parse_failed;
    line = skip_whitespace(line);

    if (!consume_identifier(&line, &section_name)) {
        emit_error(lineidx,
            "Expected section name, found '%s' instead", line);
        goto parse_failed;
    }

    line = skip_whitespace(line);
    if (!consume(&line, ","))
        goto parse_failed;
    line = skip_whitespace(line);

    if (!consume_string(&line, &flags)) {
        emit_error(lineidx,
            "Expected section flags (eg: \"arx\"), "
            "found '%s' instead",
            line);
        goto parse_failed;
    }

    if (program->sections_length == MAX_SECTIONS) {
        emit_error(lineidx, "Too many sections");
        goto parse_failed;
    }

    struct Section *prev_section = &program->sections[program->sections_length - 1];
    struct Section *section = &program->sections[program->sections_length++];
    section->start = ROUND_UP(prev_section->start + prev_section->size, SECTION_ALIGNMENT);
    section->name = section_name;
    section->size = 0;
    section->flags.raw = 0;
    for (const char *flag = flags; *flag; flag++) {
        switch (*flag) {
            case 'w':
                section->flags.write = 1;
                break;
            case 'x':
                section->flags.exec = 1;
                break;
            case 'a':
            case 'r':
                break;
            default:
                emit_error(lineidx, "Invalid flag: %c", *flag);
                goto parse_failed;
        }
    }
    free(flags);
    section->items = NULL;
    section->items_length = 0;
    section->items_capacity = 0;

    return true;

parse_failed:
    free(section_name);
    free(flags);
    return false;
}

static bool parse_global(int lineidx, const char *line)
{
    char *label = NULL;

    /* We don't do anything with .global statements, we only parse them to
       ignore them because they're present in inputs */

    if (!consume(&line, "global"))
        goto parse_failed;

    line = skip_whitespace(line);
    if (!consume_identifier(&line, &label)) {
        emit_error(lineidx, "Expected label name, found '%s' instead", line);
        goto parse_failed;
    }

    free(label);
    return true;

parse_failed:
    free(label);
    return false;
}

static bool parse_word(int lineidx, const char *line, struct ParsedProgram *program)
{
    char *label = NULL;
    int value;

    if (!consume(&line, "word"))
        goto parse_failed;

    line = skip_whitespace(line);

    if (consume_integer(&line, &value)) {

        uint8_t *data = mustmalloc(4);
        data[0] = (uint32_t) value;
        data[1] = (uint32_t) value >> 8;
        data[2] = (uint32_t) value >> 16;
        data[3] = (uint32_t) value >> 24;

        struct Item item = {
            .type = DATA,
            .length = 4,
            .data = {
                .type = RAW_DATA,
                .raw_data = data,
            }
        };
        push_item(program, item);
    } else if (consume_identifier(&line, &label)) {
        struct Item item = {
            .type = DATA,
            .length = 4,
            .data = {
                .type = LABEL_ADDR,
                .label = label,
            }
        };
        push_item(program, item);
    } else {
        emit_error(lineidx, "Expected integer or label name, found '%s' instead", line);
        goto parse_failed;
    }

    return true;

parse_failed:
    free(label);
    return false;
}

static bool parse_ascii(
    int lineidx,
    const char *line,
    struct ParsedProgram *program)
{
    char *string = NULL;
    bool include_zero_term = true;

    if (consume(&line, "ascii")) {
        include_zero_term = false;
    } else if (consume(&line, "asciz") || consume(&line, "string")) {
        include_zero_term = true;
    } else {
        goto parse_failed;
    }
    line = skip_whitespace(line);

    if (!consume_string(&line, &string)) {
        emit_error(lineidx, "Invalid string literal");
        goto parse_failed;
    }

    struct Item item = {
        .type = DATA,
        .length = strlen(string) + (include_zero_term ? 1 : 0),
        .data = {
            .type = RAW_DATA,
            .raw_data = (uint8_t *) string,
        }
    };
    push_item(program, item);

    return true;

parse_failed:
    free(string);
    return false;
}

static bool parse_preprocessor_directive(
    int lineidx,
    const char *line,
    struct ParsedProgram *program)
{
    line = skip_whitespace(line);
    if (!consume(&line, "."))
        goto parse_failed;

    return (
        parse_section(lineidx, line, program) ||
        parse_word(lineidx, line, program) ||
        parse_ascii(lineidx, line, program) ||
        parse_global(lineidx, line) ||
        emit_error(lineidx, "Unknown preprocessor directive: %s", line)
    );

parse_failed:
    return false;
}

static bool parse_label_decl(int lineidx, const char *line, struct ParsedProgram *program)
{
    char *label = NULL;

    line = skip_whitespace(line);
    if (!consume_identifier(&line, &label))
        goto parse_failed;
    if (!consume(&line, ":"))
        goto parse_failed;

    struct Section *section = &program->sections[program->sections_length - 1];
    if (hashmap_contains(program->labels, label)) {
        emit_error(lineidx, "Duplicate label '%s'", label);
        goto parse_failed;
    }
    hashmap_insert(program->labels, label, section->start + section->size);
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

    static const struct {
        const char *name;
        int idx;
    } REGISTERS[] = {
        { "r0", 0 },
        { "r1", 1 },
        { "r2", 2 },
        { "r3", 3 },
        { "r4", 4 },
        { "r5", 5 },
        { "r6", 6 },
        { "r7", 7 },
        { "r8", 8 },
        { "r9", 9 },
        { "r10", 10 },
        { "r11", 11 },
        { "r12", 12 },
        { "r13", 13 },
        { "sp", 13 },
        { "r14", 14 },
        { "lr", 14 },
        { "r15", 15 },
        { "pc", 15 },
    };
    for (size_t i = 0; i < ARRAY_SIZE(REGISTERS); i++) {
        if (strcmp(iden, REGISTERS[i].name) == 0) {
            arg->type = REGISTER;
            arg->register_index = REGISTERS[i].idx;
            found = true;
            break;
        }
    }
    if (!found)
        goto parse_failed;

    *line = start;
    free(iden);
    return true;

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

    if (*temp != '\0' && !isspace(*temp)) {
        emit_error(lineidx, "Unexpected character after integer");
        goto parse_failed;
    }

    *line = temp;
    return true;

parse_failed:
    return false;
}

static bool parse_register_list_arg(int lineidx, const char **line, struct OpcodeArg *arg)
{
    struct OpcodeArg temp_reg = {0};
    const char *start = *line;
    uint32_t bitmask = 0;

    arg->type = REGISTER_LIST;
    arg->register_list.count = 0;

    if (!consume(&start, "{"))
        goto parse_failed;
    
    start = skip_whitespace(start);
    if (parse_register_arg(&start, &temp_reg)) {
        arg->register_list.regs[arg->register_list.count++] = temp_reg.register_index;
        bitmask |= 1 << temp_reg.register_index;

        start = skip_whitespace(start);
        while (consume(&start, ",")) {
            start = skip_whitespace(start);
            if (!parse_register_arg(&start, &temp_reg)) {
                emit_error(lineidx, "Failed to parse an argument after ','");
                goto parse_failed;
            }
            if (bitmask & (1 << temp_reg.register_index)) {
                emit_error(lineidx, "Duplicate register in list");
                goto parse_failed;
            }
            arg->register_list.regs[arg->register_list.count++] = temp_reg.register_index;
            bitmask |= 1 << temp_reg.register_index;
            start = skip_whitespace(start);
        }
    }
    
    *line = start;

    return true;

parse_failed:
    return false;
}

static bool parse_opcode_arg(int lineidx, const char **line, struct OpcodeArg *arg)
{
    return (
        parse_register_arg(line, arg) ||
        parse_label_arg(line, arg) ||
        parse_immediate_value_arg(lineidx, line, arg) ||
        parse_register_list_arg(lineidx, line, arg)
    );
}

static bool parse_mnemonic(const char *mnemonic, struct SupportedInstruction **instruction, uint32_t *condition_flag)
{
    static struct {
        const char *name;
        uint32_t value;
    } CONDITIONAL_EXECUTION_SUFFIXES[] = {
        { "EQ", 0b0000 },
        { "NE", 0b0001 },
        { "CS", 0b0010 },
        { "CC", 0b0011 },
        { "MI", 0b0100 },
        { "PL", 0b0101 },
        { "VS", 0b0110 },
        { "VC", 0b0111 },
        { "HI", 0b1000 },
        { "LS", 0b1001 },
        { "GE", 0b1010 },
        { "LT", 0b1011 },
        { "GT", 0b1100 },
        { "LE", 0b1101 },
        { "AL", 0b1110 },
#define COND_ALWAYS 0b1110
    };

    for (size_t i = 0; i < ARRAY_SIZE(SUPPORTED_INSTRUCTIONS); i++) {
        size_t instr_len = strlen(SUPPORTED_INSTRUCTIONS[i].name);

        if (strncasecmp(mnemonic, SUPPORTED_INSTRUCTIONS[i].name, instr_len) == 0) {
            *instruction = &SUPPORTED_INSTRUCTIONS[i];

            if (mnemonic[instr_len] == '\0') {
                *condition_flag = COND_ALWAYS;
                return true;
            }

            // Check for condition suffix
            const char *suffix = mnemonic + instr_len;
            for (size_t j = 0; j < ARRAY_SIZE(CONDITIONAL_EXECUTION_SUFFIXES); j++) {
                if (strcasecmp(suffix, CONDITIONAL_EXECUTION_SUFFIXES[j].name) == 0) {
                    *condition_flag = CONDITIONAL_EXECUTION_SUFFIXES[j].value;
                    return true;
                }
            }
        }
    }

    return false;
}

static bool validate_instruction_args(int lineidx, struct SupportedInstruction *instruction, int argc, struct OpcodeArg args[])
{
    if (argc != instruction->argc) {
        emit_error(lineidx,
            "Invalid number of arguments for instruction '%s' "
            "(expected %d, found %d)",
            instruction->name, instruction->argc, argc);
        return false;
    }

    for (int i = 0; i < argc; i++) {
        if (!(instruction->argtypes & ARG(i, args[i].type))) {
            emit_error(lineidx, "Invalid argument type for argument %d", i);
            return false;
        }
    }

    return true;
}

static bool parse_instruction(int lineidx, const char *line, struct ParsedProgram *program)
{
    struct OpcodeArg args[4] = { 0 };
    int argc = 0;
    char *instruction_name = NULL;
    uint32_t condition_flag = 0;
    struct SupportedInstruction *instruction = NULL;

    if (!consume_identifier(&line, &instruction_name))
        goto parse_failed;

    line = skip_whitespace(line);
    if (parse_opcode_arg(lineidx, &line, &args[argc])) {
        argc++;

        line = skip_whitespace(line);
        while (consume(&line, ",")) {
            if (argc >= 4) {
                emit_error(lineidx, "Too many arguments");
                goto parse_failed;
            }

            line = skip_whitespace(line);
            if (!parse_opcode_arg(lineidx, &line, &args[argc])) {
                emit_error(lineidx, "Failed to parse an argument after ','");
                goto parse_failed;
            }
            argc++;
            line = skip_whitespace(line);
        }
    }

    if (!parse_mnemonic(instruction_name, &instruction, &condition_flag)) {
        emit_error(lineidx, "Unknown instruction '%s'", instruction_name);
        goto parse_failed;
    } else if (!validate_instruction_args(lineidx, instruction, argc, args)) {
        goto parse_failed;
    }

    struct Item item = {
        .type = INSTRUCTION,
        .length = 4,
        .instruction = {
            .lineidx = lineidx,
            .condition_flag = condition_flag,
            .opcode = instruction->opcode,
            .args = {
                [0] = args[0],
                [1] = args[1],
                [2] = args[2],
                [3] = args[3],
            } }
    };
    push_item(program, item);
    free(instruction_name);

    return true;

parse_failed:
    free(instruction_name);
    return false;
}

static bool parse_line(int lineidx, char *line, struct ParsedProgram *program)
{
    // Trim comments
    for (char *c = line; *c && *(c + 1); c++) {
        if (*c == '/' && *(c + 1) == '/') {
            *c = '\0';
            break;
        }
    }

    // Empty lines are not an error
    line = (char *) skip_whitespace(line);
    if (*line == '\0')
        return true;

    return (
        parse_preprocessor_directive(lineidx, line, program) ||
        parse_label_decl(lineidx, line, program) ||
        parse_instruction(lineidx, line, program)
    );
}

static bool parse(char *source, uint32_t startaddr, struct ParsedProgram *program)
{
    bool parsing_failed = false;
    char *line = NULL;

    program->labels = hashmap_alloc();
    program->sections_length = 1;

    struct Section *s = &program->sections[0];
    char *name = mustmalloc(strlen("default") + 1);
    strcpy(name, "default");
    s->name = name;
    s->start = startaddr,
    s->size = 0,
    s->flags.write = 0;
    s->flags.exec = 1;
    s->items = NULL;
    s->items_length = 0;
    s->items_capacity = 0;

    line = source;
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

        if (!parse_line(lineidx, line, program)) {
            parsing_failed = true;
            fprintf(stderr, "% 5d | %s\n", lineidx, line);
        }

        line = nextline;
    }

    return !parsing_failed;
}

//////// CODE GENERATION ////////

struct Region {
    struct {
        unsigned write : 1;
        unsigned exec : 1;
    } flags;
    uint32_t loadaddr;
    uint8_t *data;
    size_t size, capacity;
};

struct ObjectCode {
    uint32_t entrypoint;
    struct Region regions[MAX_SECTIONS];
    size_t regions_length;
};

static struct Region *push_region(struct ObjectCode *object_code, struct Section *section)
{
    if (object_code->regions_length == ARRAY_SIZE(object_code->regions)) {
        emit_error(0, "Reached the limit of %d regions", MAX_SECTIONS);
        exit(-1);
    }

    struct Region *region = &object_code->regions[object_code->regions_length++];
    region->flags.write = section->flags.write;
    region->flags.exec = section->flags.exec;

    region->loadaddr = section->start;

    region->data = NULL;
    region->size = 0;
    region->capacity = 0;

    return region;
}

static void add_data(struct Region *region, const uint8_t *data, size_t size)
{
    if (region->capacity < region->size + size) {
        region->capacity = region->size + ROUND_UP(size, SECTION_ALIGNMENT);
        region->data = mustrealloc(region->data, region->capacity);
    }
    memcpy(region->data + region->size, data, size);
    region->size += size;
}

static uint32_t register_list_bitmask(struct OpcodeArg *arg)
{
    assert(arg->type == REGISTER_LIST);
    uint32_t bitmask = 0;
    for (size_t i = 0; i < arg->register_list.count; i++)
        bitmask |= 1 << arg->register_list.regs[i];
    return bitmask;
}

static bool codegen_instruction(struct ParsedProgram *program, uint32_t pc, struct Item *item, uint32_t *instruction)
{
    static const uint32_t Rn_PC = (uint32_t) 15 << 16;
#define RegShift(r, n) (((r).register_index & 0xf) << n)
#define Imm5(i, n)  (((i).immediate & 0x1f) << n)
#define Imm12(i, n) (((i).immediate & 0xfff) << n)

    uint32_t addr;
    uint32_t conditional_execution_mask;

    assert(item->type == INSTRUCTION);
    conditional_execution_mask = ((uint32_t) item->instruction.condition_flag) << 28;
    switch (item->instruction.opcode) {
        case ADD:
            *instruction = 0b00000000100000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 16);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= (uint32_t) 1 << 25;
                *instruction |= Imm12(item->instruction.args[2], 0);
            } else {
                *instruction |= RegShift(item->instruction.args[2], 0);
            }
            break;
        case AND:
            *instruction = 0b00000000000000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 16);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= (uint32_t) 1 << 25;
                *instruction |= Imm12(item->instruction.args[2], 0);
            } else {
                *instruction |= RegShift(item->instruction.args[2], 0);
            }
            break;
        case ASR:
            *instruction = 0b00000001101000000000000001000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 0);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= Imm5(item->instruction.args[2], 7);
            } else {
                *instruction |= 1 << 4;
                *instruction |= RegShift(item->instruction.args[2], 8);
            }
            break;            
        case B:
        case BL: {
            assert(item->instruction.args[0].type == LABEL);

            int64_t jump = 0;
            if (!hashmap_get(program->labels, item->instruction.args[0].label, &addr)) {
                emit_error(item->instruction.lineidx,
                    "Label not found: %s", item->instruction.args[0].label);
                return false;
            }

            jump = (int64_t) addr - pc;
            if (jump <= -0x2000000 || jump > 0x1ffffc) {
                emit_error(item->instruction.lineidx,
                    "Branch out of range: %s", item->instruction.args[0].label);
                return false;
            }

            *instruction = 0b00001010000000000000000000000000;
            if (item->instruction.opcode == BL)
                *instruction |= 1 << 24;
            *instruction |= conditional_execution_mask;
            *instruction |= ((uint32_t) jump >> 2) & 0xffffff;
            break;
        }
        case CMP: {
            assert(item->instruction.args[0].type == REGISTER);
            assert(item->instruction.args[1].type == REGISTER || item->instruction.args[1].type == IMMEDIATE);

            *instruction = 0b00000001010100000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 16);
            if (item->instruction.args[1].type == IMMEDIATE) {
                *instruction |= (uint32_t) 1 << 25;
                *instruction |= Imm12(item->instruction.args[1], 0);
            } else {
                *instruction |= RegShift(item->instruction.args[1], 0);
            }
            break;
        }
        case LDR: {
            assert(item->instruction.args[0].type == REGISTER);
            assert(item->instruction.args[1].type == LABEL);

            int64_t jump = 0;
            if (!hashmap_get(program->labels, item->instruction.args[1].label, &addr)) {
                emit_error(item->instruction.lineidx,
                    "Label not found: %s", item->instruction.args[1].label);
                return false;
            }

            jump = (int64_t) addr - pc;
            if (jump <= -0x1000 || jump >= 0x1000) {
                printf("pc: %x   - label: %x\n", pc, addr);
                emit_error(item->instruction.lineidx,
                    "Label out of range: %s", item->instruction.args[1].label);
                return false;
            }

            *instruction = 0b00000100000100000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= 1 << 24; /* Set P=1 because we should use the imm value */
            if (jump >= 0) {
                /* Set U=1 because the imm value must be added to the register */
                *instruction |= 1 << 23;
            } else {
                /* Set U=0 because the imm value must be subtracted from the register */
                jump = -jump;
            }
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= Rn_PC;
            *instruction |= ((uint32_t) jump) & 0xfff;

            break;
        }
        case LSL:
            *instruction = 0b00000001101000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 0);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= Imm5(item->instruction.args[2], 7);
            } else {
                *instruction |= 1 << 4;
                *instruction |= RegShift(item->instruction.args[2], 8);
            }
            break;
        case LSR:
            *instruction = 0b00000001101000000000000000100000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 0);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= Imm5(item->instruction.args[2], 7);
            } else {
                *instruction |= 1 << 4;
                *instruction |= RegShift(item->instruction.args[2], 8);
            }
            break;
        case MOV:
            assert(item->instruction.args[0].type == REGISTER);
            assert(item->instruction.args[1].type == IMMEDIATE || item->instruction.args[1].type == REGISTER);

            *instruction = 0b00000001101000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            if (item->instruction.args[1].type == IMMEDIATE) {
                *instruction |= (uint32_t) 1 << 25;
                *instruction |= Imm12(item->instruction.args[1], 0);
            } else {
                *instruction |= RegShift(item->instruction.args[1], 0);
            }
            break;
        case MUL:
            *instruction = 0b00000000000000000000000010010000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 16);
            *instruction |= RegShift(item->instruction.args[1], 0);
            *instruction |= RegShift(item->instruction.args[2], 8);
            break;
        case ORR:
            *instruction = 0b00000001100000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 16);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= (uint32_t) 1 << 25;
                *instruction |= Imm12(item->instruction.args[2], 0);
            } else {
                *instruction |= RegShift(item->instruction.args[2], 0);
            }
            break;
        case POP:
            assert(item->instruction.args[0].type == REGISTER_LIST);
            if (item->instruction.args[0].register_list.count == 1) {
                *instruction = 0b00000100100111010000000000000100;
                *instruction |= conditional_execution_mask;
                *instruction |= ((uint32_t) item->instruction.args[0].register_list.regs[0] & 0xf) << 12;
            } else {
                *instruction = 0b00001000101111010000000000000000;
                *instruction |= conditional_execution_mask;
                *instruction |= register_list_bitmask(&item->instruction.args[0]);
            }
            break;
        case PUSH:
            assert(item->instruction.args[0].type == REGISTER_LIST);
            if (item->instruction.args[0].register_list.count == 1) {
                *instruction = 0b00000101001011010000000000000100;
                *instruction |= conditional_execution_mask;
                *instruction |= ((uint32_t) item->instruction.args[0].register_list.regs[0] & 0xf) << 12;
            } else {
                *instruction = 0b00001001001011010000000000000000;
                *instruction |= conditional_execution_mask;
                *instruction |= register_list_bitmask(&item->instruction.args[0]);
            }
            break;
        case STR: {
            assert(item->instruction.args[0].type == REGISTER);
            assert(item->instruction.args[1].type == LABEL);

            int64_t jump = 0;
            if (!hashmap_get(program->labels, item->instruction.args[1].label, &addr)) {
                emit_error(item->instruction.lineidx,
                    "Label not found: %s", item->instruction.args[1].label);
                return false;
            }

            jump = (int64_t) addr - pc;
            if (jump <= -0x1000 || jump >= 0x1000) {
                emit_error(item->instruction.lineidx,
                    "Label out of range: %s", item->instruction.args[1].label);
                return false;
            }

            *instruction = 0b00000100000000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= 1 << 24; /* Set P=1 because we should use the imm value */
            if (jump >= 0) {
                /* Set U=1 because the imm value must be added to the register */
                *instruction |= 1 << 23;
            } else {
                /* Set U=0 because the imm value must be subtracted from the register */
                jump = -jump;
            }
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= 15 << 16 /* 15 is the 'pc' register */;
            *instruction |= ((uint32_t) jump) & 0xfff;

            break;
        }
        case SMULL:
            *instruction = 0b00000000110000000000000010010000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 16);
            *instruction |= RegShift(item->instruction.args[2], 0);
            *instruction |= RegShift(item->instruction.args[3], 8);
            break;
        case SUB:
            *instruction = 0b00000000010000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= RegShift(item->instruction.args[0], 12);
            *instruction |= RegShift(item->instruction.args[1], 16);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= (uint32_t) 1 << 25;
                *instruction |= Imm12(item->instruction.args[2], 0);
            } else {
                *instruction |= RegShift(item->instruction.args[2], 0);
            }
            break;
        case SWI:
            assert(item->instruction.args[0].type == IMMEDIATE);

            *instruction = 0b00001111000000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= item->instruction.args[0].immediate & 0xffffff;
            break;
    }

    return true;
}

static bool codegen(struct ParsedProgram *program, struct ObjectCode *obj)
{
    uint32_t instruction = 0;
    bool codegen_failed = false;

    for (size_t i = 0; i < program->sections_length; i++) {
        struct Section *section = &program->sections[i];
        if (section->size == 0)
            continue;
        struct Region *region = push_region(obj, section);
        for (size_t j = 0; j < section->items_length; j++) {
            struct Item item = section->items[j];
            switch (item.type) {
                case DATA: {
                    switch (item.data.type) {
                        case RAW_DATA:
                            add_data(region, item.data.raw_data, item.length);
                            break;
                        case LABEL_ADDR: {
                            uint32_t addr;
                            if (!hashmap_get(program->labels, item.data.label, &addr)) {
                                emit_error(item.instruction.lineidx, "Label not found: %s", item.data.label);
                            }
                            add_data(region, (uint8_t *) &addr, sizeof(addr));
                            break;
                        }
                    }
                    break;
                }
                case INSTRUCTION: {
                    // pc is always 8 bytes ahead
                    uint32_t pc = region->loadaddr + region->size + 8;
                    codegen_failed |= !codegen_instruction(program, pc, &item, &instruction);
                    add_data(region, (uint8_t *) &instruction, sizeof(instruction));
                    break;
                }
            }
        }
    }

    if (!hashmap_get(program->labels, "_start", &obj->entrypoint)) {
        emit_error(0, "No '_start' label found, entrypoint will be 0");
        obj->entrypoint = 0;
    }

    return !codegen_failed;
}

static void assemble_obj(struct ObjectCode *object, int fd)
{
    for (size_t i = 0; i < object->regions_length; i++) {
        struct Region *region = &object->regions[i];
        write(fd, region->data, region->size);
    }
}

static void assemble_elf(struct ObjectCode *object, int fd)
{
    Elf32_Ehdr hdr = {
        .e_ident = {
            ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3,
            ELFCLASS32, ELFDATA2LSB,
            EV_CURRENT
        },
        .e_type = ET_EXEC,
        .e_machine = EM_ARM,
        .e_version = EV_CURRENT,
        .e_entry = object->entrypoint,
        .e_phoff = sizeof(Elf32_Ehdr),
        .e_shoff = 0,
        .e_flags = 0x5000200,
        .e_ehsize = sizeof(Elf32_Ehdr),
        .e_phentsize = sizeof(Elf32_Phdr),
        .e_phnum = object->regions_length,
        .e_shentsize = sizeof(Elf32_Shdr),
        .e_shnum = 0,
        .e_shstrndx = 0
    };
    write(fd, &hdr, sizeof(hdr));

    uint32_t next_offset = ROUND_UP(sizeof(hdr) + sizeof(Elf32_Phdr) * object->regions_length, 4096);
    for (size_t i = 0; i < object->regions_length; i++) {
        struct Region *region = &object->regions[i];

        uint32_t flags = PF_R | (
            (region->flags.exec ? PF_X : 0) |
            (region->flags.write ? PF_W : 0)
        );

        Elf32_Phdr phdr_hdr = {
            .p_type = PT_LOAD,
            .p_offset = next_offset,
            .p_vaddr = region->loadaddr,
            .p_paddr = region->loadaddr,
            .p_filesz = region->size,
            .p_memsz = region->size,
            .p_flags = flags,
            .p_align = SECTION_ALIGNMENT,
        };
        write(fd, &phdr_hdr, sizeof(phdr_hdr));
        next_offset += region->size;
    }

    uint8_t zeros[4096] = { 0 };
    size_t padding = 4096 - (lseek(fd, 0, SEEK_CUR) % 4096);
    if (padding < 4096)
        write(fd, zeros, padding);

    for (size_t i = 0; i < object->regions_length; i++) {
        struct Region *region = &object->regions[i];
        write(fd, region->data, region->size);
    }
}

int main(int argc, char *argv[])
{
    struct Args args = { 0 };
    struct ParsedProgram parsed = { 0 };
    struct ObjectCode object = { 0 };
    char *source = NULL;
    int rc = 0, fd = -1;

    parse_args(argc, argv, &args);
    read_file(args.input_file_path, &source);

    if (!parse(source, args.link_address, &parsed)) {
        rc = -1;
        goto cleanup;
    }

    if (!codegen(&parsed, &object)) {
        rc = -1;
        goto cleanup;
    }

    fd = open(args.output_file_path, O_CREAT | O_WRONLY, 0777);
    if (fd < 0) {
        perror("open");
        rc = -1;
        goto cleanup;
    }

    if (args.is_output_obj) {
        assemble_obj(&object, fd);
    } else {
        assemble_elf(&object, fd);
    }

cleanup:
    return rc;
}
