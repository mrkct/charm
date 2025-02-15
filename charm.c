#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include "elf.h"

#define MAX_SECTIONS        16
#define SECTION_ALIGNMENT   4096
#define ROUND_UP(x, y) (((x) + (y) - 1) & ~((y) - 1))
#define HASH_SIZE           1024

enum Opcode {
    ADD, AND, B, BL, CMP, LDR, MOV, MUL, ORR, STR, SUB, SWI
};
struct SupportedInstruction {
    enum Opcode opcode;
    const char *name;
    int argc;
} SUPPORTED_INSTRUCTIONS[] = {
    {ADD, "ADD", 3},
    {AND, "AND", 3},
    {B, "B",   1},
    {BL, "BL",  1},
    {CMP, "CMP", 2},
    {LDR, "LDR", 2},
    {MOV, "MOV", 2},
    {MUL, "MUL", 3},
    {ORR, "ORR", 3},
    {STR, "STR", 2},
    {SUB, "SUB", 3},
    {SWI, "SWI", 1},
    {SWI, "SVC", 1}, // SVC is the same as SWI
};
struct {
    const char *name;
    uint32_t value;
} CONDITIONAL_EXECUTION_SUFFIXES[] = {
    {"EQ", 0b0000},
    {"NE", 0b0001},
    {"CS", 0b0010},
    {"CC", 0b0011},
    {"MI", 0b0100}, 
    {"PL", 0b0101},
    {"VS", 0b0110},
    {"VC", 0b0111},
    {"HI", 0b1000},
    {"LS", 0b1001},
    {"GE", 0b1010},
    {"LT", 0b1011},
    {"GT", 0b1100},
    {"LE", 0b1101},
#define COND_ALWAYS 0b1110
    {"AL", 0b1110},
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

static void hashmap_free(struct HashMap *table)
{
    for (size_t i = 0; i < HASH_SIZE; i++) {
        struct HashTableEntry *entry = table->entries[i];
        while (entry) {
            struct HashTableEntry *next = entry->next;
            free((void*) entry->key);
            free(entry);
            entry = next;
        }
    }
    free(table);
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
        int digit = isdigit(*start) ?
            *start - '0' : toupper(*start) - 'A' + 10;
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
        uint32_t register_index;
        int32_t immediate;
        const char *label;
    };
};

struct Instruction {
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
        const uint8_t *data;
    };
};

struct Section {
    const char *name;
    uint32_t start;
    size_t size;
    union {
        unsigned allocable: 1;
        unsigned read: 1;
        unsigned write: 1;
        unsigned exec: 1;
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
        section->items_capacity = section->items_capacity ?
            section->items_capacity * 2 : 1;
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
            "found '%s' instead", line);
        goto parse_failed;
    }

    if (program->sections_length == MAX_SECTIONS) {
        emit_error(lineidx, "Too many sections");
        goto parse_failed;
    }

    struct Section *prev_section = &program->sections[program->sections_length - 1];
    struct Section *section = &program->sections[program->sections_length++];
    section->name = section_name;
    section->start = ROUND_UP(prev_section->size, SECTION_ALIGNMENT);
    section->size = 0;
    for (const char *flag = flags; *flag; flag++) {
        switch (*flag) {
        case 'a':
            section->flags.allocable = 1;
            break;
        case 'r':
            section->flags.read = 1;
            break;
        case 'w':
            section->flags.write = 1;
            break;
        case 'x':
            section->flags.exec = 1;
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
        .data = (uint8_t*) string
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

static bool parse_opcode_arg(int lineidx, const char **line, struct OpcodeArg *arg)
{
    return (
        parse_register_arg(line, arg) ||
        parse_label_arg(line, arg) ||
        parse_immediate_value_arg(lineidx, line, arg)
    );
}

static bool parse_mnemonic(const char *mnemonic, struct SupportedInstruction **instruction, uint32_t *condition_flag)
{
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
    } else if (argc != instruction->argc) {
        emit_error(lineidx,
            "Invalid number of arguments for instruction '%s' "
            "(expected %d, found %d)", instruction_name,
            instruction->argc, argc);
        goto parse_failed;
    }
    
    struct Item item = {
        .type = INSTRUCTION,
        .length = 4,
        .instruction = {
            .condition_flag = condition_flag,
            .opcode = instruction->opcode,
            .args = {
                [0] = args[0],
                [1] = args[1],
                [2] = args[2],
                [3] = args[3],
            }
        }
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
    line = (char*) skip_whitespace(line);
    if (*line == '\0')
        return true;

    return (
        parse_preprocessor_directive(lineidx, line, program) ||
        parse_label_decl(lineidx, line, program) ||
        parse_instruction(lineidx, line, program)
    );
}

static bool parse_program(char *source, struct ParsedProgram *program)
{
    bool parsing_failed = false;
    char *line = NULL;

    program->labels = hashmap_alloc();
    program->sections_length = 1;

    struct Section *s = &program->sections[0];
    char *name = mustmalloc(strlen("default") + 1);
    strcpy(name, "default");
    s->name = name;
    s->start = 0,
    s->size = 0,
    s->flags.allocable = 1;
    s->flags.read = 1;
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

static void free_program(struct ParsedProgram *program)
{
    size_t idx;
    for (idx = 0; idx < program->sections_length; idx++) {
        struct Section *section = &program->sections[idx];
        
        for (size_t i = 0; i < section->items_length; i++) {
            struct Item item = section->items[i];
            switch (item.type) {
            case DATA:
                free((void*) item.data);
                break;
            case INSTRUCTION:
                for (size_t j = 0; j < ARRAY_SIZE(item.instruction.args); j++) {
                    struct OpcodeArg *arg = &item.instruction.args[j];
                    switch (arg->type) {
                    case REGISTER:
                        break;
                    case IMMEDIATE:
                        break;
                    case LABEL:
                        free((void*) arg->label);
                        break;
                    }
                }
                break;
            }
        }
        
        free((void*) section->name);
        free(section->items);
    }
    hashmap_free(program->labels);
}

//////// CODE GENERATION ////////

static bool codegen_instruction(struct ParsedProgram *program, uint32_t pc, struct Item *item, uint32_t *instruction)
{
#define opcode(n)       (((n) & 0x7f) << 21)
#define immediate_bit   ((uint32_t) 1 << 25)
#define Rn(n)           ((((n).register_index) & 0xf) << 16)
#define Rm(n)           ((((n).register_index) & 0xf) << 0)
#define Rd(n)           ((((n).register_index) & 0xf) << 12)

    uint32_t addr;
    uint32_t conditional_execution_mask;

    assert(item->type == INSTRUCTION);
    conditional_execution_mask = ((uint32_t) item->instruction.condition_flag) << 28;
    switch (item->instruction.opcode) {
        case ADD:
            assert(item->instruction.args[0].type == IMMEDIATE || 
                   item->instruction.args[0].type == REGISTER);

            *instruction = 0b00000000100000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= Rn(item->instruction.args[1]);
            *instruction |= Rd(item->instruction.args[0]);
            if (item->instruction.args[2].type == IMMEDIATE) {
                *instruction |= immediate_bit;
                *instruction |= item->instruction.args[2].immediate & 0xfff;
            } else {
                *instruction |= Rm(item->instruction.args[2]);
            }
            break;
        case AND:
            break;
        case B:
        case BL: {
            assert(item->instruction.args[0].type == LABEL);
            
            int64_t jump = 0;
            if (!hashmap_get(program->labels, item->instruction.args[0].label, &addr)) {
                emit_error(-1, "Label not found: %s", item->instruction.args[0].label);
                return false;
            }

            jump = (int64_t) addr - pc;
            if (jump <= -0x2000000 || jump > 0x1ffffc) {
                emit_error(-1, "Branch out of range: %s", item->instruction.args[0].label);
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
            assert(item->instruction.args[1].type == REGISTER ||
                   item->instruction.args[1].type == IMMEDIATE);
            
            *instruction = 0b00000001010100000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= Rn(item->instruction.args[0]);
            if (item->instruction.args[1].type == IMMEDIATE) {
                *instruction |= immediate_bit;
                *instruction |= item->instruction.args[1].immediate & 0xfff;
            } else {
                *instruction |= Rm(item->instruction.args[1]);
            }
            break;
        }
        case LDR:
            break;
        case MOV:
            assert(item->instruction.args[0].type == REGISTER);
            assert(item->instruction.args[1].type == IMMEDIATE ||
                   item->instruction.args[1].type == REGISTER);

            *instruction = 0b00000001101000000000000000000000;
            *instruction |= conditional_execution_mask;
            *instruction |= Rd(item->instruction.args[0]);
            if (item->instruction.args[1].type == IMMEDIATE) {
                *instruction |= immediate_bit;
                *instruction |= item->instruction.args[1].immediate & 0xfff;
            } else {
                *instruction |= Rm(item->instruction.args[1]);
            }
            break;
        case MUL:
            break;
        case ORR:
            break;
        case STR:
            break;
        case SUB:
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

static bool codegen_obj(struct ParsedProgram *program, int fd)
{
    uint32_t instruction = 0;
    bool codegen_failed = false;

    for (size_t i = 0; i < program->sections_length; i++) {
        struct Section *section = &program->sections[i];
        uint32_t addr = section->start;
        for (size_t j = 0; j < section->items_length; j++) {
            struct Item item = section->items[j];
            switch (item.type) {
            case DATA:
                write(fd, item.data, item.length);
                addr += item.length;
                break;
            case INSTRUCTION:
                // pc is always 8 bytes ahead
                codegen_failed |= !codegen_instruction(program, addr + 8, &item, &instruction);
                write(fd, (uint8_t*) &instruction, sizeof(instruction));
                addr += item.length;
                break;
            }
        }
    }

    return !codegen_failed;
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

    int fd = open(arguments.output_file_path, O_WRONLY | O_CREAT, 0644);
    if (!codegen_obj(&program, fd))
        exit(-1);
    close(fd);

    free(source);
    free_program(&program);

    return 0;
}
