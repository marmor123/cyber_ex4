# Blind SQL Injection Attack - Instructions

## Files Overview

| File | Description |
|------|-------------|
| `ex4_sqli.c` | Main attack code in C |
| `INSTRUCTIONS.md` | This file |

## Prerequisites

The code must be run from within the **attacker container** in the provided VM environment.

## Configuration

Before compiling, you **MUST** edit `ex4_sqli.c` and update the `SUBMITTER_ID`:

```c
#define SUBMITTER_ID "123456789"  /* CHANGE THIS TO YOUR ID */
```

Replace `123456789` with your actual student ID.

## Compilation

### From the attacker container:

```bash
gcc -Wall -Wextra -Werror -Wconversion ex4_sqli.c -o ex4_sqli
```

> **Important**: The code must compile with NO warnings!

## Running the Attack

### Step 1: Start the VM environment

Login with username `bsqliEnv` and password `5260`.

### Step 2: Start the containers (if not already running)

```bash
docker start mariadb-server
docker start web-app
docker start attacker
```

### Step 3: Enter the attacker container

```bash
docker exec -it attacker /bin/bash
```

### Step 4: Navigate to the code directory

Inside the container:
```bash
cd /tmp/attacker
```

> **Note**: Files in `/home/bsqlenv/Desktop/attacker` on the VM are mounted to `/tmp/attacker` in the container.

### Step 5: Compile and run

```bash
gcc -Wall -Wextra -Werror -Wconversion ex4_sqli.c -o ex4_sqli
./ex4_sqli
```

## Output

On success, the attack creates a file named `{YOUR_ID}.txt` containing the password in the format:
```
*extracted_password*
```

## Debug Mode

The code includes debug output (prints to stderr). To disable debug mode for final submission:

In `ex4_sqli.c`, change:
```c
#define DEBUG 1
```
to:
```c
#define DEBUG 0
```

## Troubleshooting

### Connection refused
- Ensure `web-app` container is running: `docker ps`
- Restart the web app: `docker restart web-app`

### No password found
- Verify your ID exists in the database
- Check the query count isn't exceeded (max 400)

### Compilation errors
- Make sure you're compiling inside the attacker container (Linux environment)
- The code uses POSIX sockets which aren't available on Windows

## Verification

To manually verify the password, connect to the database:

```bash
docker exec -it mariadb-server /bin/bash
mariadb -u u67607 -p 67607db
# Password: courseUser
```

Then run:
```sql
SELECT <id_col>, CONCAT("<", <pwd_col>, ">") AS pwd FROM <table_name>;
```

## Constraints (Assignment Requirements)

- ✅ Maximum 400 queries (current implementation uses ~280)
- ✅ Maximum 30 seconds execution time
- ✅ No libcurl usage
- ✅ No shell commands (system/execve)
- ✅ Compiles with strict warning flags
