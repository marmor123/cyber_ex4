# HTTP Response Splitting Attack - Instructions

## Files

- `ex4_splitting.c` - Main attack code

## Quick Start

### 1. Start the Environment (in VM)

```bash
docker start apache2-web-ver2
docker start p-ws-ver2
docker start attacker
docker start client
```

### 2. Clear Proxy Cache (IMPORTANT - do before each attempt)

```bash
docker exec -it p-ws-ver2 /bin/bash
rm -rf /usr/local/apache2/proxy/*
exit
```

Or restart the proxy:
```bash
docker restart p-ws-ver2
```

### 3. Compile (from attacker container)

```bash
docker exec -it attacker /bin/bash
cd /tmp/attacker
gcc -Wall -Wextra -Werror -Wconversion ex4_splitting.c -o attacker_http_response_splitting
```

### 4. Run the Attack

```bash
./attacker_http_response_splitting
```

### 5. Verify (from client container)

```bash
docker exec -it client /bin/bash
curl http://192.168.1.202:8080/67607.html
```

**Expected output:** `<HTML>324807346</HTML>`

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| 502 Bad Gateway | Restart proxy: `docker restart p-ws-ver2` |
| Original page still shown | Clear cache and try again |
| Connection refused | Make sure containers are running |

### Debugging with Wireshark

1. Find network ID: `docker network inspect http-a-net2`
2. Open Wireshark, select `br-http-a-net2` interface
3. Filter: `tcp.port == 8080`

### Check Server Logs

```bash
# Proxy logs
docker exec -it p-ws-ver2 cat /usr/local/apache2/logs/error_log

# Web server logs  
docker exec -it apache2-web-ver2 cat /usr/local/apache2/logs/error_log
```

