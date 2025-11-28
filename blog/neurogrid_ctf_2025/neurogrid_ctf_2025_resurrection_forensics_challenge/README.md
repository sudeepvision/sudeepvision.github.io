# Neurogrid CTF 2025 - Resurrection forensics challenge write up

### Overview

| Challenge name | Resurrection |
| --- | --- |
| Solution author | Sudeep Singh |
| Category | Forensics |

In this challenge, we are provided a memory dump from a Linux machine along with OS symbols and a network PCAP.

Below is the directory structure of the provided files.

```
$ tree
.
├── Ubuntu_6.8.0-31-generic_6.8.0-31.31_amd64.json.xz
├── memory.dmp
└── network.pcapng
```

### Initial analysis

#### Memory dump analysis

First, I checked the list of running processes on the Linux machine using the below command

```
vol -f memory.dmp linux.pslist.PsList
```

I identified a few potential candidates which could be malicious processes. Next I checked the procMaps for each of the potential malicious processes to identify the actual malicious process.

```
vol -f memory.dmp linux.proc.Maps --pid <pid>
```

One specific process with pid 5197 stood out as malicious because its process memory map showed that a binary was mapped to the process memory address space using memfd_create syscall. The name of this process according to pslist module is `3` which is also suspicious.

The memfd_create syscall allows a file to be mapped to the memory without any presence on the disk. This technique is abused by threat actors for fileless execution of malware on Linux machines.

```
└─$ vol -f memory.dmp linux.proc.Maps --pid 5197                          
Volatility 3 Framework 2.27.0
Progress:  100.00               Stacking attempts finished           
PID     Process Start   End     Flags   PgOff   Major   Minor   Inode   File Path       File output

5197    3       0x400000        0x6ac000        r-x     0x0     0       1       1178    /memfd:libudev-cache (deleted)  Disabled
5197    3       0x6ac000        0x96b000        r--     0x2ac000        0       1       1178    /memfd:libudev-cache (deleted)  Disabled
5197    3       0x96b000        0x983000        rw-     0x56b000        0       1       1178    /memfd:libudev-cache (deleted)  Disabled
5197    3       0x983000        0x9b3000        rw-     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0xc000000000    0xc000400000    rw-     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0xc000400000    0xc004000000    ---     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0x73a009d80000  0x73a009e00000  rw-     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0x73a009e00000  0x73a00be00000  rw-     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0x73a00be00000  0x73a01bf80000  ---     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0x73a01bf80000  0x73a01bf81000  rw-     0x0     0       0       0       Anonymous Mapping       Disabled
5197    3       0x73a01bf81000  0x73a03bf80000  ---     0x0     0       0       0       Anonymous Mapping       Disabled
```

We can see that a binary with the name, libudev-cache was mapped to the memory address space of the process with pid 5197 using memfd_create. In order to dump the binary, we will dump the first few segments. The executable segment above corresponds to the CODE section of the ELF binary.

Using the below 3 commands, we can dump all the segments.

```
vol -f memory.dmp linux.proc.Maps --pid 5197 --address 0x6ac000 --dump
vol -f memory.dmp linux.proc.Maps --pid 5197 --address 0x96b000 --dump
vol -f memory.dmp linux.proc.Maps --pid 5197 --address 0x983000 --dump
```

Now we can combine all the dumped segments into a ELF binary

```
 cat pid.5197.vma.0x400000-0x6ac000.dmp \
 pid.5197.vma.0x6ac000-0x96b000.dmp \
 pid.5197.vma.0x96b000-0x983000.dmp \
 pid.5197.vma.0x983000-0x9b3000.dmp \
 > full_binary.dmp
```

We can confirm this is a 64-bit ELF binary which was written in Golang

```
└─$ file full_binary.dmp                                                          
full_binary.dmp: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, Go BuildID=7CTWG2Cxpe3VqhVMajtX/lB4Hj4LiMmEssbOxebIw/a8BwaNTj4tlGvFbIs0KU/cgRyK_4RDrltBD4RugZY, stripped
```

Since this is a Golang binary, I first ran GoReSym against it to identify the dependencies.

The output of GoReSym shows the below dependencies.

```
    "BuildInfo": {
        "GoVersion": "go1.23.0",
        "Path": "gopher",
        "Main": {
            "Path": "gopher",
            "Version": "(devel)",
            "Sum": "",
            "Replace": null
        },
        "Deps": [
            {
                "Path": "github.com/gen2brain/shm",
		...
            },
            {
                "Path": "github.com/godbus/dbus/v5",
		...
            },
            {
                "Path": "github.com/jezek/xgb",
		...
            },
            {
                "Path": "github.com/kbinani/screenshot",
		...
            },
            {
                "Path": "github.com/shirou/gopsutil/v4",
		...
            },
            {
                "Path": "github.com/tklauser/go-sysconf",
		...
            },
            {
                "Path": "github.com/tklauser/numcpus",
		...
            },
            {
                "Path": "github.com/vmihailenco/msgpack/v5",
		...
            },
            {
                "Path": "github.com/vmihailenco/tagparser/v2",
		...
            },
            {
                "Path": "golang.org/x/sys",
		...
            }
        ],
```

After some more analysis, I confirmed that this Golang binary is an Adaptix C2 gopher agent. Adaptix C2 is an open-source offensive security framework.

Next I extracted the config of this agent. I used the GitHub project [here](https://github.com/0xThiebaut/AdaptixC2-gopher) to extract the config from the gopher agent. The way this tool works is by bruteforcing the binary to look for the AES GCM key and the IV. Once it finds certain keywords specific to the gopher agent in the decrypted content, that confirms the correct decryption key and IV.

I modified the go config extractor to also dump the correct AES key and IV. We will use this AES key and IV to decrypt the first network packet sent by the agent to the C2 server later.

Below is the decrypted config of the gopher agent.

```
go run main.go ..\..\full_memory.dmp
{
  "profile": {
    "type": 2421052563,
    "addresses": [
      "192.168.91.133:8484"
    ],
    "banner_size": 1,
    "conn_timeout": 0,
    "conn_count": 1000000000,
    "use_ssl": false,
    "ssl_cert": null,
    "ssl_key": null,
    "ca_cert": null
  },
  "aes_key": "c7288225d356417174cabc03bc2700e4",
  "iv": "12ab1c5770f5d92e2f55457f",
  "key_offset": 5691776,
  "config_size": 122
}
```

From the extracted config, we can see the C2 IP address and port number. We also have the AES GCM key and the IV.

### PCAP analysis

Since we have the C2 server IP and the port number. Let's check the number of packets sent by the client to the C2 server. We will filter for packets containing tcp payload since those are the packets containing data.

```
└─$ tshark -Y "ip.addr == 192.168.91.133 && tcp.dstport == 8484 && tcp.payload" -r network.pcapng | more 
 5287  49.255932 192.168.91.191 → 192.168.91.133 TCP 292 54770 → 8484 [PSH, ACK] Seq=1 Ack=2 Win=32128 Len=226 TSval=1717558140 TSecr=242572312
12629 638.954422 192.168.91.191 → 192.168.91.133 TCP 263 54770 → 8484 [PSH, ACK] Seq=227 Ack=103 Win=32128 Len=197 TSval=1718147848 TSecr=243161856
12765 650.119590 192.168.91.191 → 192.168.91.133 TCP 1514 54770 → 8484 [ACK] Seq=424 Ack=208 Win=32128 Len=1448 TSval=1718159013 TSecr=243173066
12766 650.119603 192.168.91.191 → 192.168.91.133 TCP 1514 54770 → 8484 [ACK] Seq=1872 Ack=208 Win=32128 Len=1448 TSval=1718159013 TSecr=243173066
```

### Decryption of the packets

#### First packet

The first packet after infection is sent by the gopher agent to the C2 server. We will use the AES GCM key and the IV identified above to decrypt it.

Below is the structure of the SessionInfo packet sent by the client to the server.

```
type SessionInfo struct {
	Process    string `msgpack:"process"`
	PID        int    `msgpack:"pid"`
	User       string `msgpack:"user"`
	Host       string `msgpack:"host"`
	Ipaddr     string `msgpack:"ipaddr"`
	Elevated   bool   `msgpack:"elevated"`
	Acp        string `msgpack:"acp"`
	Oem        string `msgpack:"oem"`
	Os         string `msgpack:"os"`
	OSVersion  string `msgpack:"os_version"`
	EncryptKey []byte `msgpack:"encrypt_key"`
}
```

From the SessionInfo object, we can see the `encrypt_key` field. This key will be the session key that is used by the client and the server to encrypt and decrypt all the packets exchanged after the first packet.

The structure of the packets is as shown below.

| Offset | Len | Name | Description |
| --- | --- | --- | --- |
| 0 | 4 | Length | Length of the ciphertext |
| 4 | 16 | IV | AES GCM IV. This will be different for each packet |
| 16 | Length | Ciphertext | Encrypted data |
| Length - 16 | 16 | AES GCM tag | This is the authentication tag used in AES GCM decryption |

Below is the decrypted SessionInfo object extracted from the first network packet sent by the gopher agent to the C2 server.

```
{
    "process": "memfd:libudev-cache",
    "pid": 5197,
    "user": "dev",
    "host": "dev-work01",
    "ipaddr": "192.168.91.191",
    "elevated": false,
    "os": "linux",
    "os_version": "Ubuntu 24.04",
    "encrypt_key": "a0d03c1a2ed1f66b82fb5e8241e1f46c"
}
```

Now we have the AES key used to encrypt and decrypt all the remaining packets. I've included the full code to extract the decrypted streams from the PCAP in the Appendix.

Below are a few decrypted messages extracted from the client to server network packets.

To summarize, based on the decrypted packets, we can see that the attacker enumerated the list of files in the directory, `/home/dev/projects/technova-dev-service` and then compressed the contents of the directory to a ZIP archive in the path, `/tmp/tmp.zip` which was exfiltrated to the attacker's server by the gopher agent.

```
===== CLIENT -> SERVER MESSAGES =====

--- Decrypted Message #1 ---

{
    "type": 1,
    "object": [
        {
            "code": 3,
            "id": 1446581947,
            "data": {
                "output": "uid=1000(dev) gid=1000(dev) groups=1000(dev),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),100(users),114(lpadmin)\n"
            }
        }
    ]
}
....

--- Decrypted Message #3 ---

{
    "type": 1,
    "object": [
        {
            "code": 3,
            "id": 3026683914,
            "data": {
                "output": "dev adm cdrom sudo dip plugdev users lpadmin\n"
            }
        }
    ]
}

...

--- Decrypted Message #13 ---

{
    "type": 1,
    "object": [
        {
            "code": 12,
            "id": 4154001035,
            "data": {
                "result": true,
                "status": "",
                "path": "/home/dev/projects/technova-dev-service",
                "files": [
                    {
                        "mode": "-rwxrwxrwx",
                        "nlink": 1,
                        "user": "dev",
                        "group": "dev",
                        "size": 95,
                        "date": "Jun  1 02:10",
                        "filename": "README.md",
                        "is_dir": false
                    },
                    {
                        "mode": "drwxrwxrwx",
                        "nlink": 2,
                        "user": "dev",
                        "group": "dev",
                        "size": 4096,
                        "date": "Jun  2 05:17",
                        "filename": "config",
                        "is_dir": true
                    },
                    {
                        "mode": "-rwxrwxrwx",
                        "nlink": 1,
                        "user": "dev",
                        "group": "dev",
                        "size": 182,
                        "date": "Jun  1 02:11",
                        "filename": "main.py",
                        "is_dir": false
                    },
...

--- Decrypted Message #22 ---

{
    "type": 2,
    "object": [
        {
            "command_id": 5,
            "job_id": "c23e8d5d",
            "data": {
                "id": 2126187672,
                "path": "/tmp/tmp.zip",
                "size": 1656,
                "content": "PK\u0003\u0004\u0014\u0000\u0000\u0000\u0000\u0000",
                "start": true,
                "finish": false,
                "canceled": false
            }
        }
    ]
}

...
}
```

I wrote another script to parse out the ZIP archive from the above output. After extracting the ZIP archive and decompressing it, below are the contents

```
$ tree .
.
└── technova-dev-service
    ├── README.md
    ├── config
    │   └── dev.env
    └── main.py
```

Flag was inside the dev.env file as shown below.
```
$ cat dev.env 
DEBUG=true
SECRET_KEY=HTB{d3l3t3d_d03snt_m34n_n0t_3xsi5tEd}
```

### Appendix

Script to decrypt the packets sent from client to server

```python
import pyshark
import msgpack
from Crypto.Cipher import AES
import binascii
import json
import io
import base64

PCAP = "network.pcapng"

SESSION_KEY = bytes.fromhex("a0d03c1a2ed1f66b82fb5e8241e1f46c")

SERVER_IP = "192.168.91.133"
SERVER_PORT = "8484"
CLIENT_IP = "192.168.91.191"

def pretty(obj):
    def convert(o):
        if isinstance(o, (bytes, bytearray)):
            try:
                return o.decode("utf-8")
            except UnicodeDecodeError:
                return {"__base64__": base64.b64encode(o).decode()}

        if isinstance(o, msgpack.ExtType):
            return {
                "__exttype__": o.code,
                "__data__": base64.b64encode(o.data).decode()
            }

        if isinstance(o, (list, tuple)):
            return [convert(x) for x in o]

        if isinstance(o, dict):
            new_dict = {}
            for k, v in o.items():
                if isinstance(k, (bytes, bytearray)):
                    try:
                        new_k = k.decode("utf-8")
                    except UnicodeDecodeError:
                        new_k = "__base64key__:" + base64.b64encode(k).decode()
                else:
                    new_k = str(k)

                new_dict[new_k] = convert(v)
            return new_dict

        return o

    safe = convert(obj)
    return json.dumps(safe, indent=4, ensure_ascii=False)

def deep_unpack(obj):
    if isinstance(obj, (bytes, bytearray)):
        try:
            unpacked = msgpack.unpackb(obj, raw=False)
            return deep_unpack(unpacked)
        except Exception:
            return obj

    if isinstance(obj, list):
        return [deep_unpack(x) for x in obj]

    if isinstance(obj, dict):
        return {k: deep_unpack(v) for k, v in obj.items()}

    return obj


def unpack_msgpack_stream(raw):
    buf = io.BytesIO(raw)
    up = msgpack.Unpacker(buf, raw=False)
    out = []
    try:
        for obj in up:
            out.append(obj)
    except Exception:
        pass
    return out

def extract_tcp_streams():
    client_to_server = bytearray()

    cap = pyshark.FileCapture(
        PCAP,
        display_filter=f"tcp.port == {SERVER_PORT}"
    )

    for pkt in cap:
        if not hasattr(pkt, "tcp"):
            continue
        if not hasattr(pkt.tcp, "payload"):
            continue

        hexdata = pkt.tcp.payload.replace(":", "")
        if len(hexdata) == 0:
            continue

        raw = bytes.fromhex(hexdata)

        src = pkt.ip.src
        dst = pkt.ip.dst

        if src == CLIENT_IP and pkt.tcp.dstport == SERVER_PORT:
            client_to_server.extend(raw)

    return bytes(client_to_server)

def decrypt_gcm(blob, key):
    if len(blob) < 4:
        return None

    msg_len = int.from_bytes(blob[:4], "big")
    enc = blob[4:4 + msg_len]

    if len(enc) < 12 + 16:  # nonce + tag
        return None

    nonce = enc[:12]
    ciphertext = enc[12:-16]
    tag = enc[-16:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    try:
        pt = cipher.decrypt_and_verify(ciphertext, tag)
        return pt
    except Exception:
        return None

def split_length_prefixed_stream(stream):
    """
    Takes a TCP byte-stream and yields each length-prefixed Gopher message.
    """
    out = []
    i = 0
    while i + 4 <= len(stream):
        msg_len = int.from_bytes(stream[i:i + 4], "big")
        if msg_len == 0:
            i += 4
            continue

        start = i
        end = i + 4 + msg_len
        if end > len(stream):
            break

        out.append(stream[start:end])
        i = end

    return out

def decode_and_print(messages, direction):
    print(f"\n\n===== {direction} MESSAGES =====")

    for idx, blob in enumerate(messages):
        pt = decrypt_gcm(blob, SESSION_KEY)
        if not pt:
            continue

        print(f"\n--- Decrypted Message #{idx} ---\n")

        objs = unpack_msgpack_stream(pt)
        for o in objs:
            clean = deep_unpack(o)
            print(pretty(clean))


def main():
    print("[*] Reassembling TCP streams...")
    c2s_stream = extract_tcp_streams()

    print(f"Client->Server stream length: {len(c2s_stream)}")

    print("[*] Splitting client->server...")
    c2s_msgs = split_length_prefixed_stream(c2s_stream)

    decode_and_print(c2s_msgs, "CLIENT -> SERVER")

if __name__ == "__main__":
    main()
```

Script to extract the ZIP archive from the output generated by above script
```python
import json
import base64
import re
import sys

def extract_zip_from_logs(input_file, output_file):
    print(f"Reading from {input_file}...")
    
    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            full_text = f.read()
    except FileNotFoundError:
        print(f"Error: {input_file} not found.")
        return

    zip_binary = bytearray()
    
    fragments = re.split(r'--- Decrypted Message #\d+ ---', full_text)
    
    chunks_found = 0

    for fragment in fragments:
        fragment = fragment.strip()
        if not fragment:
            continue

        start_idx = fragment.find('{')
        end_idx = fragment.rfind('}')

        if start_idx == -1 or end_idx == -1:
            continue

        json_str = fragment[start_idx:end_idx+1]

        try:
            data_obj = json.loads(json_str)
        except json.JSONDecodeError:
            continue

        if "object" in data_obj and isinstance(data_obj["object"], list):
            for item in data_obj["object"]:
                if not isinstance(item, dict):
                    continue
                    
                job_data = item.get("data")

                if not job_data:
                    continue
                
                if job_data.get("path") == "/tmp/tmp.zip":
                    chunks_found += 1
                    content = job_data.get("content")
                    
                    if content is None:
                        continue

                    if isinstance(content, dict) and "__base64__" in content:
                        b64_str = content["__base64__"]
                        try:
                            decoded_bytes = base64.b64decode(b64_str)
                            zip_binary.extend(decoded_bytes)
                        except Exception as e:
                            print(f"Error decoding base64: {e}")
                    elif isinstance(content, str):
                        try:
                            raw_bytes = content.encode('latin1')
                            zip_binary.extend(raw_bytes)
                        except UnicodeEncodeError:
                            print("Warning: Could not encode string content with latin1")

    if chunks_found > 0:
        print(f"Found {chunks_found} chunks matching '/tmp/tmp.zip'.")
        print(f"Writing {len(zip_binary)} bytes to {output_file}...")
        
        with open(output_file, 'wb') as f:
            f.write(zip_binary)
            
        print("Done.")
    else:
        print("No matching data found for /tmp/tmp.zip")

if __name__ == "__main__":
    extract_zip_from_logs("decrypted_client_packets.txt", "tmp.zip")
```
