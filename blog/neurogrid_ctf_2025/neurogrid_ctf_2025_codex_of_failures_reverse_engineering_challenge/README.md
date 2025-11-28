# Neurogrid CTF 2025 - Codex of failures reverse engineering challenge write up

### Overview

| Challenge name | Codex of Failures |
| --- | --- |
| Solution author | Sudeep Singh |
| Category | Forensics |

In this challenge, we are provided a Linux 64-bit ELF binary which expects a key as an input, decrypts the flag at runtime and prints the flag. We have to find the correct decryption key in order to reveal the decrypted flag.

Each byte of the decryption key is derived from a specific error code that is generated at runtime. Binary also uses basic anti-debugging techniques.

### Initial analysis

Checks performed by the binary

1. Checks whether the uid or the gid are 0 to ensure the binary is not being run by a privileged user.
2. Opens /proc/self/status and checks for "CapEff:" to ensure the process does not have any capabilities.

If the above checks pass, then it asks the user to enter the key.

After this, it calls fork() to spawn a child process. The decryption key validation and the flag decryption happen in the child process.

Before the key is validated, it checks whether the binary is being debugged as shown below.

```
signed __int64 sub_3CED()
{
  return sys_ptrace(0LL, 0LL, 0LL, 0LL);
}
```
Above subroutine will return a non zero value when the process is being debugged.

Key validation

1. Length check: Binary checks to ensure the length of the license key is 28.
2. Now it begins fetching the error codes by calling subroutines mentioned in the array at address 0x04CC80 in the .data.rel.ro section.

```
    for ( i = 0LL; i < std::string::length(v27); v23 = (v23 & (v14 == *(char *)std::string::at(v27, i++) - 47)) != 0 )
    {
      v13 = (__int64 (**)(void))sub_51C8(off_4CC80, i);
      v14 = (*v13)();
    }
```

List of subroutines

```
.data.rel.ro:000000000004CC80 off_4CC80       dq offset sub_34AA      ; DATA XREF: main+35A↑o
.data.rel.ro:000000000004CC88                 dq offset sub_3CCC
.data.rel.ro:000000000004CC90                 dq offset sub_3886
.data.rel.ro:000000000004CC98                 dq offset sub_3493
.data.rel.ro:000000000004CCA0                 dq offset sub_34AA
.data.rel.ro:000000000004CCA8                 dq offset sub_34D0
.data.rel.ro:000000000004CCB0                 dq offset sub_34EC
.data.rel.ro:000000000004CCB8                 dq offset sub_3A9D
.data.rel.ro:000000000004CCC0                 dq offset sub_3886
.data.rel.ro:000000000004CCC8                 dq offset sub_36E8
.data.rel.ro:000000000004CCD0                 dq offset sub_3BEA
.data.rel.ro:000000000004CCD8                 dq offset sub_3C82
.data.rel.ro:000000000004CCE0                 dq offset sub_34AA
.data.rel.ro:000000000004CCE8                 dq offset sub_34EC
.data.rel.ro:000000000004CCF0                 dq offset sub_3A9D
.data.rel.ro:000000000004CCF8                 dq offset sub_3886
.data.rel.ro:000000000004CD00                 dq offset sub_3CCC
.data.rel.ro:000000000004CD08                 dq offset sub_3C82
.data.rel.ro:000000000004CD10                 dq offset sub_3BEA
.data.rel.ro:000000000004CD18                 dq offset sub_36E8
.data.rel.ro:000000000004CD20                 dq offset sub_3886
.data.rel.ro:000000000004CD28                 dq offset sub_3A9D
.data.rel.ro:000000000004CD30                 dq offset sub_34EC
.data.rel.ro:000000000004CD38                 dq offset sub_34D0
.data.rel.ro:000000000004CD40                 dq offset sub_34AA
.data.rel.ro:000000000004CD48                 dq offset sub_3493
.data.rel.ro:000000000004CD50                 dq offset sub_34EC
.data.rel.ro:000000000004CD58                 dq offset sub_34D0
.data.rel.ro:000000000004CD60                 dq offset sub_516F
```

Each subroutine in this array is crafted to trigger a specific error. The error code is returned and validated against the decryption key as shown below.

```
error_code == *(char *)std::string::at(decryption_key, i++) - 47
```

Above expression must evaluate to true for every error code. We can rewrite this as below.
```
decryption_key[i] = error_code[i] + 47
```
To quickly solve this challenge, I patched the binary to remove the anti-debugging checks and then set a breakpoint at the return address (0x42E8), each time these subroutines were invoked as shown below.

```
.text:00000000000042CD
.text:00000000000042CD loc_42CD:                               ; CODE XREF: main+3BF↓j
.text:00000000000042CD                 mov     rax, [rbp+var_68]
.text:00000000000042D1                 lea     rdx, array_of_subroutines
.text:00000000000042D8                 mov     rsi, rax
.text:00000000000042DB                 mov     rdi, rdx
.text:00000000000042DE                 call    lookup_index_in_array
.text:00000000000042E3                 mov     rax, [rax]
.text:00000000000042E6                 call    rax             ; invoke the error generating subroutine
.text:00000000000042E8                 mov     ebx, eax        ; eax = error code
.text:00000000000042EA                 mov     rdx, [rbp+var_68]
.text:00000000000042EE                 lea     rax, [rbp+var_60]
.text:00000000000042F2                 mov     rsi, rdx
.text:00000000000042F5                 mov     rdi, rax
```

This way, we can collect all the error codes and use them to derive the decryption key.
```
errno_seq = [2,10,6,1,2,3,4,7,6,5,8,9,2,4,7,6,10,9,8,5,6,7,4,3,2,1,4,3]
```

The encrypted flag is stored in the .rodata section at 0x4AC40 and the flag decryption subroutine is below

```
__int64 __fastcall sub_4ABE(__int64 a1, __int64 encrypted_flag, __int64 license_key)
{
  char v3; // bl
  _BYTE *v4; // rax
  unsigned __int64 i; // [rsp+28h] [rbp-18h]

  std::string::basic_string(a1);
  for ( i = 0LL; i <= 0x1B; ++i )
  {
    v3 = *(_BYTE *)lookup_index_in_array(encrypted_flag, i);
    v4 = (_BYTE *)std::string::at(license_key, i);
    std::string::push_back(a1, (unsigned int)(char)(v3 ^ *v4));
  }
  return a1;
}
```

Now we can decrypt the flag as shown below
```
encoded = [
    0x79,0x6D,0x77,0x4B,0x01,0x50,0x55,0x63,
    0x46,0x77,0x77,0x4C,0x00,0x03,0x58,0x6A,
    0x4E,0x09,0x43,0x7C,0x6A,0x05,0x41,0x60,
    0x01,0x42,0x06,0x4F
]

errno_seq = [2,10,6,1,2,3,4,7,6,5,8,9,2,4,7,6,10,9,8,5,6,7,4,3,2,1,4,3]

key = [e + 0x2F for e in errno_seq]
key_string = ''.join(chr(k) for k in key)

flag = ''.join(chr(enc ^ k) for enc, k in zip(encoded, key))

print("Key:", key_string)
print("Flag:", flag)
```

Flag: HTB{0bfUsC@t10n_w1tH_3rR0r5}




