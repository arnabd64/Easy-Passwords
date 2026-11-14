# Easy Passwords

<!-- Python Version Badges -->
[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/)
[![Python 3.13](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)
[![Python 3.14](https://img.shields.io/badge/python-3.14-blue.svg)](https://www.python.org/)
[![Python 3.15](https://img.shields.io/badge/python-3.15-blue.svg)](https://www.python.org/)

<!-- Code Coverage Badge -->

**Password hashing without the headache.** Two functions, safe defaults, zero config. 🎉

Hashing passwords is easy to get wrong. `easy_passwords` wraps [`cryptography`](https://cryptography.io) with sane, OWASP-aligned defaults so you can just call `hash_password()` and `verify_password()` and get on with your day. ☕

## ✨ Why you'll like it

- 😌 **Zero config**: the defaults follow OWASP / RFC 9106 recommendations
- 🧂 **Salts handled for you**: random salt generated with `secrets`
- 📦 **PHC string output**: salt and parameters live inside the hash, so you store one string
- 🛡️ **Guard rails**: inputs and parameters are validated (weak settings and DoS-sized settings are rejected)
- 🤫 **Safe verification**: `verify_password()` never raises, it just returns `True` or `False`
- 🎛️ **Tweakable**: power users can tune every knob

## 📥 Install

```bash
pip install easy_passwords
```

> Requires the `cryptography` package. Argon2id needs a version that ships `Argon2id` (44.0+).

## 🚀 Quickstart

Pick an algorithm. **Argon2id** is the modern recommendation. **scrypt** is a solid alternative.

### 🥇 Argon2id

```python
from easy_passwords import argon2

hashed = argon2.hash_password("correct horse battery staple")
# $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>

argon2.verify_password("correct horse battery staple", hashed)  # True ✅
argon2.verify_password("wrong password", hashed)                # False ❌
```

### 🥈 scrypt

```python
from easy_passwords import scrypt

hashed = scrypt.hash_password("correct horse battery staple")
# $scrypt$ln=17,r=8,p=1$<salt>$<hash>

scrypt.verify_password("correct horse battery staple", hashed)  # True ✅
scrypt.verify_password("wrong password", hashed)                # False ❌
```

That's it. Store `hashed` in your database (a `VARCHAR`/`TEXT` column is fine) and call `verify_password` at login. 🎯

## 🎛️ For the tinkerers

Know what you're doing? Pass keyword arguments to override the defaults.

```python
# Argon2id
argon2.hash_password(
    "hunter2",
    salt_length=32,      # bytes (16-64)
    hash_length=32,      # bytes (16-64)
    iterations=3,        # time cost (2-100)
    lanes=4,             # parallelism (1-64)
    memory_cost=65536,   # KiB (19456 - 2097152)
)

# scrypt
scrypt.hash_password(
    "hunter2",
    salt_length=32,      # bytes (8-64)
    hash_length=32,      # bytes (8-64)
    ln=17,               # log2(N), CPU/memory cost (10-20)
    r=8,                 # block size (4-16)
    p=1,                 # parallelism (1-4)
)
```

| Setting | Argon2id default | scrypt default |
|---|---|---|
| Salt | 32 bytes | 32 bytes |
| Hash | 32 bytes | 32 bytes |
| Cost | `t=2`, `m=19 MiB` | `ln=17` (N=131072) |
| Parallelism | `p=1` | `p=1` |

Out-of-range values raise `ValueError`, and wrong types raise `TypeError`, so mistakes show up at hash time instead of in production. 🚨

## 🔎 Good to know

- 🔑 Passwords must be non-empty strings of at most **1024 characters**.
- 🔄 Hashes carry their own parameters, so you can raise the defaults later and old hashes still verify.
- 🧪 `verify_password` returns `False` on malformed hashes or bad input instead of throwing.
- 🧠 Not sure which to use? Go with **Argon2id** and leave the defaults alone.

## 📄 License

Add your license here (MIT, Apache-2.0, ...). 💙