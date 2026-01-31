## Marriage System Overview

### Marriage States

| Value | State | Description |
|-------|-------|-------------|
| 0x01 | Needs Remarry | Syscon awaiting CELL pairing (factory state or after wipe) |
| 0x02 | Married | CELL and Syscon successfully paired |
| Other | Corrupted | Invalid state, triggers automatic reset to 0x01 |

### SPCR Region Structure

The SPCR (Syscon Per-Console Region) contains the encrypted marriage data:

| Offset | Size | Description |
|--------|------|-------------|
| 0x00-0x0F | 16 bytes | Encrypted marriage status |
| 0x10-0x1F | 16 bytes | Encrypted Key 0x010 (EID1 second layer decryption key) |
| 0x20-0x2F | 16 bytes | CMAC of bytes 0x10-0x1F |
| 0x30+ | Variable | Session keys and additional encrypted data |

**SPCR Location in EEPROM:**
- Mullion (CXR713/714): 0x0000-0x2800
- Sherwood (SW): 0x3000-0x5800

---

## Cryptographic Architecture

### Key Hierarchy

The following keys were identified in the firmware at their respective addresses:

| Address | Key (Hex) | Name | Purpose |
|---------|-----------|------|---------|
| 0x4558 | `2EA267093B4556ED9D3BE62E115D6D59` | FactoryInit_Password | Factory wipe authentication, Key 0x000 |
| 0x4568 | `C8979F5726F6A130CB9309A2F7AA0C84` | GARBAGE Key | Key derivation iteration (Key 0x010) |
| ~~0x4578~~? | ~~`6692F714E467465C249941AF7E7570FE`~~? | ~~Unknown~~? | ~~Possibly Key 0x020~~? | 
| ~~0x4588~~? | ~~`871CBB03E52889BC9C1A13B5D7D278ED`~~? | ~~Unknown~~? | ~~Additional key material~~? |
| 0x4598 | `2B1072970A7576D8E59803977FF2E459` | AUTH2 Related | Session authentication |
| 0x45A8 | `C50A57BEC9F2A2EE1C4478526EE24B88` | AUTH1 Related | Session authentication |
| 0x45B8 | `3350BD7820345C29056A223BA220B323` | Fixed Auth1 Response | Authentication verification |
| 0x45C8 | `3C4689E97EDF5A86C6F174888D6085CF` | Fixed Auth2 Response | Authentication verification |
| 0x5800 | `359E7E40B57DD30752584FC8330A77A6` | NVS Secure Key | Hardware-level SNVS decryption |

### Key Derivation Constants

Located at 0x4518-0x4548, used in session key derivation:

```
byte_4518: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01
byte_4528: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 02
byte_4538: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03
byte_4548: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 04
```

### Marriage Status Constants (Plaintext)

| Address | Value | Meaning |
|---------|-------|---------|
| 0x44F8 | `00000000000000000000000000000001` | Needs remarry |
| 0x4508 | `00000000000000000000000000000002` | Already married |

---

## AES Implementation

### Identified Functions

| Address | Function | Purpose |
|---------|----------|---------|
| 0x3288 (`sub_3288`) | AES-128 Key Expansion | Expands 16-byte key to 44 round keys |
| 0x32FA (`sub_32FA`) | AES Decryption Key Schedule | Transforms encryption schedule for decryption |
| 0x33DE (`sub_33DE`) | AES-128 Encrypt Block | Single block encryption |
| 0x36CC (`sub_36CC`) | AES-128 Decrypt Block | Single block decryption |
| 0x3992 (`sub_3992`) | Key Expansion Wrapper | Thunk to sub_3288 |
| 0x399C (`sub_399C`) | Decrypt Key Schedule Wrapper | Thunk to sub_32FA |
| 0x39A4 (`sub_39A4`) | Encrypt Block Wrapper | Thunk to sub_33DE |
| 0x39AC (`sub_39AC`) | Decrypt Block Wrapper | Thunk to sub_36CC |
| 0x36B90 (`sub_36B90`) | Second AES Implementation | Alternative crypto domain |

### S-Box Locations

Two AES S-box instances were found:
- **Primary S-box**: 0x04608 (used by main crypto functions)
- **Secondary S-box**: 0x428C4 (used by sub_36B90)

The S-box area includes extended T-tables:
- S-box: 256 bytes
- Inverse S-box: 256 bytes (offset +256)
- T-tables: 4 x 1024 bytes

---

## Secure Storage Architecture

### Two Storage Systems

The firmware uses two distinct storage access methods:

#### 1. NVS Secure Read (`nvs_read_secure` at 0x3D50)

Hardware protected access to the SPCR region with MMIO unlock/lock sequence:

```c
int nvs_read_secure(uint32_t half_off, void *dst, unsigned int len)
{
    // Load decryption key from ROM
    for (i = 0; i < 16; i++)
        byte_200D018[i] = aes_s_box[i + 0x11F8];  // Key at 0x5800
    
    sub_3992();  // AES key expansion
    sub_39A4();  // AES encrypt (generates unlock code)
    
    // Unlock secure region via MMIO
    MEMORY[0xA66D0844] = byte_200D018[0] ^ 0x4A;
    MEMORY[0xA66D039C] = byte_200D019 ^ 0x27;
    MEMORY[0xFEDF0E40] = byte_200D01A ^ 0x26;
    MEMORY[0xFEDF0060] = byte_200D01B ^ 0x2B;
    
    // Read data with XOR decryption
    while (len > 0) {
        *dst++ = *(src + offset) ^ MEMORY[0x3004F08];
    }
    
    // lock secure region
    MEMORY[0xA66D0844] = byte_200D01C ^ 0x3B;
    // ... etc
}
```

#### 2. Store Read (`read_from_store` at 0x3D8E)

Direct EEPROM access via SPI bus:

```c
int read_from_store(uint16_t off, void *dst, unsigned int len)
{
    return store_read_block(dev, off, dst, len);
}
```

The `dev` structure at 0x42060 determines access mode:
- Type 0: Linear read (internal flash)
- Type 1: Indexed block read (EEPROM via SPI)

---

## Marriage Status Functions

### Status Decryption (`sub_27C`)

**Address**: 0x027C

Reads and decrypts the marriage status from SPCR:

```c
int sub_27C(void *output)
{
    // Read encrypted status from SNVS offset 0
    nvs_read_secure(0, &encrypted_status, 16);
    
    // Read decryption key from internal store
    read_from_store(0, &decryption_key, 16);
    
    // Setup AES decryption
    sub_399C(&encrypted_status, &key_schedule);  // Key expansion for decrypt
    sub_39AC();  // Decrypt block
    
    // Return decrypted status
    mem_copy(output, &decrypted, 16);
    
    // Secure cleanup
    mem_zero(&key_schedule, 0, 0xC0);
    mem_zero(&encrypted_status, 0, 16);
    mem_zero(&decryption_key, 0, 16);
}
```

### Quick Marriage Check (`sub_354`)

**Address**: 0x0354

Fast check if Syscon is married:

```c
int sub_354()
{
    uint8_t status[16];
    int result;
    
    result = sub_27C(status);  // Decrypt status
    if (!result) {
        memcmp_safe(&result, status, &b, 16);  // Compare to "married" value
        result = (result == 0);  // Return 1 if married
    }
    
    mem_zero(status, 0, 16);
    return result;
}
```

### Full Status Validation (`sub_734`)

**Address**: 0x0734

Comprehensive status check with auto repair:

```c
int sub_734()
{
    uint8_t status[16];
    
    sub_27C(status);  // Decrypt current status
    
    // Check if "needs remarry" (0x01)
    memcmp_safe(&result, status, byte_44F8, 16);
    if (result == 0) return 0;  // Waiting for CELL
    
    // Check if "married" (0x02)
    memcmp_safe(&result, status, &b, 16);
    if (result == 0) return 0;  // All good
    
    // Status corrupted! Read and verify key data
    nvs_read_secure(0x10, &key_data, 16);   // Encrypted Key 0x010
    nvs_read_secure(0x20, &cmac_data, 16);  // CMAC
    
    // Verify CMAC
    sub_3FE(&key_data, 16, &cmac_data, 16);
    
    // Reset status to "needs remarry"
    sub_2EA(byte_44F8);
    
    return result;
}
```

### Status Write (`sub_2EA`)

**Address**: 0x02EA

Encrypts and writes new marriage status:

```c
void sub_2EA(const void *new_status)
{
    // Read current encrypted data (to get encryption context)
    nvs_read_secure(0, &encrypted, 16);
    
    // Copy new plaintext status
    mem_copy(&plaintext, new_status, 16);
    
    // Encrypt
    sub_3992();  // Key expansion
    sub_39A4();  // AES encrypt
    
    // Verify and write to NVS
    sub_2070C(0, &encrypted_new, 16);
    
    // Secure cleanup
    mem_zero(&key_schedule, 0, 0xC0);
    mem_zero(&encrypted, 0, 16);
    mem_zero(&plaintext, 0, 16);
}
```

---

## CELL Communication Protocol

### Message Thread (`sub_12BA2`)

**Address**: 0x12BA2

Main loop processing secure commands from CELL:

```c
void sub_12BA2()
{
    sub_1706();  // Initialize
    
    while (1) {
        // Wait for message from CELL
        sub_E9D6(thread_id, &msg, 0, 0);
        
        // Extract and validate message
        sid = msg_hdr_get_sid_byte(msg);
        len = msg_hdr_get_len(msg);
        
        // Process command
        sub_2228(&msg->payload, len, response, &response_len);
        
        // Send response
        sub_12C0A(&response_hdr, response, response_len);
        
        msg_free(msg);
    }
}
```

### Packet Parser (`sub_2228`)

**Address**: 0x2228

Validates and dispatches incoming commands:

```c
int sub_2228(uint8_t *payload, int len, uint8_t *response, uint32_t *resp_len)
{
    // Validate length
    if (len - 32 >= 0x291) return ERROR;
    
    // Verify CMAC
    nvs_read_secure(0x110, &cmac_key, 16);
    sub_43A(payload, len - 16, &cmac_key, &payload[len - 16]);
    
    // Check magic bytes at offset 3-4
    memcmp_safe(&result, &payload[3], &byte_44D8, 2);  // Must be 0xAD1A
    if (result) return ERROR;
    
    class = payload[0];
    cmd = payload[1];
    
    if (class < 8) {
        // Commands 0-7: Require married status
        sub_3134(cmd, &payload[16], len - 32, response, resp_len, class);
    }
    else if (class == 255) {
        // Command class 255: Marriage/factory commands
        sub_31C8(cmd, &payload[16], len - 32, response, resp_len);
    }
}
```

### Packet Format

```
Offset  Size  Description
──────────────────────────────────
0x00    1     Command Class (0-7 or 255)
0x01    1     Subcommand
0x02    1     Reserved
0x03    2     Magic (0xAD1A)
0x05    11    Random padding ?
0x10    N     Payload data
N+0x10  16    CMAC signature
```

---

## Command Dispatcher

### Class 255 Handler (`sub_31C8`)

**Address**: 0x31C8

Handles marriage and factory commands:

```c
void sub_31C8(int cmd, uint8_t *payload, uint32_t len, void *response, uint32_t *resp_len)
{
    switch (cmd) {
        case 0:
            // Get current status (decrypted)
            sub_27C(response);
            *resp_len = 16;
            break;
            
        case 1:
            // REMARRY - requires 0x290 bytes
            sub_18D6(payload, len, resp_len);
            break;
            
        case 5:
            // Export keys (must be married)
            if (sub_354() == 1) {
                sub_508(keys_buffer);
                mem_copy(response, &exported_key, 16);
                *resp_len = 16;
            }
            break;
            
        case 6:
            // Get console info
            sub_1ABC(response);
            *resp_len = 128;
            break;
            
        case 255:
            // FACTORY WIPE
            sub_17F0(payload, len, resp_len);
            break;
    }
}
```

### Class 0-7 Handler (`sub_3134`)

**Address**: 0x3134

Handles operational commands (requires married status):

```c
void sub_3134(int cmd, void *payload, uint32_t len, void *response, uint32_t *resp_len, int class)
{
    // Must be married
    if (sub_354() != 1) return;
    
    // Load session keys
    sub_508(session_keys);
    
    switch (cmd) {
        case 2:
            sub_1CE6(class, session_keys, payload, len, response, resp_len);
            break;
        case 3:
            sub_1EA4(class, session_keys, payload, len, response, resp_len);
            break;
        case 4:
            sub_1FB8(class, session_keys, payload, len, response, resp_len);
            break;
    }
    
    mem_zero(session_keys, 0, 0x280);
}
```

---

## Factory Wipe Function

### `sub_17F0` - Factory Reset

**Address**: 0x17F0

Wipes entire SPCR region after password verification:

```c
void sub_17F0(int payload, int len, uint32_t *resp_len)
{
    // require exactly 48 byte payload
    if (len != 48) {
        return ERROR_INVALID_LENGTH;
    }
    
    // verify FactoryInit_Password at payload[16:32]
    memcmp_safe(&result, (payload + 16), &byte_4558, 16);
    if (result != 0) {
        return -2147482600;
    }
    
    // password verified now wipe SPCR
    *resp_len = 0;
    sub_3992();  // setup AES
    
    // fill buffer with 0xFF
    mem_zero(&wipe_buffer, 0xFF, 16);
    
    // encrypt and write 0xFF to entire SPCR
    offset = 0;
    do {
        sub_39A4();  // encrypt
        sub_2070C(offset, &wipe_buffer, 16);  // write
        offset += 16;
    } while (offset < 0x2560);  // 9568 bytes
    
    // finish up
    sub_1706();
    
    // notify completion
    sub_EAE(0, &loc_26B0, 16, 400, 0, 0, &status, 0x20, ...);
}
```

**Factory Wipe Payload Format:**
```
Offset  Size  Content
──────────────────────────────────
0x00    16    Random/unused
0x10    16    FactoryInit_Password (2EA267093B4556ED9D3BE62E115D6D59)
0x20    16    Random/unused
```

---

## Remarry Function

### `sub_18D6` - Full Remarry

**Address**: 0x18D6

Performs complete CELL-Syscon pairing:

```c
void sub_18D6(uint8_t *payload, int len, uint32_t *resp_len)
{
    // Require exactly 0x290 (656) bytes
    if (len != 0x290) {
        return 0x80000402; // invalid length
    }
    
    // Verify current status
    sub_27C(current_status);
    memcmp_safe(&result, current_status, byte_44F8, 16);
    if (result != 0) {
        return 0x8000040B;  // not in "needs remarry" state
    }
    
    // Read and decrypt payload key
    nvs_read_secure(0x20, &cmac_key, 16);
    sub_4C6(&decrypted_payload, 0x280, &cmac_key, 16);
    
    // Verify payload CMAC
    sub_43A(payload, 0x280, &cmac_key, &payload[640]);
    if (result != 0) {
        return 0x8000040C;  // cmac failed?
    }
    
    // Derive 4 session keys
    for (i = 0; i < 4; i++) {
        result = sub_53C(i, payload);  // Key derivation
        if (result) return result;
    }
    
    // Initialize 8 authentication contexts
    for (j = 0; j < 8; j++) {
        mem_zero(&auth_ctx, 0, 16);
        result = sub_C7C(j, payload, 0, 1, &auth_ctx);
        if (result) return result;
    }
    
    // Commit key data
    sub_1342(0);
    
    // Store encrypted payload
    sub_3FE(payload, 0x280, &cmac_key, 16);
    
    // Write "married" status
    sub_2EA(&b);  // Write 0x02
    
    // Complete 4 authentication handshakes
    for (k = 0; k < 4; k++) {
        do {
            result = sub_7E2(k);  // Auth handshake
        } while (result == 0x80000419);  // Retry on busy
        if (result) return result;
    }
    
    // Success
    *resp_len = 0;
    sub_EAE(0, &loc_26B0, 16, 400, 1, 0, keys, 0x280, ...);
}
```

### Key Derivation (`sub_53C`)

**Address**: 0x053C

Derives session keys from remarry payload:

```c
int sub_53C(int index, const void *payload)
{
    // Calculate key storage offsets
    key_offset = 16 * index + 672;
    session_offset = index * 128 + 736;
    
    // Copy input key material
    mem_copy(&input_key, payload, 16);
    
    // Read master key from secure storage
    nvs_read_secure(64, &master_key, 16);
    
    // Derive keys through multiple AES rounds
    sub_3992();  // Key expansion
    
    for (i = 0; i <= index; i++) {
        sub_39A4();  // Encrypt iteration
    }
    
    mem_copy(&derived_key, &input_key, 16);
    
    // Additional 4 encryption rounds
    for (j = 0; j < 4; j++) {
        sub_39A4();
    }
    
    // Derive multiple subkeys using constants
    mem_copy(temp, byte_4518, 16);  // Counter 1
    sub_3992();
    sub_39A4();
    sub_2070C(key_offset, temp, 16);
    
    mem_copy(temp, byte_4528, 16);  // Counter 2
    // ... repeat for byte_4538, byte_4548
    
    return 0;
}
```
---

## Command Reference

### Class 255 Commands (Marriage/Factory)

| Cmd | Function | Payload Size | Description |
|-----|----------|--------------|-------------|
| 0 | `sub_27C` | 0 | Get decrypted marriage status (returns 16 bytes) |
| 1 | `sub_18D6` | 0x290 | Full remarriage (requires status=0x01) |
| 5 | `sub_508` | 0 | Export session keys (requires married) |
| 6 | `sub_1ABC` | 0 | Get console info (returns 128 bytes) |
| 255 | `sub_17F0` | 48 | Factory wipe (requires password) |

### Class 0-7 Commands (Operational, requires married)

| Cmd | Function | Description |
|-----|----------|-------------|
| 2 | `sub_1CE6` | Secure data operation |
| 3 | `sub_1EA4` | Secure data operation |
| 4 | `sub_1FB8` | Secure data operation |

---

## Function Reference

### Marriage Core Functions

| Address | Name | Purpose |
|---------|------|---------|
| 0x027C | `sub_27C` | Decrypt and return marriage status |
| 0x02EA | `sub_2EA` | Encrypt and write marriage status |
| 0x0354 | `sub_354` | Quick marriage check |
| 0x03FE | `sub_3FE` | Encrypt data with CMAC and write to NVS |
| 0x043A | `sub_43A` | CMAC verification |
| 0x04C6 | `sub_4C6` | Read and decrypt from NVS with CMAC |
| 0x0508 | `sub_508` | Load session keys (if married) |
| 0x053C | `sub_53C` | Session key derivation |
| 0x0734 | `sub_734` | Full status validation with auto repair |
| 0x17F0 | `sub_17F0` | Factory wipe |
| 0x18D6 | `sub_18D6` | Full remarriage |

### Communication Functions

| Address | Name | Purpose |
|---------|------|---------|
| 0x12BA2 | `sub_12BA2` | Secure command thread main loop |
| 0x2228 | `sub_2228` | Packet parser and dispatcher |
| 0x3134 | `sub_3134` | Class 0-7 command handler |
| 0x31C8 | `sub_31C8` | Class 255 command handler |

### Crypto Functions

| Address | Name | Purpose |
|---------|------|---------|
| 0x3288 | `sub_3288` | AES-128 key expansion |
| 0x32FA | `sub_32FA` | AES decrypt key schedule |
| 0x33DE | `sub_33DE` | AES-128 encrypt block |
| 0x36CC | `sub_36CC` | AES-128 decrypt block |
| 0x3992 | `sub_3992` | Key expansion wrapper |
| 0x399C | `sub_399C` | Decrypt key schedule wrapper |
| 0x39A4 | `sub_39A4` | Encrypt wrapper |
| 0x39AC | `sub_39AC` | Decrypt wrapper |

### Storage Functions

| Address | Name | Purpose |
|---------|------|---------|
| 0x3D50 | `nvs_read_secure` | Hardware protected SNVS read |
| 0x3D8E | `read_from_store` | Direct EEPROM read |
| 0x2070C | `sub_2070C` | Verify and write to secure store |

---

## Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│  CELL                                   SYSCON                              │
│  (ss_sc_init_pu.fself)                  (Firmware)                          │
│                                                                             │
│  ┌────────────────────┐                 ┌────────────────────┐              │
│  │ EID1 (flash?)      │                 │ SPCR (EEPROM)      │              │
│  │ ├─ eid_root_key?   │                 │ ├─ 0x00: Status    │              │
│  │ ├─ Per-console?    │                 │ ├─ 0x10: Enc Key   │              │
│  │ └─ Random seed?    │                 │ ├─ 0x20: CMAC      │              │
│  └────────────────────┘                 │ └─ 0x30+: Session  │              │
│                                         └────────────────────┘              │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           FACTORY WIPE SEQUENCE                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. JIG sends Command 255.255:                                              │
│     ┌──────────────────────────────────────────────────────┐                │
│     │[FF][FF][00][AD][1A][...random?...][password][random?]│                │
│     │                      ▲                               │                │
│     │            FactoryInit_Password                      │                │
│     │     (2EA267093B4556ED9D3BE62E115D6D59)               │                │
│     └──────────────────────────────────────────────────────┘                │
│                              │                                              │
│                              ▼                                              │
│  2. Syscon verifies password (sub_17F0)                                     │
│                              │                                              │
│                              ▼                                              │
│  3. Syscon wipes SPCR (0x2560 bytes encrypted 0xFF)                         │
│                              │                                              │
│                              ▼                                              │
│  4. Status becomes "uninitialized" -> decrypts to 0x01                      │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           REMARRY SEQUENCE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. CELL sends Command 255.1 with 0x290 byte payload:                       │
│     ┌──────────────────────────────────────────────────────┐                │
│     │ [FF][01][00][AD][1A][padding][656 bytes data][CMAC]  │                │
│     └──────────────────────────────────────────────────────┘                │
│                              │                                              │
│                              ▼                                              │
│  2. Syscon checks status == 0x01 (sub_27C)                                  │
│     └─ If not 0x01 -> ERROR 0x8000040B                                      │
│                              │                                              │
│                              ▼                                              │
│  3. Verify payload CMAC (sub_43A)                                           │
│     └─ If invalid -> ERROR 0x8000040C                                       │
│                              │                                              │
│                              ▼                                              │
│  4. Derive 4 session keys (sub_53C x 4)                                     │
│     ├─ Key 0: Base session key?                                             │
│     ├─ Key 1: Encryption key?                                               │
│     ├─ Key 2: Decryption key?                                               │
│     └─ Key 3: CMAC key?                                                     │
│                              │                                              │
│                              ▼                                              │
│  5. Initialize 8 auth contexts (sub_C7C × 8)                                │
│                              │                                              │
│                              ▼                                              │
│  6. Store encrypted payload and keys (sub_3FE)                              │
│                              │                                              │
│                              ▼                                              │
│  7. Write status = 0x02 "married" (sub_2EA)                                 │
│                              │                                              │
│                              ▼                                              │
│  8. Complete 4 auth handshakes (sub_7E2 × 4)                                │
│                              │                                              │
│                              ▼                                              │
│  9. Remarry complete                                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Issues

The Syscon side protocol is now fully understood. The remaining blocker is reverse engineering `ss_sc_init_pu.fself`. The CELL side factory initialization module that generates the 0x290-byte remarry payload. While the eid_root_key needed for this process is dumpable with existing CFW tools, the exact payload format, which EID1 fields are used, and the CMAC signing process remain undocumented. Once someone reverses the CELL side module, it should be possible to craft remarriage payloads using dumped eid_root_key and EID1 data.
