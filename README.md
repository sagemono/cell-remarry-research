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

## CELL Side: sc_iso_factory.self (SPU Module)

### Overview

The CELL side marriage logic runs inside `sc_iso_factory.self`, an Isolated SPU Module extracted from `ss_sc_init_pu.fself` (the PPU orchestrator), which itself is embedded in `lv1.self`. The SPU module runs in hardware isolation, meaning even the hypervisor cannot read its local store during execution.

### SPU Memory Map

| Range | Type | Purpose |
|-------|------|---------|
| 0x0880-0xBF8F | Code | Executable code (seg000, seg001) |
| 0xC000-0xC01F | Data | Module configuration |
| 0xC020-0xC08F | Data | Key derivation seeds + old auth keys |
| 0xC090-0xC0EF | Data | Hardcoded fallback auth keys |
| 0xC0F0-0xC12F | Data | Pointers and padding |
| 0xC130-0xC1AF | Data | Payload construction constants |
| 0xC1B0-0xC1CF | Data | Additional data (channel read buffer) |
| 0xC1E0-0xC23F | BSS | Current derived auth keys (runtime) |
| 0xC240-0xC27F | BSS | Working buffers |
| 0xC280-0xC2FF | BSS | Packet assembly / crypto work area |

### AES Crypto Primitives

| Address | Function | Purpose |
|---------|----------|---------|
| 0x59A0 | `aes_key_expand` | AES-128 key expansion |
| 0x5DA0 | `aes_key_expand_wrapper` | Key expansion with schedule extraction |
| 0x5EB8 | `aes_encrypt_block` | AES-128 single block encrypt |
| 0x6060 | `aes_inv_key_schedule` | AES-128 inverse key schedule |
| 0x66C0 | `aes_decrypt_block` | AES-128 single block decrypt |
| 0x6250 | `aes_cbc_mac` | AES-CBC-MAC (block-aligned) |
| 0x63C0 | `aes_cbc` | AES-CBC encrypt/decrypt (mode param) |
| 0x8590 | `aes_cmac` | AES-CMAC (full K1/K2 subkey, 0x87 poly) |

S-box locations: Forward at 0xBA90, Inverse at 0xBC30.

### Higher-Level Crypto Operations

| Address | Function | Purpose |
|---------|----------|---------|
| 0x7AC0 | `auth_encrypt` | Authenticated encryption (CMAC + CBC) |
| 0x7A00 | `dual_mac` | Dual MAC for packet signing |
| 0x7FA0 | `build_signed_packet` | Core packet builder with CMAC |
| 0x7850 | `dual_mac_alt` | Alternate dual MAC path |
| 0x74D0 | `auth1_sign` | AUTH1 CMAC signing (trampoline, type=2) |
| 0x7480 | `auth2_sign` | AUTH2 CMAC signing (trampoline, type=3) |
| 0x74A0 | `session_cbc_encrypt` | CBC encrypt session material between AUTH rounds |
| 0x7448 | `marriage_payload_trampoline` | Trampoline to loc_7D20, sets r3=0xC280 |
| loc_7D20 | `build_marriage_payload` | Actual 0x290-byte payload construction |

### SPU Working Buffers

| Address | Role |
|---------|------|
| 0xC280 | Packet assembly / work buffer |
| 0xC2C0 | AES IV / key schedule storage |
| 0xC2D0 | Packet header + CMAC output |
| 0xC2E0 | CBC-MAC result / CBC encrypt buffer 1 |
| 0xC2F0 | CBC encrypt buffer 2 |

---

## CELL Side: Key Material

### Key Derivation Seeds (0xC030-0xC08F)

These seeds are used with AES-CBC-MAC over the individual info to derive the current per-console auth keys. They match the `sc_magic::auth_magic` values from the wiki.

| Address | Seed (Hex) | Wiki Name | Purpose |
|---------|-----------|-----------|---------|
| 0xC030 | `63DCA7D3FEE47F749A408363F1104E8F` | auth_1 0x00 | Derive current auth_key_1 class 0x00 |
| 0xC040 | `4D10094324009CC8E6B69C70328E34C5` | auth_2 0x00 | Derive current auth_key_2 class 0x00 |
| 0xC050 | `D97949BAD8DA69D0E01BF31523732832` | auth_1 0x01 | Derive current auth_key_1 class 0x01 |
| 0xC060 | `C9D1DD3CE27E356697E26C12A7B316A8` | auth_2 0x01 | Derive current auth_key_2 class 0x01 |
| 0xC070 | `4420ED722FEA35021955AB40C78EE6DF` | auth_1 0x06 | Derive current auth_key_1 class 0x06 |
| 0xC080 | `3E67C2D9432E15D09BEF0E6C6492455D` | auth_2 0x06 | Derive current auth_key_2 class 0x06 |

### Hardcoded Fallback Auth Keys (0xC090-0xC0EF)

Used when derived keys fail (firmware mismatch, key generation change). These are copied to the current key slots (0xC1E0-0xC230) by `sub_F20` during the retry path.

| Address | Key (Hex) | Wiki Name |
|---------|-----------|-----------|
| 0xC090 | `13163A92B50513542C18ABAD31B85FB7` | old_auth_key_1_0x00 |
| 0xC0A0 | `2BC8BB73F4B59AC658A737A5DD535DFE` | old_auth_key_2_0x00 |
| 0xC0B0 | `D6C374FCDFF8C3CF44018C78733BF5B2` | old_auth_key_1_0x01 |
| 0xC0C0 | `648B9FF94EF321C69A4AE596F2F08D22` | old_auth_key_2_0x01 |
| 0xC0D0 | `626C7124FC5BA1AF7436389BA37C6654` | old_auth_key_1_0x06 |
| 0xC0E0 | `9D94BE461CAF083C9D9FA185C93AEE7B` | old_auth_key_2_0x06 |

### Payload Construction Constants (0xC130-0xC1A0)

Eight 16-byte constants loaded during the final marriage payload construction at loc_7D20. Used as MAC keys and data in the CBC-MAC/CBC-encrypt steps that produce the 0x290-byte payload.

| Address | Value (Hex) |
|---------|-------------|
| 0xC130 | `9F1DF816BB4A4A0129D031CFB0AD9B30` |
| 0xC140 | `D302FDE17578FBDBA1058449BA5C1BEA` |
| 0xC150 | `0E6B7480E5CEB2562A3347BB41012455` |
| 0xC160 | `7910AC5D2AD16001F6A2783979096103` |
| 0xC170 | `E3052804B7D2836F2879A1751BB40D48` |
| 0xC180 | `EF586F9D599170676850590BA67D4BC7` |
| 0xC190 | `5D9598637AF25F8023623B1268B5131A` |
| 0xC1A0 | `0EAA32140A2861D8659626F6CE2286DB` |

### sc_iso Module Seed (from SELF metadata)

The 0x100-byte seed stored in the SCE header of sc_iso_factory.self. isoldr encrypts this with `eid_root_key`/`eid_root_iv` to produce the individual info passed to the SPU module.

```
B0D655764C3B44B338F32DD1D0999B66
48A35A2CEB15E28EECDC2DC0B4C7EB05
DC8225C0D5789DBB2E89A24A78585800
72363834EE1A116C2CD25E58EE6763F7
00000000000000000000000000000000  (remaining 0xC0 bytes are zero)
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
00000000000000000000000000000000
```

---

## CELL Side: Key Derivation Chain

### Full Derivation (eFuse to Auth Keys)

```
Step 1: eFuse (48-bit, burned into Cell BE die)
  |  bootrom derivation (OTP mask ROM, not readable)
  v
Step 2: per_console_root_key_0
  |  AES derivation inside metldr (?)
  v
Step 3: eid_root_key + eid_root_iv  (per_console_root_key_1)
  |  stored in metldr, copied to LS offset 0
  |  obtainable via CFW
  v
Step 4: individual_info = AES-CBC-encrypt(
  |      key  = eid_root_key,
  |      iv   = eid_root_iv,
  |      data = sc_iso_module_seed  (0x100 bytes from SELF metadata)
  |  )
  |  computed by isoldr, passed to SPU module in r7-r22
  v
Step 5: For each command class {0x00, 0x01, 0x06}:
  |    current_auth_key = AES-CBC-MAC(
  |        key  = auth_magic_seed[class],
  |        iv   = 0x00000000000000000000000000000000,
  |        data = individual_info[0x50:0x150]  (256 bytes)
  |    )
  v
Step 6: Six derived keys stored at 0xC1E0-0xC230
        ready for AUTH1/AUTH2 handshake
```

### Key Derivation Function (sub_1DD0)

```c
// Called 6 times by sub_1E68, once per auth key slot
int derive_auth_key(void *context, void *dest_key, void *seed)
{
    uint8_t iv[16] = {0};
    uint8_t *eid_data = (uint8_t *)context + 0x50;  // individual info, offset 0x50
    
    return aes_cbc_mac(
        dest_key,   // output: 16-byte derived key
        seed,       // AES key: auth_magic seed constant
        16,         // key length
        eid_data,   // data: 256 bytes of individual info
        0x100,      // data length
        iv          // IV: all zeros
    );
}
```

### Key Initialization (sub_1E68)

```c
int init_current_keys(void *context)
{
    // Derive current auth keys from per-console individual info
    if (derive_auth_key(context, KEY_C1E0, SEED_C030)) return err;  // auth_key_1_0x00
    if (derive_auth_key(context, KEY_C1F0, SEED_C040)) return err;  // auth_key_2_0x00
    if (derive_auth_key(context, KEY_C200, SEED_C050)) return err;  // auth_key_1_0x01
    if (derive_auth_key(context, KEY_C210, SEED_C060)) return err;  // auth_key_2_0x01
    if (derive_auth_key(context, KEY_C220, SEED_C070)) return err;  // auth_key_1_0x06
    if (derive_auth_key(context, KEY_C230, SEED_C080)) return err;  // auth_key_2_0x06
    return 0;
}
```

### Fallback Key Swap (sub_F20)

```c
// Called when AUTH with derived keys fails
void swap_to_old_keys()
{
    memcpy(KEY_C1E0, OLD_C090, 16);  // old_auth_key_1_0x00
    memcpy(KEY_C1F0, OLD_C0A0, 16);  // old_auth_key_2_0x00
    memcpy(KEY_C200, OLD_C0B0, 16);  // old_auth_key_1_0x01
    memcpy(KEY_C210, OLD_C0C0, 16);  // old_auth_key_2_0x01
    memcpy(KEY_C220, OLD_C0D0, 16);  // old_auth_key_1_0x06
    memcpy(KEY_C230, OLD_C0E0, 16);  // old_auth_key_2_0x06
}
```

---

## CELL Side: AUTH1/AUTH2 Protocol

### Protocol Sequence (sub_16F0)

```c
// Main AUTH handshake, called by retry_wrapper (sub_1C48)
int auth_handshake(void *context)
{
    // 1. Build packet header (service IDs: 0x83, 0x81)
    // 2. Read 16-byte challenge from SPU channel 74 (from PPU)
    
    // --- AUTH1 ---
    setup_packet(packet);                               // sub_2BF8
    printf("AUTH1\n");
    
    // CMAC-sign AUTH1 with auth_key_1
    // CBC-MAC(C2E0, challenge, 0x10, session, 0x80, C2C0)
    // build_signed_packet(C2D0, auth_key_1, type=2)
    err = auth1_sign(packet, auth_key, session, challenge);   // sub_74D0
    if (err) return 0x81010301;
    
    dma_send(context, packet, size);                    // sub_51A8
    dma_receive(response);                              // sub_2D10
    
    err = verify_response_cmac(context, ...);           // sub_4298
    if (err) return 0x81010304;
    
    err = verify_response_header(context, ...);         // sub_3AC8
    if (err) return 0x81010303;
    
    if (type_out != 2) return 0x81010305;
    if (cmd_out != 0x83) return 0x81010306;
    
    parse_session_params(response, &session_data);      // sub_2C08
    dma_send(context, session_data, size);              // sub_4F18
    
    // --- Encrypt session material ---
    dual_mac(C280, packet, size, key, type=2);          // sub_7A00
    aes_cbc_encrypt(C2E0, session_key, C2C0);           // sub_63C0
    aes_cbc_encrypt(C2F0, session_key, C2C0);           // sub_63C0
    session_cbc_encrypt(packet, key, session, output);  // sub_74A0
    
    // --- AUTH2 ---
    printf("AUTH2\n");
    
    // CMAC-sign AUTH2 with auth_key_2
    // CBC-MAC(C2E0, prev_mac, 0x10, session, 0x80, C2C0)
    // build_signed_packet(C2D0, auth_key_2, type=3)
    err = auth2_sign(packet, auth_key, session, mac);   // sub_7480
    if (err) return 0x81010301;
    
    dma_send(context, packet, size);                    // sub_51A8
    dma_receive(response);                              // sub_2D10
    // [repeat verify cycle for AUTH2 response]
    
    parse_session_params(response, &session_data);      // sub_2C08
    dma_send(context, session_data, size);              // sub_4F18
    
    // --- Build marriage payload ---
    err = build_marriage_payload(                        // sub_7448 -> loc_7D20
        packet, key, 0, session, payload, data, size
    );
    if (err) return err;
    
    printf("succeeded\n");
    context[0x90] = 1;  // auth_complete flag
    return 0;
}
```

### AUTH Packet Signing (sub_7FA0)

```c
// Core packet builder called by both AUTH1 and AUTH2 paths
int build_signed_packet(void *header_out, int key_len, void *auth_key, int type)
{
    // Build 5-byte header at C2D0:
    //   byte[0] = key identifier (low byte of auth_key pointer)
    //   byte[1] = type (2=AUTH1, 3=AUTH2)
    //   byte[2] = 0xFF (marker)
    //   byte[3] = C280[6]  (from work buffer)
    //   byte[4] = C280[7]  (from work buffer)
    
    sub_8568();  // fill remaining 11 header bytes
    memcpy(C2D0 + 5, temp_header, 11);  // total: 16-byte header
    
    // Check C280[5] for signing mode
    if (C280[5] != 0) {
        // CBC-MAC over packet body
        err = aes_cbc_mac(C2D0_aligned, auth_key+0x10, C280+0x10, 0x80, C2C0);
        if (err) return 0xFFFF0001;
        
        // AES-CMAC tag
        err = aes_cmac(C2D0_end, auth_key+0x10, C280+0x10, 0x80);
        if (err) return 0xFFFF0001;
    }
    return 0;
}
```

### Retry Wrapper (sub_1C48)

```c
int retry_wrapper(void *context)
{
    // Try with current (derived) keys first
    int err = auth_handshake(context);
    if (err == 0) return 0;
    
    // Fallback: swap to hardcoded old keys
    printf("Trying again with old key...\n");
    swap_to_old_keys();
    
    err = auth_handshake(context);
    if (err) return 0x81012401;  // both attempts failed
    
    return 0;
}
```

### Session Key Derivation (sub_2C08)

Not cryptographic, parses the syscon AUTH response to extract session parameters:

```c
int parse_session_params(void *packet, int size, void *session_out, void *keys_out)
{
    // Validate response
    if (packet[0] == 0) return 0x81030280;     // null response
    if (packet[4] != 0x10) return 0x81030281;  // invalid size
    if (packet[8] > 0x0F0F) return 0x81030282; // overflow
    if (packet[12] > 0x0F0F) return 0x81030283;
    
    // Extract two 32-bit values into output buffers
    memcpy(session_out, &packet[offset1], 4);
    memcpy(keys_out, &packet[offset2], 4);
    return 0;
}
```

### Marriage Payload Builder (loc_7D20)

```c
int build_marriage_payload(void *workbuf, void *packet, void *key, 
                           void *session, void *payload, void *data, int size)
{
    // Validate payload size (must be > 0x1F, at least 32 bytes)
    int data_size = extract_size(packet);
    if (data_size <= 0x1F) return -1;
    
    // Phase 1: Authenticated encrypt of payload body
    err = auth_encrypt(workbuf, packet, data_size - 0x20, key, type);  // sub_7A00
    if (err) return -0xFF;
    
    // Phase 2: Clear 0x80 bytes and load payload constants
    memset(temp, 0, 0x80);  // sub_9E90
    
    // Load 8 constants from C130-C1A0 onto stack
    // C130-C160 -> stack vars (MAC input)
    // C170-C1A0 -> stack vars (additional data)
    
    // Phase 3: CBC-MAC over payload body
    err = aes_cbc_mac(temp, session_key, payload_body, 0x80, KEY_C2C0);
    if (err) return -0xFF;
    
    // Phase 4: CBC-MAC over CMAC tag at offset
    err = aes_cbc_mac(temp, session_key, cmac_at_offset, 0x10, KEY_C2C0);
    if (err) return -0xFF;
    
    // Phase 5: AES-CBC encrypt final block
    err = aes_cbc(C2E0, C2E0, 0x10, KEY_C2C0, 0x80);    // sub_63C0
    if (err) return -0xFF;
    
    // Phase 6: Write result back to PPU via DMA
    err = dma_put(C2E0, dest, 0x10);  // sub_9C48
    
    // Phase 7: Copy encrypted result to output
    memcpy(output, C2F0, 0x10);
    
    return (err == 0) ? 0 : -3;
}
```

---

## CELL Side: Command Dispatcher (sub_28E0)

### Entry Point

Called from `main` at loc_E84. Two commands supported:

```c
int command_dispatcher(void *context, void *status_ptr, void *size_ptr, 
                       void *unused, void *result_ptr, void *extra)
{
    // 1. DMA GET: pull data from PPU into SPU local store
    dma_get(local_buffer);                               // sub_4E50
    
    // 2. Derive current auth keys from individual info
    err = init_current_keys(context);                    // sub_1E68
    if (err) { log_error(0x81010101); goto cleanup; }
    
    // 3. Validate version/format
    err = validate_version(context, VERSION_B6C0);       // sub_39A8
    if (err) { log_error(0x81010102); goto cleanup; }
    
    // 4. Parse command packet header
    err = parse_header(context, &type, &cmd, &hash);     // sub_3AC8
    if (err) { log_error(0x81010103); goto cleanup; }
    
    // 5. Verify packet type
    if (type != 1) { log_error(0x81010105); goto cleanup; }
    
    printf("command = %x\n", cmd);
    
    // 6. Dispatch command
    switch (cmd) {
        case 0x14:  // SC_ISO_INIT_FOR_UPDATER
            err = sc_iso_init_for_updater(context, ...);   // sub_2680
            break;
        case 0x15:  // SC_ISO_SET_SC_STATUS
            err = sc_iso_set_status(context, ...);         // sub_2468
            break;
        default:
            log_error(0x81010106);  // unknown command
            break;
    }
    
    // 7. DMA PUT: write results back to PPU
    dma_put(local_buffer);                               // sub_4F10
    return err;
}
```

### SPU Communication Channels

| Channel | Direction | Purpose |
|---------|-----------|---------|
| ch74 (rdch) | PPU -> SPU | Read challenge/nonce, control data |
| ch28 (wrch) | SPU -> PPU | Write to PPU outbound mailbox |
| ch30 (wrch) | SPU -> PPU | Interrupt mailbox |
| ch16-24 (DMA) | Bidirectional | Memory transfers (GET=0x20, PUT=0x40) |

---

## CELL Side: Error Codes

| Code | Location | Meaning |
|------|----------|---------|
| 0x81010101 | sub_28E0 | Key derivation failed |
| 0x81010102 | sub_28E0 | Version validation failed |
| 0x81010103 | sub_28E0 | Packet header parse failed |
| 0x81010105 | sub_28E0 | Wrong packet type (expected 1) |
| 0x81010106 | sub_28E0 | Unknown command |
| 0x81010301 | sub_16F0 | AUTH1/AUTH2 CMAC signing failed |
| 0x81010303 | sub_16F0 | Response header verification failed |
| 0x81010304 | sub_16F0 | Response CMAC verification failed |
| 0x81010305 | sub_16F0 | Response type != 2 |
| 0x81010306 | sub_16F0 | Response command != 0x83 |
| 0x81010401 | sub_1E68 | Key derivation CBC-MAC error |
| 0x81010501 | sub_1DD0 | Individual CBC-MAC computation error |
| 0x81012401 | sub_1C48 | Both key attempts failed |
| 0x81030280 | sub_2C08 | Null response from syscon |
| 0x81030281 | sub_2C08 | Invalid size field in response |
| 0x81030282 | sub_2C08 | Size overflow (field 1) |
| 0x81030283 | sub_2C08 | Size overflow (field 2) |

### String References

| Address | String | Used By |
|---------|--------|---------|
| 0xB600 | `AUTH1\n` | sub_16F0 (before AUTH1 sign) |
| 0xB610 | `AUTH2\n` | sub_16F0 (before AUTH2 sign) |
| 0xB620 | `succeeded\n` | sub_16F0 (after marriage payload) |
| 0xB630 | `Trying again with old key...\n` | sub_1C48 (retry path) |
| 0xB650 | `set = ` | sub_2468 (SC_ISO_SET_SC_STATUS) |
| 0xB660 | `, get = ` | sub_2468 |
| 0xB670 | `[ERROR]: cannot get system version\n` | sub_2680 |
| 0xB6A0 | `command = ` | sub_28E0 (dispatcher) |

---

## CELL Side: Function Reference

### Initialization and Dispatch

| Address | Name | Purpose |
|---------|------|---------|
| 0x0880 | `main` | Entry point, calls sub_28E0 |
| 0x28E0 | `command_dispatcher` | DMA setup, key init, command dispatch |
| 0x1E68 | `init_current_keys` | Derive 6 auth keys from individual info |
| 0x1DD0 | `derive_auth_key` | Single key derivation (CBC-MAC of EID data) |
| 0x0F20 | `swap_to_old_keys` | Copy fallback keys to current slots |

### AUTH Protocol

| Address | Name | Purpose |
|---------|------|---------|
| 0x16F0 | `auth_handshake` | Full AUTH1/AUTH2 + marriage payload sequence |
| 0x1C48 | `retry_wrapper` | Try current keys, fallback to old |
| 0x1C50 | `auth_entry` | Top-level caller of retry_wrapper |
| 0x74D0 | `auth1_sign` | AUTH1 CMAC signing trampoline |
| 0x7480 | `auth2_sign` | AUTH2 CMAC signing trampoline |
| 0x7FA0 | `build_signed_packet` | Core packet construction + CMAC |
| 0x74A0 | `session_cbc_encrypt` | CBC encrypt session data between rounds |
| 0x2C08 | `parse_session_params` | Extract session params from AUTH response |

### Payload Construction

| Address | Name | Purpose |
|---------|------|---------|
| 0x7448 | `marriage_payload_trampoline` | Arg shuffle + jump to 7D20 |
| 0x7D20 | `build_marriage_payload` | Actual 0x290 payload builder |
| 0x7A00 | `dual_mac` | Dual MAC (CMAC + CBC) operation |

### Communication

| Address | Name | Purpose |
|---------|------|---------|
| 0x4E50 | `dma_get` | DMA pull from PPU |
| 0x4F10 | `dma_put_results` | DMA push results to PPU |
| 0x4F18 | `dma_put` | DMA push data to PPU |
| 0x51A8 | `dma_send_packet` | Send AUTH packet via DMA |
| 0x2D10 | `dma_receive_packet` | Receive AUTH response via DMA |
| 0x2BF8 | `setup_packet` | Initial packet buffer setup |
| 0x4298 | `verify_response_cmac` | Parse and CMAC-verify response |
| 0x3AC8 | `verify_response_header` | Validate response type/cmd/hash |
| 0x39A8 | `validate_version` | Version/format check |

### Utility

| Address | Name | Purpose |
|---------|------|---------|
| 0x9D08 | `memcpy` | Memory copy |
| 0x9E90 | `memset` | Memory set |
| 0x9C48 | `dma_write_16` | DMA write 16 bytes |
| 0x4508 | `debug_flush` | Debug output flush |
| 0x45B0 | `debug_print_str` | Print string |
| 0x4B40 | `debug_print_hex` | Print hex value |
| 0x4AD8 | `debug_print_int` | Print integer |
| 0x8568 | `read_channel_data` | Read data from SPU channel |

---

## Updated Flow

```
+-----------------------------------------------------------------------------+
|                                                                             |
|  CELL                                   SYSCON                              |
|  (ss_sc_init_pu.fself)                  (Firmware)                          |
|                                                                             |
|  +---------------------+                  +--------------------+            |
|  | sc_iso_factory.self |                 | SPCR (EEPROM)      |             |
|  | (Isolated SPU)      |                 | +- 0x00: Status    |             |
|  |                     |                 | +- 0x10: Enc Key   |             |
|  | Inputs:             |                 | +- 0x20: CMAC      |             |
|  |  - eid_root_key     |                 | +- 0x30+: Session  |             |
|  |  - module seed      |                 +--------------------+             |
|  |  - individual info  |                                                    |
|  +---------------------+                                                    |
|                                                                             |
+--------- KEY DERIVATION CHAIN (per-console) --------------------------------+
|                                                                             |
|  1. eFuse (48-bit, Cell BE hardware)                                        |
|     |                                                                       |
|     v                                                                       |
|  2. per_console_root_key_0 (bootrom derivation)                             |
|     |                                                                       |
|     v                                                                       |
|  3. eid_root_key + eid_root_iv (metldr, dumpable via erk_dumper)            |
|     |                                                                       |
|     v                                                                       |
|  4. isoldr: AES-CBC(eid_root_key, eid_root_iv, module_seed)                 |
|     = individual_info (0x100 bytes, per-console per-module)                 |
|     |                                                                       |
|     v                                                                       |
|  5. sc_iso_factory: AES-CBC-MAC(auth_magic[N], zero_iv, indi_info)          |
|     = 6 derived auth keys (per-console)                                     |
|                                                                             |
+--------- FACTORY WIPE SEQUENCE ---------------------------------------------+
|                                                                             |
|  1. JIG sends Command 255.255:                                              |
|     +------------------------------------------------------+                |
|     |[FF][FF][00][AD][1A][...random...][password][random]   |               |
|     |                      ^                                |               |
|     |            FactoryInit_Password                       |               |
|     |     (2EA267093B4556ED9D3BE62E115D6D59)                |               |
|     +------------------------------------------------------+                |
|                              |                                              |
|                              v                                              |
|  2. Syscon verifies password (sub_17F0)                                     |
|                              |                                              |
|                              v                                              |
|  3. Syscon wipes SPCR (0x2560 bytes encrypted 0xFF)                         |
|                              |                                              |
|                              v                                              |
|  4. Status becomes "uninitialized" -> decrypts to 0x01                      |
|                                                                             |
+--------- REMARRIAGE SEQUENCE (CELL side now (mostly) reversed) -------------+
|                                                                             |
|  PPU (ss_sc_init_pu.fself):                                                 |
|  1. individual_info_mgr::read_individual_info                               |
|  2. request_loading_spu_module (sc_iso_factory.self)                        |
|  3. DMA individual_info + command data to SPU local store                   |
|                                                                             |
|  SPU (sc_iso_factory.self):                                                 |
|  4. Derive 6 per-console auth keys from individual_info                     |
|     auth_key = AES-CBC-MAC(seed, zero_iv, indi_info[0x50:0x150])            |
|                                                                             |
|  5. AUTH1 Handshake:                                                        |
|     a. Read 16-byte challenge from PPU (channel 74)                         |
|     b. CBC-MAC(challenge, session_buf, KEY_C2C0) -> C2E0                    |
|     c. Build packet header at C2D0 (type=2, key_id, marker)                 |
|     d. CMAC sign with auth_key_1 -> send to syscon                          |
|     e. Receive + verify response (CMAC, type==2, cmd==0x83)                 |
|     f. Extract session parameters from response                             |
|                                                                             |
|  6. Encrypt session material:                                               |
|     a. Dual MAC over packet body                                            |
|     b. AES-CBC encrypt C2E0 and C2F0 with session key                       |
|     c. DMA send encrypted session data to PPU                               |
|                                                                             |
|  7. AUTH2 Handshake:                                                        |
|     a. CBC-MAC(prev_mac, session_buf, KEY_C2C0) -> C2E0                     |
|     b. Build packet header at C2D0 (type=3, key_id, marker)                 |
|     c. CMAC sign with auth_key_2 -> send to syscon                          |
|     d. Receive + verify response                                            |
|     e. Extract session parameters                                           |
|                                                                             |
|  8. Build 0x290-byte marriage payload (loc_7D20):                           |
|     a. Authenticated encrypt of payload body (CMAC + CBC)                   |
|     b. CBC-MAC with payload constants (C130-C1A0)                           |
|     c. AES-CBC final encrypt with session keys                              |
|     d. DMA result back to PPU                                               |
|                                                                             |
|  9. PPU forwards 0x290 payload to syscon via /dev/sc3                       |
|                                                                             |
|  Syscon:                                                                    |
|  10. sub_18D6 receives 0x290 payload (Class 255, Command 1)                 |
|  11. Verify CMAC -> derive 4 session keys -> init 8 auth contexts           |
|  12. Write status = 0x02 "married" to SPCR                                  |
|  13. Complete 4 post-marriage auth handshakes                               |
|                                                                             |
|  If AUTH fails with current keys:                                           |
|     -> "Trying again with old key..."                                       |
|     -> swap_to_old_keys() copies C090-C0E0 -> C1E0-C230                     |
|     -> Retry entire AUTH1/AUTH2 sequence                                    |
|     -> If both fail: error 0x81012401                                       |
|                                                                             |
+-----------------------------------------------------------------------------+
```

---

### Remaining Work

The CELL side module is now fully reversed. The remaining work for a complete "reimplementation" is:

1. **PPU transport layer** -- exact /dev/sc3 ioctl interface and packet framing used by `ss_sc_init_pu.fself` to relay between SPU and syscon
2. **Packet byte-level format** -- exact byte positions within the AUTH1/AUTH2 packets (header bytes 5-15 from sub_8568 helper)
3. **Session key flow** -- how the session parameters extracted by sub_2C08 feed into the CBC encryption and final payload construction
4. **Post-AUTH command loop** -- the indirect dispatch loop at loc_19C4-1BE0 that executes additional operations after AUTH completes
