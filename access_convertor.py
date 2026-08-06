#!/usr/bin/env python3
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
except:
    class Fore:
        RED = GREEN = YELLOW = CYAN = WHITE = ""
    class Style:
        RESET_ALL = ""
PROCESS_ACCESS_RIGHTS = {
    "PROCESS_TERMINATE": 0x0001,
    "PROCESS_CREATE_THREAD": 0x0002,
    "PROCESS_SET_SESSIONID": 0x0004,
    "PROCESS_VM_OPERATION": 0x0008,
    "PROCESS_VM_READ": 0x0010,
    "PROCESS_VM_WRITE": 0x0020,
    "PROCESS_DUP_HANDLE": 0x0040,
    "PROCESS_CREATE_PROCESS": 0x0080,
    "PROCESS_SET_QUOTA": 0x0100,
    "PROCESS_SET_INFORMATION": 0x0200,
    "PROCESS_QUERY_INFORMATION": 0x0400,
    "PROCESS_SUSPEND_RESUME": 0x0800,
    "PROCESS_QUERY_LIMITED_INFORMATION": 0x1000,
    "PROCESS_SET_LIMITED_INFORMATION": 0x2000,
    "DELETE": 0x00010000,
    "READ_CONTROL": 0x00020000,
    "WRITE_DAC": 0x00040000,
    "WRITE_OWNER": 0x00080000,
    "SYNCHRONIZE": 0x00100000,
    "GENERIC_ALL": 0x10000000,
    "GENERIC_EXECUTE": 0x20000000,
    "GENERIC_WRITE": 0x40000000,
    "GENERIC_READ": 0x80000000,
}
PROCESS_ALL_ACCESS = 0x1FFFFF

try:
    value = int(input(Fore.CYAN + "Enter GrantedAccess (e.g. 0x1410): " + Fore.WHITE), 0)
except ValueError:
    print(Fore.RED + "Invalid numeric value." + Style.RESET_ALL)
    exit()
print("\n" + Fore.YELLOW + "="*50)
print(Fore.GREEN + f"GrantedAccess Value : {hex(value)}")
print(Fore.GREEN + f"Binary              : {bin(value)}")
print(Fore.YELLOW + "="*50 + "\n")
matched = []
remaining_bits = value

for name, mask in PROCESS_ACCESS_RIGHTS.items():
    if value & mask:
        matched.append(name)
        remaining_bits &= ~mask

# Output
if value == PROCESS_ALL_ACCESS:
    print(Fore.RED + "[!] PROCESS_ALL_ACCESS detected\n")

if matched:
    print(Fore.GREEN + "[+] Decoded Access Rights:\n")
    for right in matched:
        print(Fore.WHITE + "   ├─ " + Fore.CYAN + right)
else:
    print(Fore.YELLOW + "No known access rights matched.")

if remaining_bits != 0:
    print("\n" + Fore.RED + "[!] Unknown / Unmapped Bits Detected:")
    print(Fore.RED + f"   Remaining Value: {hex(remaining_bits)}")
