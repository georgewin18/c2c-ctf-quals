import struct

# Map some Linux Keycodes to human readable
KEY_MAP = {
    2: '1', 3: '2', 4: '3', 5: '4', 6: '5', 7: '6', 8: '7', 9: '8', 10: '9', 11: '0',
    12: '-', 13: '=', 14: '[BACKSPACE]', 15: '[TAB]',
    16: 'q', 17: 'w', 18: 'e', 19: 'r', 20: 't', 21: 'y', 22: 'u', 23: 'i', 24: 'o', 25: 'p', 26: '[', 27: ']', 28: '\n',
    30: 'a', 31: 's', 32: 'd', 33: 'f', 34: 'g', 35: 'h', 36: 'j', 37: 'k', 38: 'l', 39: ';', 40: "'", 42: '[SHIFT]',
    44: 'z', 45: 'x', 46: 'c', 47: 'v', 48: 'b', 49: 'n', 50: 'm', 51: ',', 52: '.', 53: '/', 54: '[SHIFT]',
    57: ' ', 58: '[CAPS]'
}

with open('cron.aseng', 'rb') as f:
    while True:
        # Read 24 byte per event
        data = f.read(24)
        if not data or len(data) < 24:
            break
        
        # Unpack using the same struct with malware: QQHHi
        tv_sec, tv_usec, ev_type, ev_code, ev_value = struct.unpack('QQHHi', data)
        
        # Filter: Only take EV_KEY (Type 1) and when key PRESSED (Value 1)
        if ev_type == 1 and ev_value == 1:
            char = KEY_MAP.get(ev_code, f'[{ev_code}]')
            print(char, end='')
print()
