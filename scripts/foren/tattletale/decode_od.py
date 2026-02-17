import struct

output_text = ""

with open("whatisthis.baboi.recovered", "r") as f:
    for line in f:
        parts = line.strip().split()
        
        # if line empty or only last offset ( 0005002), pass
        if len(parts) < 2:
            continue
            
        # First column is offset, the rest of it are octal values
        octal_values = parts[1:]
        
        for oct_str in octal_values:
            # Convert octal string to integer
            val = int(oct_str, 8)
            
            # Pack integer into 2 byte (Little Endian), then decode to teks
            # Ignore error if non-ASCII characters
            chars = struct.pack('<H', val).decode('ascii', errors='ignore')
            output_text += chars

print(output_text)

