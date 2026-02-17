import re
from datetime import datetime

log_file = "access.log"

try:
    with open(log_file, "r") as file:
        lines = file.readlines()

    data = []

    for i in range(len(lines) - 1):
        current_line = lines[i]
        next_line = lines[i+1]
        
        # Only search for lines that extract characters with pattern != (URL encoded: %21%3D)
        if "SLEEP" in current_line and "%21%3D" in current_line:
            
            # Ekstrak current request time and next request
            time_match_1 = re.search(r'\[(.*?) \+0000\]', current_line)
            time_match_2 = re.search(r'\[(.*?) \+0000\]', next_line)
            
            if time_match_1 and time_match_2:
                time_1 = datetime.strptime(time_match_1.group(1), "%d/%b/%Y:%H:%M:%S")
                time_2 = datetime.strptime(time_match_2.group(1), "%d/%b/%Y:%H:%M:%S")
                
                # Count time diff
                time_diff = (time_2 - time_1).total_seconds()
                
                # if time diff less than 2s, != condition is FALSE.
                # So, guess for the character is TRUE
                if time_diff < 2:
                    # Find guessed ASCII number (after %21%3D)
                    ascii_match = re.search(r'%21%3D(\d+)', current_line)
                    if ascii_match:
                        ascii_val = int(ascii_match.group(1))
                        char = chr(ascii_val)
                        data.append(char)

    print("[+] Extraction Result: " + "".join(data))

except Exception as e:
    print(f"Error occured: {e}")
