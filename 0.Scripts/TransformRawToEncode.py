import random
import os
import sys

# Configuration
LINE_WIDTH = 64

def encrypt_file(input_filename: str, output_filename: str):
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        return

    try:
        # READ AS RAW BINARY
        with open(input_filename, 'rb') as f_in:
            raw_bytes = f_in.read()

        with open(output_filename, 'w', encoding='utf-8') as f_out:
            current_line = []
            valid_bases = [48, 64, 96] 

            for byte in raw_bytes:
                msb = (byte >> 4) & 0x0F
                lsb = byte & 0x0F

                char_msb = chr(random.choice(valid_bases) + msb)
                char_lsb = chr(random.choice(valid_bases) + lsb)

                current_line.append(char_msb)
                current_line.append(char_lsb)
                
                if len(current_line) >= LINE_WIDTH:
                    line_str = "".join(current_line)
                    f_out.write(f'"{line_str}"\n')
                    current_line = []
            
            if current_line:
                line_str = "".join(current_line)
                f_out.write(f'"{line_str}"\n')

        print(f"[SUCCESS] Encrypted raw shellcode to text -> {output_filename}")

    except Exception as e:
        print(f"[Encrypt] Error: {e}")

def decrypt_file(input_filename: str, output_filename: str):
    if not os.path.exists(input_filename):
        print(f"Error: Input file '{input_filename}' not found.")
        return

    try:
        # WRITE AS RAW BINARY (to match original input)
        with open(input_filename, 'r', encoding='utf-8') as f_in, \
             open(output_filename, 'wb') as f_out:
            
            for line in f_in:
                clean_line = line.strip().replace('"', '')
                if not clean_line:
                    continue
                
                byte_array = bytearray()
                for i in range(0, len(clean_line), 2):
                    if i + 1 >= len(clean_line):
                        break

                    msb = ord(clean_line[i]) % 16
                    lsb = ord(clean_line[i+1]) % 16
                    byte_val = (msb << 4) | lsb
                    byte_array.append(byte_val)
                
                f_out.write(byte_array)

        print(f"[SUCCESS] Decrypted text back to raw shellcode -> {output_filename}")

    except Exception as e:
        print(f"[Decrypt] Error: {e}")

def check_diff(file1, file2):
    size1, size2 = os.path.getsize(file1), os.path.getsize(file2)
    
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        buf1 = f1.read()
        buf2 = f2.read()

    if buf1 == buf2:
        print(f"[+] Files are IDENTICAL ({size1} bytes).\n")
        # os.remove(file2) # Uncomment to clean up the restored file
        return

    print(f"[!] Files DIFFER! Size1: {size1}b, Size2: {size2}b")

def TransformShellCodeToPayload(bin_input, txt_output, bin_restored="restored.bin"):
    encrypt_file(bin_input, txt_output)
    decrypt_file(txt_output, bin_restored)
    #check_diff(bin_input, bin_restored)
    
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python diff.py <raw_shellcode.bin> <obfuscated_output.txt>")
    else:
        TransformShellCodeToPayload(sys.argv[1], sys.argv[2])