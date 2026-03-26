import hashlib

def calculate_md5(input_string):
    # Create an MD5 hash object
    md5_hash = hashlib.md5()
    # Encode the string to bytes and update the hash object
    md5_hash.update(input_string.encode('utf-8'))
    # Return the hexadecimal representation of the digest
    return md5_hash.hexdigest()

# Main Execution
input_string = input("Nhập chuỗi cần băm: ")
md5_hash = calculate_md5(input_string)

print("Mã băm MD5 của chuỗi '{}' là: {}".format(input_string, md5_hash))