from Crypto.Cipher import AES
import base64

def read_key_from_file(keyfile):
    with open(keyfile, 'rb') as file:
        return file.read(32)
    
def remove_padding(data):
    # print(data)
    padding_length = data[-1]
    if padding_length > len(data):
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def decrypt_file(file_path,output_filename, key):
    # output_file = "decrypted_" + os.path.basename(file_path)[:-4]
    output_file = output_filename

    with open(file_path, 'rb') as encrypted_file:
        integrity_check_string = encrypted_file.read(len(b"INTEGRITY_CHECK_STRING"))
        print(integrity_check_string)
        if integrity_check_string != b"INTEGRITY_CHECK_STRING":
            raise ValueError("Incorrect or corrupted encrypted file")
        encrypted_data = encrypted_file.read()
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ciphertext)

        # Remove PKCS7 padding
        # decrypted_data = decrypted_data[:-decrypted_data[-1]]
        # decrypted_data = remove_padding(decrypted_data)

        with open(output_file, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f'File decrypted successfully: {output_file}')

if __name__ == "__main__":
    keyfile = input("Enter keyfile path: ")
    key = read_key_from_file(keyfile)
    output_filename = input("Enter output file name: ")
    # file_path = input("Enter path of the encrypted file: ")
    file_path = 'target.aes'
    decrypt_file(file_path,output_filename, key)
