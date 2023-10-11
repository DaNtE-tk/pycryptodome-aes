from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes



def read_key_from_file(keyfile):
    with open(keyfile,'rb') as file:
        return file.read(32)
    
def encrypt_file(file_path, key):
    chunk_size = 64*1024
    outputfile = 'target.aes'
    iv = get_random_bytes(16)
    cipher = AES.new(key,AES.MODE_CBC,iv)

    integrity_check_string = b"INTEGRITY_CHECK_STRING"
    with open(file_path,'rb') as file:
        with open(outputfile,'wb') as encrypted_file:
            # encrypted_file.write(base64.b64encode(iv))
            encrypted_file.write(integrity_check_string)
            encrypted_file.write(iv)
            while True:
                chunk = file.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk)%16!=0:
                    padding_length = 16 - (len(chunk)%16)
                    chunk += bytes([padding_length])*padding_length
                encrypted_chunk = cipher.encrypt(chunk)
                # encrypted_file.write(base64.b64encode(encrypted_chunk))
                encrypted_file.write(encrypted_chunk)
        print(f'File encrypted successfully : {outputfile}')

if __name__ == '__main__':
    keyfile = input("Enter keyfile path : ")
    key = read_key_from_file(keyfile)
    filepath = input("Enter path of the file to be encrypted : ")
    encrypt_file(filepath, key)