# main.py
"""
Main Entry Point

Este arquivo é o ponto de entrada principal para a execução da cifra AES.
Aqui você pode definir e testar a implementação da cifra AES, modo CTR, cifra de arquivo.
"""

from aes import AES, AESFileCipher

def test_aes():
    print("\nCifra AES (bloco= 128 bits, chave 128 bits)")
    
    #Texto de Exemplo
    plaintext = b"TestandoAES12345"
    print(f"Plaintext: {plaintext}")

    # Exemplo de chave de 16 bytes
    key = b"ExemploChave16by"
    aes = AES(key)

    # Cifragem
    ciphertext = aes.encrypt_block(plaintext)
    print(f"Ciphertext: {ciphertext}")

    # Decifragem
    decrypted_text = aes.decrypt_block(ciphertext)
    print(f"Decrypted text: {decrypted_text}")

    # Verifica se a decifragem foi correta            
    print("Sucesso! A decifragem corresponde ao texto original."
          if decrypted_text == plaintext
          else "Erro! A decifragem não corresponde ao texto original.")
    
def test_CTR():
    #Para modo CTR
    iv = b'\x01' * 16
    
    print("\nCifra AES modo CTR")
    #Texto de Exemplo
    plaintext = b"TestandoAES12345"
    print(f"Plaintext: {plaintext}")

    # Exemplo de chave de 16 bytes
    key = b"ExemploChave16by"
    aes = AES(key)

    # Cifragem
    ciphertext = aes.encrypt_ctr(plaintext, iv)
    print(f"Ciphertext: {ciphertext}")

    # Decifragem
    decrypted_text = aes.decrypt_ctr(ciphertext, iv)
    print(f"Decrypted text: {decrypted_text}")

    # Verifica se a decifragem foi correta            
    print("Sucesso! A decifragem corresponde ao texto original."
          if decrypted_text == plaintext
          else "Erro! A decifragem não corresponde ao texto original.")
    
def test_file():
    print("\nCifra AES de arquivo")
    
    # Exemplo de chave de 16 bytes
    key = b'TestandoAES12345'
    cipher = AESFileCipher(key, mode='ECB')

    # Cifrar o arquivo
    cipher.encrypt_file('arquivo_original.txt', 'arquivo_cifrado.enc')

    # Decifrar o arquivo
    cipher.decrypt_file('arquivo_cifrado.enc', 'arquivo_decifrado.txt')

    # Verifica se a decifragem foi correta            
    print("Sucesso! A decifragem corresponde ao arquivo original."
          if cipher.compare_files('arquivo_original.txt', 'arquivo_decifrado.txt') == True
          else "Erro! A decifragem do arquivo não corresponde ao texto original.")

if __name__ == "__main__":
    test_aes()
    test_CTR()
    test_file()
