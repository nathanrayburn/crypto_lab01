import unidecode


# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT

def caesar_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the shift which is a number

    Returns
    -------
    the ciphertext of <text> encrypted with Caesar under key <key>
    """
    # TODO

    filtered_text = unidecode.unidecode(text).upper()
    ciphered_text = ""

    ascii_ref = ord('A')
    for letter in filtered_text:
        if letter.isalpha():
            ascii_letter = ord(letter)
            ciphered_text += chr((ascii_letter - ascii_ref + key) % 26 + ascii_ref)
        if letter.isspace():
            ciphered_text += letter
    return ciphered_text


def caesar_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the shift which is a number

    Returns
    -------
    the plaintext of <text> decrypted with Caesar under key <key>
    """
    #

    plain_text = ""
    ciphered_text = text.upper()
    ascii_ref = ord('A')
    for letter in ciphered_text:
        if letter.isalpha():
            ascii_letter = ord(letter)
            plain_text += chr((ascii_letter - ascii_ref - key) % 26 + ascii_ref)
        if letter.isspace():
            plain_text += letter

    return plain_text


def freq_analysis(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    list
        the frequencies of every letter (a-z) in the text.

    """
    # Each value in the vector should be in the range [0, 1]
    freq_vector = [0] * 26
    # TODO
    text.upper()
    ascii_ref = ord('A')
    total = 0
    for letter in text:
        if letter.isalpha():
            freq_vector[ord(letter) - ascii_ref] += 1
            total += 1

    result = [i/total for i in freq_vector]
    return result


def caesar_break(text, ref_freq):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    a number corresponding to the caesar key
    """
    # TODO
    return ''


def vigenere_encrypt(text, key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the ciphertext of <text> encrypted with Vigenere under key <key>
    """
    # TODO
    return ""


def vigenere_decrypt(text, key):
    """
    Parameters
    ----------
    text: the ciphertext to decrypt
    key: the keyword used in Vigenere (e.g. "pass")

    Returns
    -------
    the plaintext of <text> decrypted with Vigenere under key <key>
    """
    # TODO
    return ""


def coincidence_index(text):
    """
    Parameters
    ----------
    text: the text to analyse

    Returns
    -------
    the index of coincidence of the text
    """
    # TODO
    return 0


def vigenere_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    the keyword corresponding to the encryption key used to obtain the ciphertext
    """
    # TODO
    return ''


def vigenere_caesar_encrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to encrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the ciphertext of <text> encrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    return ""


def vigenere_caesar_decrypt(text, vigenere_key, caesar_key):
    """
    Parameters
    ----------
    text: the plaintext to decrypt
    vigenere_key: the keyword used in Vigenere (e.g. "pass")
    caesar_key: a number corresponding to the shift used to modify the vigenere key after each use.

    Returns
    -------
    the plaintext of <text> decrypted with improved Vigenere under keys <key_vigenere> and <key_caesar>
    """
    # TODO
    return ""


def vigenere_caesar_break(text, ref_freq, ref_ci):
    """
    Parameters
    ----------
    text: the ciphertext to break
    ref_freq: the output of the freq_analysis function on a reference text
    ref_ci: the output of the coincidence_index function on a reference text

    Returns
    -------
    pair
        the keyword corresponding to the vigenere key used to obtain the ciphertext
        the number corresponding to the caesar key used to obtain the ciphertext
    """
    # TODO you can delete the next lines if needed
    vigenere_key = ""
    caesar_key = ''
    return (vigenere_key, caesar_key)


def main():
    print("Welcome to the Vigenere breaking tool")
    # TODO something 
    ciphered = caesar_encrypt("Salut je bench plus que toi",24)
    print(freq_analysis(ciphered))
    print(ciphered)
    print(caesar_decrypt(ciphered,24))
if __name__ == "__main__":
    main()


