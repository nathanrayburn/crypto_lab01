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

    filtered_text = unidecode.unidecode(text).upper()
    filtered_text.upper()
    ascii_ref = ord('A')
    total = 0
    for letter in filtered_text:
        if letter.isalpha():
            freq_vector[ord(letter) - ascii_ref] += 1
            total += 1

    result = [i/total for i in freq_vector]
    return result

def chi_squared(observed, expected):
    chi2 = sum(((o - e)**2 / e for o, e in zip(observed, expected) if e > 0))
    return chi2
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
    x_temp = float('inf')
    supposed_shift = 0
    for shift in range(26):
        decrypted_text = caesar_decrypt(text, shift)
        stage_freq = freq_analysis(decrypted_text)
        observed = stage_freq[8]  # index i
        expected = ref_freq[8]  # index i
        x_squared = (((observed - expected) ** 2) / expected)
        print("x_squared for shift {}: {}".format(shift, x_squared))  # print x_squared
        if (x_squared < x_temp):
            x_temp = x_squared
            supposed_shift = shift
    print("supposed shift {}".format(supposed_shift))
    return supposed_shift


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


    with open('exemple.txt', 'r', encoding='utf-8') as file:
        example_data = file.read()

    ref_freq = freq_analysis(example_data)

    with open('vigenere.txt', 'r') as file:
        ciphered_text = file.read()
    shift = caesar_break(ciphered_text,ref_freq)
    print(caesar_decrypt(ciphered_text, shift))

    test_ciphered = caesar_encrypt(example_data,15)
    print("Test encrypted : ")
    print(test_ciphered)
    with open('example_french_text.txt','r') as file:
        example_french_data = file.read()

    ref_freq = freq_analysis(example_french_data)
    shift = caesar_break(test_ciphered, ref_freq)
    print(caesar_decrypt(test_ciphered,shift))
if __name__ == "__main__":
    main()


