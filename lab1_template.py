import unidecode
import re

# IMPORTANT
# IL EST PRIMORDIAL DE NE PAS CHANGER LA SIGNATURE DES FONCTIONS
# SINON LES CORRECTIONS RISQUENT DE NE PAS FONCTIONNER CORRECTEMENT

def normalizeText(text):
    regex = re.compile("[^a-zA-Z]")
    return regex.sub('',unidecode.unidecode(text).upper())

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
    if not text:
        return ""
    filtered_text = normalizeText(text)
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
    if not text:
        return ""
    plain_text = ""
    ciphered_text = normalizeText(text)
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
    if not text:
        freq_vector
    filtered_text = normalizeText(text)
    ascii_ref = ord('A')
    total = 0 ciphered_text += chr((ord(text[i]) + ord(vig_key[i % len(vig_key)]) + shift) % ALPHA_SIZE + ascii_ref)
    for letter in filtered_text:
        if letter.isalpha():
            freq_vector[ord(letter) - ascii_ref] += 1
            total += 1

    result = [i/total for i in freq_vector]
    return result
def calculate_chi_squared(observed_freq, expected_freq):
    """
    Parameters
    ----------
    observed_freq: the observed frequencies
    expected_freq: the expected frequencies

    Returns
    -------
    the chi-squared statistic
    """
    ALPHA_SIZE = 26
    current_distance = 0
    for i in range(ALPHA_SIZE):
        Oi = observed_freq[i]
        Ei = expected_freq[i]
        current_distance += ((Oi - Ei) ** 2) / Ei
    return current_distance
def find_best_shift(text, ref_freq):
    """
    Parameters
    ----------
    text: the text to analyze
    ref_freq: the output of the freq_analysis function on a reference text

    Returns
    -------
    the shift that gives the smallest chi-squared statistic
    """
    ALPHA_SIZE = 26
    minimum_distance = float('inf')
    supposed_shift = 0

    for shift in range(ALPHA_SIZE):
        decrypted_text = caesar_decrypt(text, shift)
        freq_dist = freq_analysis(decrypted_text)
        current_distance = calculate_chi_squared(freq_dist, ref_freq)

        if current_distance < minimum_distance:
            minimum_distance = current_distance
            supposed_shift = shift

    return supposed_shift
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
    if not all(value != 0.0 for value in ref_freq):
        print("Error ---- There are 0.0 values in ref_freq, cannot divide by 0")
        return 0

    text = normalizeText(text)

    if not text or not ref_freq:
        return -1

    return find_best_shift(text, ref_freq)


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

    text = normalizeText(text)
    key = normalizeText(key)
    ciphered_text = ""
    ascii_ref = ord('A')
    key_length = len(key)
    for i, letter in enumerate(text):
        if letter.isalpha():
            ascii_letter = ord(letter)
            ascii_key = ord(key[i % key_length])
            ciphered_text += chr((ascii_letter - ascii_ref + ascii_key - ascii_ref) % 26 + ascii_ref)
        else:
            ciphered_text += letter
    return ciphered_text


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
    text = normalizeText(text)
    key = normalizeText(key)
    deciphered_text = ""
    ascii_ref = ord('A')
    key_length = len(key)
    for i, letter in enumerate(text):
        if letter.isalpha():
            ascii_letter = ord(letter)
            ascii_key = ord(key[i % key_length])
            deciphered_text += chr((ascii_letter - ascii_ref - ascii_key + ascii_ref) % 26 + ascii_ref)
        else:
            deciphered_text += letter
    return deciphered_text


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
    text = normalizeText(text)

    if len(text) < 2:
        return 0
    letter_counts = [text.count(chr(i)) for i in range(ord('A'), ord('Z') + 1)]

    N = sum(letter_counts)

    return  (len(letter_counts) * sum(ni * (ni - 1) for ni in letter_counts)) / (N * (N - 1))
def find_key_length(text, max_key_length, ref_ic):
    """
    Estime la longueur de la clé en examinant l'indice de coïncidence pour les sous-textes créés
    en prenant les lettres à des intervalles équivalant à la longueur de la clé potentielle.

    Parameters
    ----------
    text: le texte chiffré à analyser
    max_key_length: la longueur maximale de la clé à tester
    french_ic: l'indice de coïncidence d'un texte français standard pour comparaison

    Returns
    -------
    La longueur de clé estimée.
    """
    text = normalizeText(text)
    estimated_key_length = 0
    closest_ic_diff = float('inf')

    for key_length in range(1, max_key_length + 1):

        subtext = text[::key_length]
        ic = coincidence_index(subtext)

        ic_diff = abs(ic - ref_ic)

        if ic_diff < closest_ic_diff:
            closest_ic_diff = ic_diff
            estimated_key_length = key_length

    return estimated_key_length

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
    text = normalizeText(text)
    key_length = find_key_length(text, 20, ref_ci)
    key = ""
    print(key_length)
    ascii_ref = ord('A')
    for i in range(key_length):
        shift = caesar_break(text[i::key_length], ref_freq)
        key += chr(shift % 26 + ascii_ref)
    return key

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
    text = normalizeText(text)
    vig_key = normalizeText(vigenere_key)
    shift = 0
    ciphered_text = ""
    ascii_ref = ord('A')
    ALPHA_SIZE = 26

    for i in range(len(text)):
        ciphered_text += chr((ord(text[i]) + ord(vig_key[i % len(vig_key)]) + shift) % ALPHA_SIZE + ascii_ref)
        if not i % len(vigenere_key):
            shift += caesar_key

    return ciphered_text


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
    text = normalizeText(text)
    vig_key = normalizeText(vigenere_key)
    shift = 0
    plain_text = ""
    ascii_ref = ord('A')
    ALPHA_SIZE = 26

    for i in range(len(text)):
        plain_text += chr((ord(text[i]) - ord(vig_key[i % len(vig_key)]) - shift) % ALPHA_SIZE + ascii_ref)
        if not i % len(vigenere_key):
            shift += caesar_key

    return plain_text


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

    # Read the example French text and calculate the reference frequencies
    with open('text_fr.txt', 'r', encoding='utf-8') as file:
        example_french_data = file.read()
    ref_freq = freq_analysis(example_french_data)
    ref_ci = coincidence_index(example_french_data)
    print(ref_freq)
    print(ref_ci)
    # Create a ciphered text using the caesar_encrypt function
    text = "The quick brown fox jumps over the lazy dog"
    key = 3
    ciphered_text = caesar_encrypt(text, key)
    print(f"Ciphered text: {ciphered_text}")

    # Use caesar_break to find the key
    found_key = caesar_break(ciphered_text, ref_freq)
    print(f"Found key: {found_key}")

    # Decrypt the ciphered text using the found key
    decrypted_text = caesar_decrypt(ciphered_text, found_key)
    print(f"Decrypted text: {decrypted_text}")
    # Read the ciphered text
    with open('vigenere.txt',  'r', encoding='utf-8') as file:
        ciphered_text = file.read()

    key_length = find_key_length(ciphered_text, 20, ref_ci)

    print("Longueur de clef trouvé : " + str(key_length))

    key = vigenere_break(ciphered_text, ref_freq, ref_ci)
    print("Found key : " + key)

    cip = vigenere_caesar_encrypt("Hello world", "maison", 2)
    print(vigenere_caesar_decrypt(cip,"maison",2))
if __name__ == "__main__":
    main()


