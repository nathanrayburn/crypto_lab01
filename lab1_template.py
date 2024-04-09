import concurrent
from concurrent.futures import ProcessPoolExecutor

import unidecode
import re
from statistics import mean

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
    total = 0
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

    # Calculating the average IC for each key length and the difference from the reference IC
    final_ics = [abs(mean([coincidence_index(text[j::i]) for j in range(i)]) - ref_ic)
                 for i in range(1, min(max_key_length + 1, len(text) + 1))]

    key_length = final_ics.index(min(final_ics)) + 1
    print("key length :" + str(key_length))
    return key_length

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
    vigenere_key = normalizeText(vigenere_key)
    ascii_ref = ord('A')
    ALPHA_SIZE = 26
    shift = 0
    ciphered_text = ""

    for i, char in enumerate(text):
        if char.isalpha():
            vig_key_index = i % len(vigenere_key)  # Adjust the index for the shift
            vig_char = ord(vigenere_key[vig_key_index]) - ascii_ref
            char_shift = (ord(char) - ascii_ref + vig_char + shift) % ALPHA_SIZE
            ciphered_text += chr(char_shift + ascii_ref)
            if (i + 1) % len(vigenere_key) == 0:
                shift = (shift + caesar_key) % ALPHA_SIZE

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
    vigenere_key = normalizeText(vigenere_key)
    ascii_ref = ord('A')
    ALPHA_SIZE = 26
    shift = 0
    plain_text = ""
    for i, char in enumerate(text):
        if char.isalpha():
            vig_key_index = i % len(vigenere_key)  # Adjust the index for the shift
            vig_char = ord(vigenere_key[vig_key_index]) - ascii_ref
            char_shift = (ord(char) - ascii_ref - vig_char - shift + ALPHA_SIZE) % ALPHA_SIZE
            plain_text += chr(char_shift + ascii_ref)
            if (i + 1) % len(vigenere_key) == 0:
                shift = (shift + caesar_key) % ALPHA_SIZE
    return plain_text

def mean_ic(text, key_length):
    ics = []
    for i in range(key_length):
        block = text[i::key_length]
        ics.append(coincidence_index(block))
    return mean(ics)
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

    max_key_size = 20
    ALPHA_SIZE = 26
    min_ic_text = "CaesarDecrypted"
    min_ic_value = float("inf")
    min_ic_caesar_key = 0

    for i in range(1, max_key_size + 1):
        for j in range(ALPHA_SIZE):
            final_text = ''.join(
                [caesar_decrypt(text[chunk_start_index:chunk_start_index + i], ((j * (chunk_start_index // i)) % ALPHA_SIZE)) for chunk_start_index in range(0, len(text), i)])

            ics = []
            for index in range(i):
                block = final_text[index::i]
                ics.append(coincidence_index(block))

            ic = abs(mean(ics) - ref_ci)

            if ic < min_ic_value:
                min_ic_text = final_text
                min_ic_value = ic
                min_ic_caesar_key = j

    key_caesar = min_ic_caesar_key
    key_vigenere = vigenere_break(min_ic_text, ref_freq, ref_ci)

    return key_vigenere, key_caesar


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
    print("Found key length : " + str(key_length))
    key = vigenere_break(ciphered_text, ref_freq, ref_ci)
    print(vigenere_decrypt(ciphered_text,key))
    print("----------------------------------------")
    cip = vigenere_encrypt("Vigenere simple en cryptographie décide d’améliorer le chiffre de Vigenère. Son raisonnement est le suivant : le problème avec le chiffre de Vigenère est la réutilisation de la clef. Il décide donc, après chaque utilisation de la clef de la changer en la chiffrant avec le chiffre de César généralisé. Par exemple,si la clef initiale est la clef MAISON et la clef du chiffre de César est 2, les six premières lettres du texte clair sont chiffrées avec MAISON, les suivantes avec OCKUQP, puis QEMWSR","monster")
    key = vigenere_break(cip,ref_freq,ref_ci)
    print("Vigenere simple key :" + key)
    print(vigenere_decrypt(cip, key))
    print("----------------------------------------")
    cip = vigenere_caesar_encrypt("Vigenere caesar  en cryptographie décide d’améliorer le chiffre de Vigenère. Son raisonnement est le suivant : le problème avec le chiffre de Vigenère est la réutilisation de la clef. Il décide donc, après chaque utilisation de la clef de la changer en la chiffrant avec le chiffre de César généralisé. Par exemple,si la clef initiale est la clef MAISON et la clef du chiffre de César est 2, les six premières lettres du texte clair sont chiffrées avec MAISON, les suivantes avec OCKUQP, puis QEMWSR","monster",3)
    vigenere_key, caesar_key = vigenere_caesar_break(cip, ref_freq, ref_ci)
    print(f"Found Vigenere key: {vigenere_key}")
    print(f"Found Caesar key: {caesar_key}")
    decrypted_text = vigenere_caesar_decrypt(cip, vigenere_key, caesar_key)
    print(f"Decrypted text: {decrypted_text}")

    print("----------------------------------------")
    with open('vigenereAmeliore.txt',  'r', encoding='utf-8') as file:
        ciphered_text = file.read()

    vigenere_key, caesar_key = vigenere_caesar_break(ciphered_text, ref_freq, ref_ci)
    print(f"Found Vigenere key: {vigenere_key}")
    print(f"Found Caesar key: {caesar_key}")

    decrypted_text = vigenere_caesar_decrypt(ciphered_text, vigenere_key, caesar_key)
    print(f"Decrypted text: {decrypted_text}")
if __name__ == "__main__":
    main()


