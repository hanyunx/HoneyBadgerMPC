import asyncio
from random import randint
from honeybadgermpc.field import GF
from honeybadgermpc.mpc import PreProcessedElements, Subgroup
from honeybadgermpc.elliptic_curve import Point, Jubjub
from honeybadgermpc.progs.jubjub import share_mul
from honeybadgermpc.progs.mimc import mimc_mpc, mimc_plain

pp_elements = PreProcessedElements()
field = GF(Subgroup.BLS12_381)
CURVE = Jubjub()
KEY_LENGTH = 32
# GP: The generator of Jubjub curve, hardcode here
GP = Point(5,
           6846412461894745224441235558443359243034138132682534265960483512729196124138,
           CURVE)


async def key_generation(context):
    """
    The MPC system creates random bitwise shared value [x]_B
    as the private key (priv_key),
    then calcultes X = ([x]G).open as the public key (pub_key)
    """
    # Generate the private key
    priv_key = [pp_elements.get_bit(context) for _ in range(KEY_LENGTH)]

    # Compute [X] = [x]G, then open it as public key
    pub_key_share = await share_mul(context, priv_key, GP)
    x, y = await asyncio.gather(pub_key_share.xs.open(), pub_key_share.ys.open())
    pub_key = Point(x, y, CURVE)
    return priv_key, pub_key


def mimc_encrypt(pub_key, ms, seed=None):
    """
    The dealer does the counter-mode encryption to plaintext,
    then sents (ciphertext, A) to the MPC system.

    a - randomly generated, only kept by the dealer
    a_ - auxiliary variable to be sent to MPC system for decryption
    k - x coordinate of a * pub_key, secret key only kept by the dealer
    ms - blocks of plaintext, that is, plaintext -> {m1, m2,...,ml}
    i - The index of the plaintext array, take it as counter
    ciphertext - a field element
    """
    if seed:
        a = seed
    else:
        a = randint(0, field.modulus)

    a_ = a * GP
    k = (a * pub_key).x
    ciphertext = []

    for i in range(len(ms)):
        ciphertext.append(mimc_plain(i, k) + ms[i])

    return (ciphertext, a_)


async def mimc_decrypt(context, priv_key, ciphertext):
    """
    The MPC system decrypts the ciphertext to get the shared value of plaintext.

    ([x]A).x -> [k], where k = S.x and S = aX = axG := xA
    cs - blocks of ciphertext, {c1, c2,...,cl}
    """
    (cs, a_) = ciphertext
    k_share = (await share_mul(context, a_, priv_key)).xs
    decrypted = []

    for i in range(len(cs)):
        d = cs[i] - (await mimc_mpc(context, i, k_share))
        decrypted.append(d)

    return decrypted
