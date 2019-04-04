from random import randint
from asyncio import gather
from honeybadgermpc.field import GF
from honeybadgermpc.mpc import PreProcessedElements, Subgroup
from honeybadgermpc.elliptic_curve import Point, Jubjub
from progs.jubjub import share_mul
from progs.mimc import mimc_mpc, mimc_plain

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
    # priv_key_p = field(0)
    # for i in range(KEY_LENGTH):
    #     priv_key_p += (await (2**(KEY_LENGTH-i-1)) * priv_key[i])

    # Compute [X] = [x]G, then open it as public key
    pub_key_share = await share_mul(context, GP, priv_key)
    x, y = await gather(pub_key_share.xs.open(), pub_key_share.ys.open())
    pub_key = Point(x, y, CURVE)
    return priv_key, pub_key


def mimc_encrypt(pub_key, plaintext):
    """
    The dealer does the counter-mode encryption to plaintext,
    then sents (ciphertext, A) to the MPC system.

    a - randomly generated, only kept by the dealer
    a_ - auxiliary variable to be sent to MPC system for decryption
    k - x coordinate of a * pub_key, secret key only kept by the dealer
    ctr - counter, ranomly generated here and then sent to MPC system
    ms - blocks of plaintext, that is, plaintext -> {m1, m2,...,ml}
    ciphertext - a field element
    """
    a = randint(0, field.modulus)
    a_ = a * GP
    k = (a * pub_key).x
    ctr = field(randint(0, field.modulus))
    ciphertext = mimc_plain(ctr, k) + plaintext

    return (ciphertext, a_, ctr)


async def mimc_decrypt(context, priv_key, cipher):
    """
    The MPC system decrypts the ciphertext to get the shared value of plaintext.

    ([x]A).x -> [k], where k = S.x and S = aX = axG := xA
    cs - blocks of ciphertext, {c1, c2,...,cl}
    """
    (ciphertext, a_, ctr) = cipher
    k_share = (await share_mul(context, a_, priv_key)).xs

    return ciphertext - (await mimc_mpc(context, ctr, k_share))
