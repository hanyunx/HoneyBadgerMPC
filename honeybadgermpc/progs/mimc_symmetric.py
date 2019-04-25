from honeybadgermpc.field import GF
from honeybadgermpc.mpc import PreProcessedElements, Subgroup
from honeybadgermpc.progs.mimc import mimc_mpc, mimc_plain

pp_elements = PreProcessedElements()
field = GF(Subgroup.BLS12_381)


# def get_key():
#     """ """
#     return field(randint(0, field.modulus))

# async def get_key(context):
#     """ """
#     return pp_elements.get_rand(context)


def mimc_encrypt(key, ms):
    """
    ms - blocks of plaintext, that is, plaintext -> {m1, m2,...,ml}
         Each plaintext is a field element.
    ciphertext <- F_MiMC(counter, key) + plaintext
    """
    ciphertext = []
    for i in range(len(ms)):
        ciphertext.append(mimc_plain(i, key) + ms[i])

    return ciphertext


async def mimc_decrypt(context, key, cs):
    """
    plaintext <- F_MiMC(counter, key) - ciphertext
    """
    decrypted = []
    for i in range(len(cs)):
        d = cs[i] - (await mimc_mpc(context, field(i), key))
        decrypted.append(d)

    return decrypted
