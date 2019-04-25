import asyncio
from pytest import mark
from random import randint
from honeybadgermpc.field import GF
from honeybadgermpc.mpc import PreProcessedElements, Subgroup
from honeybadgermpc.elliptic_curve import Point
from honeybadgermpc.progs.jubjub import share_mul
from honeybadgermpc.progs.mixins.share_arithmetic import BeaverMultiply
from honeybadgermpc.progs.mimc_jubjub_pkc import (mimc_encrypt, mimc_decrypt,
                                                  GP, CURVE, KEY_LENGTH)

MIXINS = [BeaverMultiply()]
PREPROCESSING = ['rands', 'triples', 'zeros', 'cubes', 'bits']
n, t = 3, 1
k = 10000


@mark.asyncio
async def test_mimc_jubjub_pkc(test_preprocessing, test_runner):

    field = GF(Subgroup.BLS12_381)
    plaintext = [randint(0, field.modulus)]
    priv_key_ = [field(randint(0, 1)) for _ in range(KEY_LENGTH)]
    seed = randint(0, field.modulus)

    async def _prog(context):
        pp_elements = PreProcessedElements()
        # Key Generation
        priv_key = [pp_elements.get_zero(context) + priv_key_[i]
                    for i in range(KEY_LENGTH)]
        pub_key_share = await share_mul(context, priv_key, GP)
        print("\npriv_key_share done ...")
        x, y = await asyncio.gather(pub_key_share.xs.open(), pub_key_share.ys.open())
        print("\nx, y done...")
        pub_key = Point(x, y, CURVE)
        print("\npub_key ...")

        # Encryption & Decryption
        cipher = mimc_encrypt(pub_key, plaintext, seed)
        decrypted_value = await mimc_decrypt(context, priv_key, cipher)

        assert (await context.ShareArray(decrypted_value).open()) == plaintext

    await test_runner(_prog, n, t, PREPROCESSING, k, MIXINS)
