from pytest import mark
from random import randint
from honeybadgermpc.field import GF
from honeybadgermpc.mpc import TaskProgramRunner, Subgroup
from honeybadgermpc.mixins import BeaverTriple, MixinOpName
from progs.symmetrc_mimc import key_generation, mimc_encrypt, mimc_decrypt


@mark.asyncio
async def test_mimc(test_preprocessing):
    n, t = 3, 1
    to_generate = ['zeros', 'rands', 'triples', 'bits', "cubes"]
    for x in to_generate:
        test_preprocessing.generate(x, n, t, k=2000)

    async def _prog(context):
        plaintext = randint(0, GF(Subgroup.BLS12_381).modulus)

        priv_key, pub_key = await key_generation(context)

        cipher = mimc_encrypt(pub_key, plaintext)
        decryption_value = await mimc_decrypt(context, priv_key, cipher)

        assert (await decryption_value.open()) == plaintext

    program_runner = TaskProgramRunner(n, t, {
        MixinOpName.MultiplyShare: BeaverTriple.multiply_shares,
    })
    program_runner.add(_prog)
    await program_runner.join()
