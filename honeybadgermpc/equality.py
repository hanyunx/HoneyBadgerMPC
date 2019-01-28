from honeybadgermpc.mpc import *
# from honeybadgermpc.mpc import Mpc, generate_test_zeros, generate_test_randoms, generate_test_triples, TaskProgramRunner
import logging
import asyncio

# zeros_files_prefix = 'sharedata/test_zeros'
# triples_files_prefix = 'sharedata/test_triples'
# random_files_prefix = 'sharedata/test_random'
# bits_files_prefix = 'sharedata/test_bits'

async def equality(context, p_share, q_share):

    def legendre_mod_p(a):
        """Return the legendre symbol ``legendre(a, p)`` where *p* is the
        order of the field of *a*.
        """

        assert a.modulus % 2 == 1
        b = (a ** ((a.modulus - 1)//2))
        if b == 1:
            return 1
        elif b == a.modulus-1:
            return -1
        return 0

    diff_a = p_share - q_share
    k = security_parameter = 32

    def mul(x, y):
        a, b, ab = context.get_triple()
        return beaver_mult(context, x, y, a, b, ab)

    async def _gen_test_bit():

        # b \in {0, 1}
        # _b \in {5, 1}, for p = 1 mod 8, s.t. (5/p) = -1
        # so _b = -4 * b + 5
        _b = (-4) * context.get_bit() + context.Share(5)
        _r = context.get_rand()
        _rp = context.get_rand()

        # c = a * r + b * rp * rp
        # If b_i == 1 c_i will always be a square modulo p if a is
        # zero and with probability 1/2 otherwise (except if rp == 0).
        # If b_i == -1 it will be non-square.
        _c = await mul(diff_a, _r) + await mul(_b, await mul(_rp, _rp))
        c = await _c.open()

        return c, _b

    async def gen_test_bit():
        cj, bj = await _gen_test_bit()
        while cj == 0:
            cj, bj = await _gen_test_bit()
        # bj.open() \in {5, 1}

        legendre = legendre_mod_p(cj)

        if legendre == 1:
            xj = (1 / Field(2)) * (bj + context.Share(1))
        elif legendre == -1:
            xj = (-1) * (1 / Field(2)) * (bj - context.Share(1))
        else:
            gen_test_bit()

        return xj

    x = [await gen_test_bit() for _ in range(k)]

    # Take the product (this is here the same as the "and") of all
    # the x'es
    while len(x) > 1:
        x.append(await mul(x.pop(0), x.pop(0)))

    return await x[0].open()

async def test_equality(context):
    p = context.get_zero() + context.Share(2233)
    q = context.get_zero() + context.Share(2333)
    
    # result, count_comm = await equality(context, p, q)
    result = await equality(context, p, q)

    if result == 0:
        print("The two numbers are different! (with high probability)")
    else:
        print("The two numbers are equal!")

    # print("The number of communication count_complexity is: ", count_comm)

if __name__ == '__main__':
    logging.info('Generating random shares of zero in sharedata/')
    generate_test_zeros('sharedata/test_zeros', 1000, 3, 1)
    logging.info('Generating random shares in sharedata/')
    generate_test_randoms('sharedata/test_random', 1000, 3, 1)
    logging.info('Generating random shares of triples in sharedata/')
    generate_test_triples('sharedata/test_triples', 1000, 3, 1)
    logging.info('Generating random shares of bits in sharedata/')
    generate_test_bits('sharedata/test_bits', 1000, 3, 1)


    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    # loop.set_exception_handler(handle_async_exception)
    # loop.set_debug(True)
    try:
        logging.info("Start")
        programRunner = TaskProgramRunner(3, 1)
        programRunner.add(test_equality)
        loop.run_until_complete(programRunner.join())
    finally:
        loop.close()
