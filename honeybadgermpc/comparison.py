from honeybadgermpc.mpc import *
import logging
import asyncio
from honeybadgermpc.field import GF
from gmpy2 import num_digits
from honeybadgermpc.mixins import BeaverTriple, MixinOpName
from math import sqrt

async def comparison(context, a_share, b_share):
    """MULTIPARTY COMPARISON - An Improved Multiparty Protocol for 
    Comparison of Secret-shared Values by Tord Ingolf Reistad (2007)
    This method `greater_than_equal` method which can compare 
    Zp field elements and gives a secret result shared over Zp.
    `greater_than_equal` method which can compare Zp field
    """

    pp_elements = PreProcessedElements()
    modulus = Subgroup.BLS12_381
    Field = GF.get(modulus)
    l = num_digits(modulus, 2)

    async def get_random_bit():
        r = pp_elements.get_rand(context)
        r_square = await (r*r)
        r_sq = await r_square.open()

        if pow(r_sq, (modulus-1)//2) != Field(1) or r_sq ==0:
            return await get_random_bit()

        root = r_sq.sqrt()
        return (~Field(2)) * ((~root)*r + Field(1))

    # assert 2 * a_share + 1 < modulus, "[a] < (p-1)/2 must hold"
    # assert 2 * b_share + 1 < modulus, "[b] < (p-1)/2 must hold"

    # ############# PART 1 ###############
    # First Transformation
    r_bits = [pp_elements.get_bit(context) for _ in range(l)]
    r_B = Field(0)
    for i, b in enumerate(r_bits):
        r_B = r_B + (2**i) * b

    # assert 2**l < modulus

    z = a_share - b_share

    twoz0_open = int(await (2*z).open()) % 2
    print('2z0:', twoz0_open)
    a_open = int(await a_share.open())
    b_open = int(await b_share.open())
    print ('a_open:', a_open)
    print ('b_open:', b_open)
    assert (a_open < b_open) == (twoz0_open)
    
    c = await (2 * z + r_B).open()
    c_bits = [Field(int(x)) for x in list('{0:0255b}'.format(c.value))]
    c_bits.reverse()

    r_0 = r_bits[0]        # [r0]
    c0 = c_bits[0]

    r_B_open = await r_B.open()
    r_0_open = int(r_B_open) % 2
    r_0_open2 = await r_0.open()
    assert r_0_open == r_0_open2
    print('r_B.open():', r_B_open)
    rBgtC = int(r_B_open) > int(c)
    print('r_B > c:', int(r_B_open) > int(c))

    # Check equation 6
    assert twoz0_open == (c0 ^ r_0_open ^ rBgtC)
    print('r_0_open:', r_0_open)

    # ############# PART 2 ###############
    # Compute X
    X = Field(0)
    for i in range(l-1):
        cr = Field(0)
        for j in range(i+1, l):
            c_xor_r = r_bits[j] + c_bits[j] - Field(2)*c_bits[j]*r_bits[j]
            cr = cr + c_xor_r
        cr_open = await cr.open()
        pp = pow(2, int(cr_open))
        X = X + (Field(1) - c_bits[i]) * pp * r_bits[i]
    X = X + (Field(1) - c_bits[l-1]) * r_bits[l-1]    # ???

    # ############# PART 3 ###############
    # Extracting LSB
    # TODO
    # assert X.v.value < sqrt(4 * modulus)

    s_bits = [pp_elements.get_bit(context) for _ in range(l)]
    
    s_0 = s_bits[0]
    s1 = s_bits[-1]        # [s_{l-1}]    
    s2 = s_bits[-2]        # [s_{l-2}]
    s1s2 = await (s1*s2)

    s_B = Field(0)
    for i, b in enumerate(s_bits):
        s_B = s_B + (2**i) * b

    # Compute d_hat for check
    # d_hat = s_hat + x
    s_hat_bits = s_bits[:-2]
    assert len(s_hat_bits) == len(s_bits) - 2
    s_hat_B = Field(0)
    for i, b in enumerate(s_hat_bits):
        s_hat_B = s_hat_B + (2**i) * b

    s_hat_B_open = await s_hat_B.open()
    print('s_hat_B.open():', s_hat_B_open)
    s_B_open = await s_B.open()
    print('s.open():', s_B_open)
    print('(s_B-s_hat_B):', hex(int(s_B_open - s_hat_B_open)))

    d_hat = s_hat_B + X
    d_hat_open = await d_hat.open()
    import math
    # Condition from paper
    assert int(d_hat_open) < 2**(l-2) + math.sqrt(4 * modulus)

    d_hat_0_open = int(d_hat_open) % 2
    
    D = s_B + X
    d = await D.open()
    d0 = int(d) & 1

    # TODO
    # assert d > sqrt(4 * modulus)
    
    dxor1 = d0 ^ (d.value < 2**(l-1))     # d0 ^ (d < 2**{l-1})
    dxor2 = d0 ^ (d.value < 2**(l-2))     # d0 ^ (d < 2**{l-1})
    dxor12 = d0 ^ (d.value < (2**(l-1) + 2**(l-2)))         # d0 ^ (d < (2**{l-2} + 2**{l-1}))

    #[d_0]
    d_0 = d0 * (Field(1) + s1s2 - s1 - s2) \
        + dxor2 * (s2 - s1s2) \
        + dxor1 * (s1 - s1s2) \
        + dxor12 * s1s2

    # Check alternate way of computing d_hat_0
    d_0_open = await d_0.open()
    assert d_0_open == d_hat_0_open
    print('d_0_open:', d_0_open)

    x_0 = s_0 + d_0 - 2 * (await (s_0 * d_0))    # [x0] = [s0] ^ [d0], equal to [r]B > c

    # Check alternate way of computing x0
    X_open = await X.open()
    X_0_open = int(X_open) % 2
    x_0_open = await x_0.open()
    assert x_0_open == X_0_open
    assert int(int(r_B_open) > int(c)) == int(x_0_open)

    r_0_open = await r_0.open()
    print('c_0:', c0)
    print('r_0:', r_0_open)
    print('x_0:', x_0_open)
    print('c0 ^ r_0 ^ x_0:', c0 ^ r_0_open ^ x_0_open)
    c0_xor_r0 = c0 + r_0 - 2*c0*r_0    #c0 ^ r_0
    final_val = c0_xor_r0 + x_0- 2*(await (c0_xor_r0*x_0)) #c0 ^ r_0 ^ x_0
    print ('final_val:', await final_val.open())
    return final_val


async def test_comp(context):
    pp_elements = PreProcessedElements()
    a = pp_elements.get_zero(context) + context.Share(233)
    b = pp_elements.get_zero(context) + context.Share(3333)

    r = pp_elements.get_rand(context)
    result = await comparison(context, a, b)
    result_open = await result.open()
    print(result_open)
    
    if result_open == 1:
        print("Comparison result: a < b")
    else:
        print("Comparison result: a >= b")

if __name__ == '__main__':
    n, t = 3, 1
    pp_elements = PreProcessedElements()
    logging.info('Generating random shares of zero in sharedata/')
    pp_elements.generate_zeros(1000, n, t)
    logging.info('Generating random shares in sharedata/')
    pp_elements.generate_rands(1000, n, t)
    logging.info('Generating random shares of triples in sharedata/')
    pp_elements.generate_triples(1000, n, t)
    logging.info('Generating random shares of bits in sharedata/')
    pp_elements.generate_bits(1000, n, t)

    asyncio.set_event_loop(asyncio.new_event_loop())
    loop = asyncio.get_event_loop()
    try:
        programRunner = TaskProgramRunner(n, t, {MixinOpName.MultiplyShare: BeaverTriple.multiply_shares})
        programRunner.add(test_comp)
        loop.run_until_complete(programRunner.join())
    finally:
        loop.close()