# tango642 4.3.9 SAT solving simulation -
# finds a key specified in seed_i and hcv[].
# requires autosat from https://github.com/petersn/autosat
# and python-sat
#
# use "time python t642_sat.py" to measure solving time.
# increase "bits" (an even value) to estimate solving complexity. "bits=64"
# corresponds to real tango642 variable size. a minimal reasonable "bits"
# value is 6; lower values solve instantly. base exponential time increase can
# be assessed by setting hci=0 and incrementally assigning various "bits"
# values. note that the SAT solver may have to consider most of the system
# anyway, so a time difference between various "hci" values may not be
# pronounced. the time exponent dependence on "hci" itself depends on "bits"
# asymptotically, with higher "bits" values producing a more linear "hci*bits"
# exponent.

import autosat

##### simulation parameters

bits = 6 # state variable size
hci = 2 # number of keyed hash elements in use (key length-1)
ivlen = 4 # nonce vector length

seed_i = 4 # keyed prng init (key value 1)
hcv = [3,14,3,13,14,4,2,15,2,5,6,11,9,1,11,5,8,6,10,7,5,6,3,10,3,0,2,9,9,12,15,11] # key values
iv = [15,9,4,6] # nonce vector

hc = 16 # keyed hash array length
fc = 15 # firewall prng init length
num_obs = 16 # number of observations to use for solving (*4)

#####

def inibits(inst,l,ini):
    result = []
    for i in range(l):
        if( (ini>>i)&1 ):
            v=True
        else:
            v=False
        result.append(inst.get_constant(v))
    return result

@autosat.sat
def full_adder(a, b, carry_in):
    r = a + b + carry_in
    return r & 1, (r & 2) >> 1

def add(a, b):
    assert len(a) == len(b)
    carry = False
    result = []
    for a_bit, b_bit in zip(a, b):
        sum_bit, carry = full_adder(a_bit, b_bit, carry)
        result.append(sum_bit)
    return result

def xor(a, b):
    assert len(a) == len(b)
    return [i ^ j for i, j in zip(a, b)]

def and_(a, b):
    assert len(a) == len(b)
    return [i & j for i, j in zip(a, b)]

def mul(a, b):
    assert len(a) == len(b)
    result = [a[0] & bit for bit in b]
    for i in range(1, len(a)):
        addend = [a[i] & bit for bit in b[:-i]]
        result[i:] = add(result[i:], addend)
    return result

obs = [] # observations
bits2 = bits>>1
bmask = (1<<bits)-1
rawbits5 = 0
rawbitsA = 0

for i in range(bits2):
    rawbits5 <<= 2
    rawbits5 |= 0x1
    rawbitsA <<= 2
    rawbitsA |= 0x2

def prvhash_core_calc(seed, lcg, h):
    seed = seed * ( lcg * 2 + 1 )
    seed &= bmask
    rs = seed>>bits2 | seed<<bits2
    rs &= bmask
    h += rs + rawbitsA
    h &= bmask
    lcg += seed + rawbits5
    lcg &= bmask
    seed ^= h
    out = lcg ^ rs
    return seed, lcg, h, out

# calculate real outputs

calc_seed = seed_i&bmask
calc_lcg = 0
calc_h = []
calc_seed1 = 0
calc_lcg1 = 0
calc_seed2 = 0
calc_lcg2 = 0
calc_seed3 = 0
calc_lcg3 = 0
calc_seed4 = 0
calc_lcg4 = 0
calc_h2 = [0,0,0,0,0]

for i in range(hc):
    if(i < hci):
        calc_h.append(hcv[i]&bmask)
    else:
        calc_h.append(0)

calc_x = 0
calc_x2 = 0
ivpos = 0

for i in range(5):
    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])

for i in range(hc):
    if((i&1)==1 and ivpos < ivlen):
        calc_seed ^= iv[ivpos]&bmask
        calc_lcg ^= iv[ivpos]&bmask
        ivpos += 1

    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])
    calc_x += 1

for i in range(hc+1):
    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])
    calc_x += 1

for i in range(fc+num_obs):
    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])
    calc_x += 1

    calc_seed4 ^= out1
    calc_seed1, calc_lcg1, calc_h2[(calc_x2+0)%5], outf1 = prvhash_core_calc(calc_seed1, calc_lcg1, calc_h2[(calc_x2+0)%5])
    calc_seed2, calc_lcg2, calc_h2[(calc_x2+1)%5], outf2 = prvhash_core_calc(calc_seed2, calc_lcg2, calc_h2[(calc_x2+1)%5])
    calc_seed3, calc_lcg3, calc_h2[(calc_x2+2)%5], outf3 = prvhash_core_calc(calc_seed3, calc_lcg3, calc_h2[(calc_x2+2)%5])
    calc_seed4, calc_lcg4, calc_h2[(calc_x2+3)%5], outf4 = prvhash_core_calc(calc_seed4, calc_lcg4, calc_h2[(calc_x2+3)%5])
    calc_x2 += 1

    if(i>=fc):
        obs.append(outf1)
        obs.append(outf2)
        obs.append(outf3)
        obs.append(outf4)

print("----")

# solve initial state

inst = autosat.Instance()

BITR5 = inibits(inst, bits, rawbits5)
BITRA = inibits(inst, bits, rawbitsA)

def prvhash_core_sat(seed, lcg, h):
    seed = mul(seed, [True] + lcg[:-1])
    rs = seed[bits2:] + seed[:bits2]
    h = add(h, add(rs, BITRA))
    lcg = add(lcg, add(seed, BITR5))
    seed = xor(seed, h)
    out = xor(lcg, rs)
    return seed, lcg, h, out

start_seed = inst.new_vars(bits)
start_h = []

seed = start_seed[:]
h = []

for i in range(hc):
    if(i < hci):
        start_h.append(inst.new_vars(bits))
        h.append(start_h[i][:])
    else:
        h.append(inibits(inst, bits, 0))

lcg = inibits(inst, bits, 0)
seed1 = inibits(inst, bits, 0)
lcg1 = inibits(inst, bits, 0)
seed2 = inibits(inst, bits, 0)
lcg2 = inibits(inst, bits, 0)
seed3 = inibits(inst, bits, 0)
lcg3 = inibits(inst, bits, 0)
seed4 = inibits(inst, bits, 0)
lcg4 = inibits(inst, bits, 0)
h2 = [inibits(inst, bits, 0),inibits(inst, bits, 0),inibits(inst, bits, 0),inibits(inst, bits, 0),inibits(inst, bits, 0)]

x = 0
x2 = 0
ivpos = 0

for k in range(5):
    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])

for k in range(hc):
    if((k&1)==1 and ivpos < ivlen):
        seed = xor(seed, inibits(inst,bits,iv[ivpos]))
        lcg = xor(lcg, inibits(inst,bits,iv[ivpos]))
        ivpos += 1

    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])
    x += 1

for k in range(hc+1):
    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])
    x += 1

for k in range(fc+num_obs):
    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])
    x += 1

    seed4 = xor(seed4, out1)
    seed1, lcg1, h2[(x2+0)%5], outf1 = prvhash_core_sat(seed1, lcg1, h2[(x2+0)%5])
    seed2, lcg2, h2[(x2+1)%5], outf2 = prvhash_core_sat(seed2, lcg2, h2[(x2+1)%5])
    seed3, lcg3, h2[(x2+2)%5], outf3 = prvhash_core_sat(seed3, lcg3, h2[(x2+2)%5])
    seed4, lcg4, h2[(x2+3)%5], outf4 = prvhash_core_sat(seed4, lcg4, h2[(x2+3)%5])
    x2 += 1

    if(k>=fc):
        for i, b in enumerate(outf1):
            b.make_equal(bool((obs[(k-fc)*4+0] >> i) & 1))
        for i, b in enumerate(outf2):
            b.make_equal(bool((obs[(k-fc)*4+1] >> i) & 1))
        for i, b in enumerate(outf3):
            b.make_equal(bool((obs[(k-fc)*4+2] >> i) & 1))
        for i, b in enumerate(outf4):
            b.make_equal(bool((obs[(k-fc)*4+3] >> i) & 1))

model = inst.solve(solver_name="Glucose3",decode_model=False)
#print(model)

print("seed = %4i (%4i)" % (autosat.decode_number(start_seed, model), (seed_i&bmask)))

for i in range(hci):
    print("hash = %4i (%4i)" % (autosat.decode_number(start_h[i], model), (hcv[i]&bmask)))
