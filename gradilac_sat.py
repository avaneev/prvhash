# gradilac/prvhash 4.3.1 fuse=1 CSPRNG (XOR) SAT solving simulation -
# finds a key specified in seed_i, lcg_i, and hcv[].
# requires autosat from https://github.com/petersn/autosat
# and python-sat
#
# use "time python gradilac_sat.py" to measure solving time.
# increase "bits" (an even value) and "hci" to estimate solving complexity.
# "bits=64" corresponds to uint64_t variable size. a minimal reasonable "bits"
# value is 6; lower values solve instantly. the time exponent dependence on
# "hci" itself depends on "bits" asymptotically, with higher "bits" values
# producing a more linear "hci*bits" exponent.

import autosat

##### simulation parameters

bits = 6 # state variable size
hci = 2 # number of hash elements in use

seed_i = 4 # prng init
lcg_i = 5 # prng init
hcv = [13,4,13,3,4,14,12,5,12,15,6,1,9,13,1,15,12,6,11,4,8,5,9,12,13,0,2,1,9,12,15,11] # hash init (hci)

hc = hci # hash array length
num_obs = 64 # number of observations to use for solving

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
calc_lcg = lcg_i&bmask
calc_h = []

for i in range(hc):
    if(i < hci):
        calc_h.append(hcv[i]&bmask)
    else:
        calc_h.append(0)

calc_x = 0

for i in range(5):
    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])

for i in range(hc+1):
    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])
    calc_x += 1

for i in range(num_obs):
    calc_seed, calc_lcg, calc_h[calc_x%hc], out1 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])
    calc_x += 1
    calc_seed, calc_lcg, calc_h[calc_x%hc], out2 = prvhash_core_calc(calc_seed, calc_lcg, calc_h[calc_x%hc])
    calc_x += 1

    obs.append(out1^out2)

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
start_lcg = inst.new_vars(bits)
start_h = []

seed = start_seed[:]
lcg = start_lcg[:]
h = []

for i in range(hc):
    if(i < hci):
        start_h.append(inst.new_vars(bits))
        h.append(start_h[i][:])
    else:
        h.append(inibits(inst, bits, 0))

x = 0

for k in range(5):
    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])

for k in range(hc+1):
    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])
    x += 1

for k in range(num_obs):
    seed, lcg, h[x % hc], out1 = prvhash_core_sat(seed, lcg, h[x % hc])
    x += 1
    seed, lcg, h[x % hc], out2 = prvhash_core_sat(seed, lcg, h[x % hc])
    x += 1

    out = xor(out1, out2)

    for i, b in enumerate(out):
        b.make_equal(bool((obs[k] >> i) & 1))

model = inst.solve(solver_name="Glucose3",decode_model=False)
#print(model)

print("seed = %4i (%4i)" % (autosat.decode_number(start_seed, model), (seed_i&bmask)))
print("lcg  = %4i (%4i)" % (autosat.decode_number(start_lcg, model), (lcg_i&bmask)))

for i in range(hci):
    print("hash = %4i (%4i)" % (autosat.decode_number(start_h[i], model), (hcv[i]&bmask)))
