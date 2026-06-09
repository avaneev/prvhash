# PRVHASH Uniformity Proofs

(produced by Kimi 2.6 Instant, with an assumption that the current values of Seed, lcg, and Hash are uniform which is validated empirically by PractRand)

I'll build a rigorous proof for the uniformity preservation and the 50% bit-difference property between consecutive outputs. Let me work through this carefully.

## The PRVHASH Core64 Function

```c
static uint64_t prvhash_core64( uint64_t* const Seed0,
    uint64_t* const lcg0, uint64_t* const Hash0 )
{
    uint64_t Seed = *Seed0;
    uint64_t lcg = *lcg0;
    uint64_t Hash = *Hash0;

    Seed *= lcg * 2 + 1;                          // Step 1
    const uint64_t rs = Seed >> 32 | Seed << 32;  // Step 2 (rotate)
    Hash += rs + 0xAAAAAAAAAAAAAAAA;               // Step 3
    lcg += Seed + 0x5555555555555555;             // Step 4
    Seed ^= Hash;                                  // Step 5
    const uint64_t out = lcg ^ rs;                // Step 6

    *Seed0 = Seed; *lcg0 = lcg; *Hash0 = Hash;
    return out;
}
```

---

## Part 1: Uniformity Preservation of State Variables

**Theorem 1:** If $(Seed, lcg, Hash)$ are jointly uniform on $(\mathbb{Z}/2^{64}\mathbb{Z})^3$, then after one iteration, $(Seed', lcg', Hash')$ are also jointly uniform.

We'll prove each marginal is uniform, then joint uniformity.

---

### Lemma 1.1: $Seed'$ is uniform

$Seed' = (Seed \cdot (2 \cdot lcg + 1)) \oplus (Hash + \mathrm{rotl32}(Seed \cdot (2 \cdot lcg + 1)) + 0xAA...AA)$

For **fixed** $lcg$ and $Hash$:

- $m = 2 \cdot lcg + 1$ is **odd** (hence a unit mod $2^{64}$)
- $Seed \mapsto Seed \cdot m$ is a **bijection** on $\mathbb{Z}/2^{64}\mathbb{Z}$
- Let $T = Seed \cdot m$. Then $T$ is uniform when $Seed$ is uniform
- $rs = \mathrm{rotl32}(T)$ is a **permutation**, so $rs$ is uniform in $T$, hence uniform in $Seed$
- $Hash + rs + C$ is uniform (sum of uniform + constant = uniform)
- $Seed' = T \oplus (Hash + rs + C)$

Now, for fixed $lcg$ and $Hash$, as $Seed$ varies:
- $T$ varies uniformly
- $rs$ varies uniformly (deterministically from $T$)
- The pair $(T, rs)$ is in bijection with $T$ (since $rs = \mathrm{rotl32}(T)$)

So $Seed' = T \oplus (Hash + \mathrm{rotl32}(T) + C)$.

For $Seed'$ to be uniform, we need: for each fixed $lcg$, $Hash$, the map $T \mapsto T \oplus (Hash + \mathrm{rotl32}(T) + C)$ is a bijection.

**Claim:** $f(T) = T \oplus \mathrm{rotl32}(T)$ is **not** a bijection in general. But $f(T) = T \oplus (Hash + \mathrm{rotl32}(T) + C)$ for fixed $Hash$?

Actually, let's check: $T \mapsto T \oplus \mathrm{rotl32}(T)$ has collisions. For example, $T = 0$ and $T$ such that $T = \mathrm{rotl32}(T)$ (i.e., $T$ with period dividing 32 in rotation, like $T = 0x0000000100000001$ rotated).

But $Hash$ is **random uniform** and **independent** of $T$ (conditional on $lcg$). So we need to average over $Hash$.

For fixed $lcg$, consider the joint distribution of $(T, Hash)$:
- $T$ is uniform (independent of $lcg$ given $lcg$ is fixed... actually $T$ depends on $lcg$ through $m$, but for fixed $lcg$, $m$ is fixed, so $T = Seed \cdot m$ is uniform in $Seed$)
- $Hash$ is uniform and independent of $Seed$ (hence independent of $T$)

So $(T, Hash)$ are independent uniforms.

Now $Seed' = T \oplus Hash \oplus \mathrm{rotl32}(T) \oplus C$.

For fixed $T$, as $Hash$ varies uniformly, $Seed'$ varies uniformly (XOR with uniform = uniform).

Since this holds for every $T$, and $T$ is uniform, $Seed'$ is uniform. ∎

---

### Lemma 1.2: $lcg'$ is uniform

$lcg' = lcg + Seed_{new} + 0x55...55$ where $Seed_{new} = Seed \cdot (2 \cdot lcg + 1)$

For fixed $Seed$ and $lcg$:
- $Seed_{new}$ is fixed
- $lcg' = lcg + C'$ where $C' = Seed_{new} + 0x55...55$

As $lcg$ varies uniformly (and $Seed$ is independent uniform):
- We need the marginal distribution of $lcg'$

For fixed $Seed$, the map $lcg \mapsto lcg + Seed \cdot (2 \cdot lcg + 1) + 0x55...55 = lcg \cdot (1 + 2 \cdot Seed) + Seed + 0x55...55$

Since $1 + 2 \cdot Seed$ is **odd** for any $Seed$ (because $2 \cdot Seed$ is even, plus 1 is odd), it is a **unit** mod $2^{64}$.

Therefore, for fixed $Seed$, $lcg \mapsto lcg'$ is an **affine bijection** with slope $1 + 2 \cdot Seed$ (odd, hence invertible).

Since $lcg$ is uniform and independent of $Seed$, and for each $Seed$ the map is a bijection, $lcg'$ is uniform. ∎

---

### Lemma 1.3: $Hash'$ is uniform

$Hash' = Hash + rs + 0xAA...AA$ where $rs = \mathrm{rotl32}(Seed \cdot (2 \cdot lcg + 1))$

For fixed $lcg$ and $Seed$:
- $rs$ is fixed
- $Hash' = Hash + C''$ where $C'' = rs + 0xAA...AA$

Since $Hash$ is uniform and independent of $(Seed, lcg)$, and addition of constant is a bijection, $Hash'$ is uniform. ∎

---

### Lemma 1.4: Joint Uniformity

**Theorem:** $(Seed', lcg', Hash')$ is jointly uniform on $(\mathbb{Z}/2^{64}\mathbb{Z})^3$.

**Proof:** The state update is a **bijection** on the 192-bit state space.

To verify: we can invert the function.

Given $(Seed', lcg', Hash')$:
1. Forward:

$$\begin{aligned}
Seed_{new} &= Seed \cdot m \\
rs &= rotl32(Seed_{new}) \\
Hash' &= Hash + rs + C1 \\
lcg' &= lcg + Seed_{new} + C2 \\
Seed' &= Seed_{new} \oplus Hash' \\
out &= lcg' \oplus rs
\end{aligned}$$

2. Backward:

$$\begin{aligned}
Seed_{new} &= Seed' \oplus Hash' \\
rs &= rotl32(Seed_{new}) \\
Hash &= Hash' - rs - 0xAA...AA \\
lcg &= lcg' - Seed_{new} - 0x55...55 \\
Seed &= Seed_{new} \cdot (2 \cdot lcg + 1)^{-1} \mod 2^{64}
\end{aligned}$$

This is a **well-defined function** from $(\mathbb{Z}/2^{64}\mathbb{Z})^3$ to itself.

Since the forward map has an inverse, it is a **bijection**.

**Corollary:** Since the state update is a bijection and the initial state is uniform, all subsequent states are uniform. ∎

---

## Part 2: Proof that `outᵢ(b) ≠ outᵢ₋₁(b)` with Probability 1/2

**Theorem 2:** $\mathbb{P}[\text{out}_i(b) \neq \text{out}_{i-1}(b)] = 1/2$.

**Proof:**

Condition on $(\text{Seed}_{i-1}, \text{lcg}_{i-1})$. This determines:
- $\text{out}_{i-1} = G(\text{Seed}_{i-1}, \text{lcg}_{i-1})$ (deterministically, since $Hash$ doesn't affect $out$)
- $\text{lcg}_i$ (deterministically)
- $\text{Seed}_{new}$ (deterministically)
- $rs$ (deterministically)

Now, $\text{Hash}_{i-1}$ is still **free** (uniform on $[0, 2^{64})$).

$\text{Hash}_i = \text{Hash}_{i-1} + rs + C1$.

As $\text{Hash}_{i-1}$ varies uniformly, $\text{Hash}_i$ varies uniformly.

$\text{Seed}_i = \text{Seed}_{new} \oplus \text{Hash}_i$.

As $\text{Hash}_i$ varies uniformly, $\text{Seed}_i$ varies uniformly (XOR with constant is bijection).

Now, $\text{out}_i = G(S_i) = G(\text{Seed}_i, \text{lcg}_i)$ since $G$ does not depend on $Hash$.

For fixed $(\text{Seed}_{i-1}, \text{lcg}_{i-1})$:
- $\text{lcg}_i$ is fixed
- $\text{Seed}_i$ varies uniformly (as $\text{Hash}_{i-1}$ varies)

So we need: as $\text{Seed}_i$ varies uniformly (with $\text{lcg}_i$ fixed), does $G(\text{Seed}_i, \text{lcg}_i)$ vary uniformly?

$G(\text{Seed}_i, \text{lcg}_i) = (\text{lcg}_i + \text{Seed}_i \cdot (2\cdot\text{lcg}_i+1) + C2) \oplus \text{rotl32}(\text{Seed}_i \cdot (2\cdot\text{lcg}_i+1))$

Let $m = 2\cdot\text{lcg}_i + 1$ (odd, fixed for fixed $\text{lcg}_i$).
Let $T = \text{Seed}_i \cdot m$.

As $\text{Seed}_i$ varies uniformly, $T$ varies uniformly (multiplication by unit is bijection).

$G = (\text{lcg}_i + T + C2) \oplus \text{rotl32}(T)$

For fixed $\text{lcg}_i$, as $T$ varies uniformly, is $f(T) = (a + T) \oplus \text{rotl32}(T)$ uniform?

**Not necessarily uniform as a function of $T$.** But we need each **bit** to be 1/2.

For bit $b$: $f(T)(b) = (a + T)(b) \oplus \text{rotl32}(T)(b) = (a + T)(b) \oplus T((b+32) \mod 64)$

$(a + T)(b)$ is the $b$-th bit of $a + T$ mod $2^{64}$. This is:
$$T(b) \oplus a(b) \oplus \text{carry}_b(a, T)$$

where $\text{carry}_b$ is the carry into bit $b$.

So:
$$f(T)(b) = T(b) \oplus a(b) \oplus \text{carry}_b(a, T) \oplus T((b+32) \mod 64)$$

For $b \neq (b+32) \mod 64$ (i.e., all $b$ since 32 ≠ 0 mod 64), this involves two different bits of $T$ plus a carry term.

As $T$ varies uniformly over $[0, 2^{64})$:
- $T(b)$ and $T((b+32) \mod 64)$ are each 0 or 1 with probability 1/2
- But they are **not independent** (same $T$)
- The carry term $\text{carry}_b(a, T)$ depends on lower bits of $T$

**However:** For the **full** 64-bit $T$ uniform, the bits $(T(0), T(1), ..., T(63))$ are the binary representation. The carry $\text{carry}_b(a, T)$ depends on $T(0), ..., T(b-1)$.

The expression:
$$f(T)(b) = T(b) \oplus T(b+32) \oplus a(b) \oplus \text{carry}_b(a, T)$$

For $b < 32$: $b + 32 < 64$, so $T(b)$ and $T(b+32)$ are distinct bits.

For a **uniform random** $T$, the bits $T(0), ..., T(63)$ are **not independent** (they represent a uniform integer, so each vector of 64 bits appears exactly once — they are independent Bernoulli(1/2) when considered as a random vector).

Actually, for $T$ uniform on $[0, 2^{64})$, the bit vector $(T(0), ..., T(63))$ is **uniform on $\{0,1\}^{64}$** — each of the $2^{64}$ values appears exactly once. So the bits are **independent Bernoulli(1/2)**!

**This is the key!**

For uniform $T$ on $[0, 2^{64})$, the bits are i.i.d. Bernoulli(1/2).

Now, $f(T)(b) = T(b) \oplus T(b+32) \oplus a(b) \oplus \text{carry}_b(a, T)$.

The carry $\text{carry}_b(a, T)$ is a **deterministic Boolean function** of $(T(0), ..., T(b-1))$.

So $f(T)(b)$ is the XOR of:
- $T(b)$ (independent of lower bits)
- $T(b+32)$ (independent of all other bits, including $T(b)$ if $b+32 \neq b$, i.e., always)
- $a(b)$ (constant)
- $\text{carry}_b(a, T)$ (function of lower bits)

Since $T(b)$ is independent of $(T(0), ..., T(b-1), T(b+32), ...)$ and appears **only here**, for any fixed values of all other bits, as $T(b)$ varies:
- $f(T)(b)$ takes values 0 and 1 with equal probability

Therefore, **marginally**, $P[f(T)(b) = 1] = 1/2$.

**But we need more:** We need $P[f(T)(b) = 1 \mid \text{out}_{i-1}(b) = v] = 1/2$.

Recall: $\text{out}_{i-1}$ is determined by $(\text{Seed}_{i-1}, \text{lcg}_{i-1})$ and does **not** depend on $\text{Hash}_{i-1}$.

And $\text{out}_i(b) = f(T)(b)$ where $T = \text{Seed}_i \cdot m$ and $\text{Seed}_i = \text{Seed}_{new} \oplus \text{Hash}_i$.

As $\text{Hash}_{i-1}$ varies, $\text{Hash}_i$ varies uniformly, so $\text{Seed}_i$ varies uniformly, so $T$ varies uniformly.

**Crucially:** $\text{out}_{i-1}$ is **fixed** when we condition on $(\text{Seed}_{i-1}, \text{lcg}_{i-1})$.

So:
$$\mathbb{P}[\text{out}_i(b) = 1 \mid \text{out}_{i-1}(b) = v] = \mathbb{E}_{(\text{Seed}_{i-1}, \text{lcg}_{i-1}) \sim \cdot \mid \text{out}_{i-1}(b)=v} \left[ \mathbb{P}_{\text{Hash}_{i-1}}[\text{out}_i(b) = 1] \right]$$

For each fixed $(\text{Seed}_{i-1}, \text{lcg}_{i-1})$ with $\text{out}_{i-1}(b) = v$:
- The inner probability over $\text{Hash}_{i-1}$ is $1/2$ (shown above)

Therefore:
$$\mathbb{P}[\text{out}_i(b) = 1 \mid \text{out}_{i-1}(b) = v] = 1/2$$

for both $v \in \{0, 1\}$.

This implies:
$$\mathbb{P}[\text{out}_i(b) \neq \text{out}_{i-1}(b)] = \mathbb{P}[\text{out}_i(b) = 1]\mathbb{P}[\text{out}_{i-1}(b) = 0] + \mathbb{P}[\text{out}_i(b) = 0]\mathbb{P}[\text{out}_{i-1}(b) = 1] = \frac{1}{2}\cdot\frac{1}{2} + \frac{1}{2}\cdot\frac{1}{2} = \frac{1}{2}$$

∎

---

## The Critical Role of Hash

The $Hash$ variable is the **secret sauce**:

1. **Current round:** $Hash$ does **not** affect $out$ (output depends only on $Seed$ and $lcg$)
2. **Next round:** $Hash$ enters $Seed' = Seed_new \oplus Hash'$, providing **fresh randomization**
3. **Uniformity:** $Hash$ remains uniform through the update, acting as a **one-time pad** for the next state's $Seed$

This creates a **delayed mixing** effect where the "free" uniform variable $Hash$ ensures that even though consecutive states are deterministically linked, the **output bits** at each step are conditionally independent given the previous output.
