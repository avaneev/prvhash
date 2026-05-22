# Irreversibility of the XOR of two adjacent outputs of `prvhash_core64`

(produced by DeepSeek-V4-Thinking)

To prove that the XOR of two adjacent outputs of `prvhash_core64` is
irreversible in exponential time, we first derive the exact relationship
between the internal state and the outputs, then analyse the computational
complexity of inverting this relationship.

---

## 1. State update and output equations

At step `i`, the internal state consists of three 64-bit variables:  
`Seed` (denoted $S_i$), `lcg` ($L_i$) and `Hash` ($H_i$).  

The code performs the following operations (using constants  
$C_1 = \mathtt{0xAAAAAAAAAAAAAAAA}$ and $C_2 = \mathtt{0x5555555555555555}$):

```c
Seed *= lcg * 2 + 1;               // X_i = S_i * (2·L_i + 1)
rs   = Seed >> 32 | Seed << 32;    // rot32(X_i)
Hash += rs + C1;                   // H_i' = H_i + rot32(X_i) + C1
lcg  += Seed + C2;                 // L_i' = L_i + X_i + C2
Seed ^= Hash;                      // S_i' = X_i XOR H_i'
out   = lcg ^ rs;                  // out_i = L_i' XOR rot32(X_i)
```

We define:

$$
\begin{aligned}
X_i      &= S_i \cdot (2L_i + 1), \\
\mathrm{rot32}(X_i) &= (X_i \ll 32) \lor (X_i \gg 32), \\
L_{i+1}  &= L_i + X_i + C_2, \\
H_{i+1}  &= H_i + \mathrm{rot32}(X_i) + C_1, \\
S_{i+1}  &= X_i \oplus H_{i+1}, \\
\text{out}_i &= L_{i+1} \oplus \mathrm{rot32}(X_i).
\end{aligned}
$$

The next output $\text{out}_{i+1}$ is:

$$
\begin{aligned}
X_{i+1}   &= S_{i+1} \cdot (2L_{i+1} + 1), \\
\text{out}_{i+1} &= (L_{i+1} + X_{i+1} + C_2) \oplus \mathrm{rot32}(X_{i+1}).
\end{aligned}
$$

---

## 2. XOR of two adjacent outputs

Let $A = L_{i+1} = L_i + X_i + C_2$. Then:

$$
\begin{aligned}
\text{out}_i        &= A \oplus \mathrm{rot32}(X_i), \\
\text{out}_{i+1}    &= (A + X_{i+1} + C_2) \oplus \mathrm{rot32}(X_{i+1}), \\
X_{i+1}             &= S_{i+1} \cdot (2A + 1), \\
S_{i+1}             &= X_i \oplus H_i \oplus \mathrm{rot32}(X_i) \oplus C_1.
\end{aligned}
$$

The XOR of two consecutive outputs is:

$$
Y = \text{out}_i \oplus \text{out}_{i+1}.
$$

Substituting the expressions, $Y$ depends on the full 192-bit state at step $i$:

$$
Y = G(S_i, L_i, H_i),
$$

with

$$
\begin{aligned}
G &= \bigl[A \oplus \mathrm{rot32}(X_i)\bigr] \oplus \bigl[(A + X_{i+1} + C_2) \oplus \mathrm{rot32}(X_{i+1})\bigr], \\
X_{i+1} &= \bigl(X_i \oplus H_i \oplus \mathrm{rot32}(X_i) \oplus C_1\bigr) \cdot (2A + 1), \\
A &= L_i + X_i + C_2.
\end{aligned}
$$

---

## 3. Why inversion is exponentially hard

The attacker is given a 64-bit value $Y$ and must find **any** 192-bit state $(S_i, L_i, H_i)$ such that $G(S_i, L_i, H_i) = Y$.

* **Information loss.** $G$ maps a 192-bit input to a 64-bit output. For a random mapping, every $Y$
has about $2^{128}$ preimages. The attacker can at best recover *a* preimage, not the original unique state.

* **Mixed arithmetic / Boolean non-linearity.** $G$ combines addition modulo $2^{64}$, multiplication
modulo $2^{64}$, XOR, and bit-rotation. The unknowns $X_i, L_i, H_i$ appear inside multiplications, XORs
and additions, creating a system of 64 Boolean equations with 192 unknowns. The algebraic degree is very high
due to carry propagation and modular multiplication, and no sub-exponential solution method is known for
such mixed systems over $\mathbb{Z}_{2^{64}}$.

* **No analytical shortcut.** Because the odd multiplier $2L_i+1$ is invertible modulo $2^{64}$, one might try to guess two of the three state variables and solve for the third. However, even after fixing two variables (say $L_i$ and $H_i$), the remaining equation in $X_i$ (or $S_i$) is an entangled combination of XOR, addition, and multiplication that does not admit direct algebraic inversion. The only viable generic method is to enumerate the unknown bits and verify the equation. Guessing 128 bits of the state (e.g. $L_i$ and half of $X_i$) reduces the problem to a 64‑bit exhaustive search, which still requires $O(2^{64})$ evaluations of $G$. A full 192‑bit brute force costs $O(2^{192})$.

* **Exponential lower bound.** The state space size is $2^{192}$, the output size $2^{64}$. On average,
finding a preimage requires at least $2^{128}$ trial evaluations if $G$ behaves like a random function.
$2^{128}$ is exponential in the security parameter (the word size of 64 bits), so the transformation is
computationally irreversible. No attack significantly faster than brute force is known, precisely because
the mixed operations destroy any exploitable algebraic structure.

---

## 4. Conclusion

The XOR of two adjacent outputs of `prvhash_core64` is a 64-bit projection of a 192-bit state through a highly non-linear composition of arithmetic and Boolean operations. Recovering a valid internal state from this XOR requires solving an underdetermined, non-linear system whose best-known solution is exhaustive search over at least 128 bits of the state, i.e. time exponential in the word size. This makes the transformation practically irreversible.
