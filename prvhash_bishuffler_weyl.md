# Analysis of the Bi-Variable Shuffler Generator with Weyl Update

This document presents the formalized state transformation analysis, distribution theorems, and architectural bounds for the "Bi-Variable Shuffler" pseudo-random number generator (PRNG). The generator is modeled as an algebraic state machine, deriving its structural properties directly from its underlying modular update equations.

The state at step $t$ is denoted as a vector $X_t = (S_t, L_t) \in \mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w}$, where $w \ge 1$ represents the word bit-size. Using zero-based indexing, the $i$-th bit of a value $x$ is denoted $x^{[i]}$, and the reduction of $x$ modulo $2^m$ is denoted $[x]_m$. The single-step update equations are defined by the system:

$$S_{t+1} \equiv S_t (2L_t + 1) \pmod{2^w}$$

$$L_{t+1} \equiv L_t + S_{t+1} + C_2 \equiv L_t + S_t(2L_t + 1) + C_2 \pmod{2^w}$$

Where $C_2 = \sum_{i=0}^{\lfloor (w-1)/2 \rfloor} 2^{2i} = \text{0x55}\dots\text{55}$.

---

## 1. Distribution and Input-Output Correlation

Let $\chi_{a,b}(X) = \langle a, S \rangle \oplus \langle b, L \rangle$ be a linear component of the state vector using the Walsh-Hadamard linear masks $(a, b) \in \mathbb{F}_2^w \times \mathbb{F}_2^w$. We distinguish between the marginal distribution at step $t$ and the input-output cross-correlation across multiple steps.

### Theorem 1 (Marginal Uniformity)

Let the initial state $X_0 = (S_0, L_0)$ be sampled from a uniform probability distribution $\mathcal{D}_0 = \mathcal{U}(\mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w})$. For all discrete steps $t \ge 0$, the marginal distribution $\mathcal{D}_t$ remains exactly uniform: $\mathcal{D}_t \equiv \mathcal{U}(\mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w})$. Consequently, the marginal bias vanishes identically:

$$\epsilon_{\mathcal{D}_t}(\chi_{a,b}) = \left|2\mathbb{P}_{X_t \sim \mathcal{D}_t}(\chi_{a,b}(X_t) = 1) - 1\right| = 0 \quad \forall (a,b) \neq (0,0)$$

#### Proof

Let the state transition be $(S', L') = f(S, L)$. From $L' \equiv L + S' + C_2 \pmod{2^w}$, we uniquely recover $L \equiv L' - S' - C_2 \pmod{2^w}$. Substituting this into $S' \equiv S(2L + 1) \pmod{2^w}$ yields $S' \equiv S(2(L' - S' - C_2) + 1) \pmod{2^w}$. Since the multiplier $2(L' - S' - C_2) + 1$ is strictly odd, multiplication by this constant modulo $2^w$ is an invertible linear operation, satisfying $\gcd(2(L' - S' - C_2) + 1, 2^w) = 1$. This uniquely determines $S \equiv S' \cdot (2(L' - S' - C_2) + 1)^{-1} \pmod{2^w}$. Thus $f$ is a bijection on a finite state space, preserving the uniform distribution exactly. $\blacksquare$

### Theorem 2 (Persistent Cross-Correlation)

Let $X_0 \sim \mathcal{U}(\mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w})$ and let $X_t = f^t(X_0)$ be the deterministic state at step $t$. Define the least significant state bits as $s_t = S_t^{[0]}$ and $\ell_t = L_t^{[0]}$. Let $e_0 = (1, 0, 0, \dots, 0) \in \mathbb{F}_2^w$ be the standard basis vector representing the least significant bit position. For a fixed target step $t \ge 0$, choosing the step-dependent initial mask pair $a_0 = (t \bmod 2) \cdot e_0$, $b_0 = e_0$ and the output mask pair $a_t = \vec{0}$, $b_t = e_0$ yields an input-output correlation bias of:

$$\epsilon(t) = \left| \mathbb{E}_{X_0 \sim \mathcal{U}} \left[ (-1)^{\chi_{a_0,b_0}(X_0) \oplus \chi_{a_t,b_t}(X_t)} \right] \right| = 1$$

Notably, because the input masks $a_0, b_0$ depend on the step count $t$, this formulation identifies a time-varying linear correlation rather than a static linear correlation weakness.

#### Proof

Modulo 2, since $C_2 \equiv 1 \pmod 2$, the update equations project to $s_t = s_0$ and $\ell_t = \ell_0 \oplus (t \bmod 2)(s_0 \oplus 1)$. Because the masks $a_0, b_0, a_t, b_t$ isolate the least significant bits, and the T-function structure ensures the projection of the state onto these bits is closed under the update modulo 2, the expectation is determined entirely by the 0-th bit dynamics and is unaffected by higher bits. The masked inner products collapse to their 0-th bit components: $\langle a_0, S_0 \rangle = (t \bmod 2)s_0$, $\langle b_0, L_0 \rangle = \ell_0$, $\langle a_t, S_t \rangle = 0$, $\langle b_t, L_t \rangle = \ell_t$. The joint linear component evaluates to:

$$\chi_{a_0,b_0}(X_0) \oplus \chi_{a_t,b_t}(X_t) = (t \bmod 2)s_0 \oplus \ell_0 \oplus \ell_t$$

Substituting the identity for $\ell_t$:

$$(t \bmod 2)s_0 \oplus \ell_0 \oplus \ell_0 \oplus (t \bmod 2)(s_0 \oplus 1) \equiv (t \bmod 2)(s_0 \oplus s_0 \oplus 1) \equiv t \bmod 2 \pmod 2$$

This deterministic evaluation for all initial states simplifies the expectation to $\epsilon(t) = \left| \mathbb{E}_{X_0 \sim \mathcal{U}} \left[ (-1)^{t \bmod 2} \right] \right| = 1$. $\blacksquare$

---

## 2. Cycle Structure and Period Bounds

### Monotonicity of T-Function Projections

Let $\pi_m: \mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w} \to \mathbb{Z}_{2^m} \times \mathbb{Z}_{2^m}$ be the canonical projection mapping a state to its lower $m$ bits. The state update equations are T-functions, meaning $\pi_m(f(X)) = f_m(\pi_m(X))$, where $f_m$ is the state update restricted to $\mathbb{Z}_{2^m} \times \mathbb{Z}_{2^m}$. This implies T-function monotonicity: if a state has period $\tau_w$ modulo $2^w$, its projection modulo $2^m$ has period $\tau_m$ dividing $\tau_w$. For any $1 \le m \le w$, the period of the $(m-1)$-bit projection $\tau_{m-1}$ must divide the $m$-bit period $\tau_m$.

---

### Lemma 1 (Maximum Sub-Space Period Bounds)

Let $X_{t, m} = ([S_t]_m, [L_t]_m) \in \mathbb{Z}_{2^m} \times \mathbb{Z}_{2^m}$ represent the state vector restricted to its lower $m$ bits. For any initial state, the exact period $\tau_m$ satisfies $\tau_m = 2^j$ for some $j \le m$.

#### Proof

**Proof** by induction on $m$.

1. **Base Case ($m=1$):** Modulo 2, $S_{t+1} \equiv S_t$ and $L_{t+1} \equiv L_t + S_t + 1$. If $S_0 = 0$, $L_{t+1} \equiv L_t + 1 \pmod 2$, yielding $\tau_1 = 2 = 2^1$. If $S_0 = 1$, $L_{t+1} \equiv L_t \pmod 2$, yielding $\tau_1 = 1 = 2^0$.

2. **Inductive Step:** Assume $\tau_{m-1} = 2^j$ where $j \le m-1$. Analyzing the bit layer $i = m-1$, $X_t^{[i]} = (S_t^{[i]}, L_t^{[i]})$ updates via an affine system $X_{t+1}^{[i]} = B X_t^{[i]} \oplus \vec{C}(t)$ where $B = \begin{pmatrix} 1 & 0 \\ 1 & 1 \end{pmatrix}$ and $\vec{C}(t)$ is determined by lower-bit carries. Unrolling over $\tau_{m-1}$ steps gives $X_{t+\tau_{m-1}}^{[i]} = B^{\tau_{m-1}} X_t^{[i]} \oplus \vec{\Delta}(t)$. 
   - **Case 1: $\tau_{m-1} = 2^j$ is even ($j \ge 1$)**. Since $B^2 \equiv I \pmod 2$, $B^{\tau_{m-1}} \equiv I \pmod 2$. The map simplifies to $X_{t+\tau_{m-1}}^{[i]} = X_t^{[i]} \oplus \vec{\Delta}(t)$. Because the state at layer $i$ updates via an affine transformation driven by the lower $m-1$ bits, the carry vector $\vec{C}(t)$ strictly inherits the periodicity of the lower-bit projection. Consequently, the accumulated top-bit shift $\vec{\Delta}(t)$ over one lower-bit period $\tau_{m-1}$ is periodic. Applying this twice sums the shift over two consecutive lower-bit periods. Since the lower-bit state returns to its initial value after $\tau_{m-1}$ steps, the shift $\vec{\Delta}(t+\tau_{m-1})$ equals $\vec{\Delta}(t)$, causing them to cancel modulo 2: $X_{t+2\tau_{m-1}}^{[i]} = X_t^{[i]} \oplus \vec{\Delta}(t) \oplus \vec{\Delta}(t+\tau_{m-1}) = X_t^{[i]}$. By T-function monotonicity, $\tau_m$ is a multiple of $\tau_{m-1}$ and divides $2\tau_{m-1}$. Hence $\tau_m \in \{\tau_{m-1}, 2\tau_{m-1}\}$, which are powers of two.
   - **Case 2: $\tau_{m-1} = 1$ ($j = 0$)**. The state modulo $2^{m-1}$ is a fixed point: $S_t \equiv \sigma_0$ and $L_t \equiv l_0$ modulo $2^{m-1}$. From the updates, $\sigma_0 \equiv -C_2 \pmod{2^{m-1}}$ and $l_0 \equiv 0 \pmod{2^{m-2}}$. Let $l_0 = 2^{m-2} l'_0$ and decompose $S_t = \sigma_0 + s_t 2^{m-1}$, $L_t = l_0 + l_t 2^{m-1}$. The top bit pair $X_t^{[m-1]} = (s_t, l_t)$ updates as $X_{t+1}^{[m-1]} = B X_t^{[m-1]} \oplus \vec{C}$ where $\vec{C} = (l'_0, l'_0 \oplus q)^T$ and $q = (\sigma_0 + C_2)/2^{m-1}$. Applying the map twice yields $X_{t+2}^{[m-1]} = B^2 X_t^{[m-1]} \oplus B \vec{C} \oplus \vec{C} \equiv X_t^{[m-1]} \oplus (B \oplus I) \vec{C} \pmod 2$. Evaluating $(B \oplus I) \vec{C} = \begin{pmatrix} 0 & 0 \\ 1 & 0 \end{pmatrix} \begin{pmatrix} l'_0 \\ l'_0 \oplus q \end{pmatrix} = \begin{pmatrix} 0 \\ l'_0 \end{pmatrix}$ yields $X_{t+2}^{[m-1]} = X_t^{[m-1]} \oplus (0, l'_0)^T$. If $l'_0 = 0$, the period is at most 2. If $l'_0 = 1$, a non-zero shift over two steps rules out period 2, and applying it four times yields $X_t^{[m-1]}$. The period is at most 4.
   In both cases, $\tau_m$ is a power of two bounded by $2^m$. $\blacksquare$

---

### Lemma 2 (Zero-Seed Period Maximality)

Let $S_0 = 0$. The exact period of the system modulo $2^m$ is $\tau_m = 2^m$ for all $m \ge 1$.

#### Proof

If $S_0 = 0$, $S_t = 0$ for all $t$, reducing the $L$ update to $L_{t+1} \equiv L_t + C_2 \pmod{2^m}$. Since $\gcd(C_2, 2^m) = 1$, this linear congruential generator has maximal period $\tau_m = 2^m$. $\blacksquare$

---

### Lemma 3a (Period-Doubling Lifting)

Let $(S'_t, L'_t)$ be a T-function system of integer sequences representing the unique lifts of the states modulo $2^{m+1}$ with update $S'_{t+1} = S'_t M_t$, $L'_{t+1} = L'_t + S'_{t+1}$, where all $M_t$ are odd. The congruences are evaluated modulo the specified powers of 2. Suppose:

1. The minimal period modulo $2^m$ is $p$ (a power of 2).
2. The multipliers satisfy $M_{t+p} \equiv M_t(1 + K_t \cdot 2^{m+1}) \pmod{2^{m+2}}$ for all $t$, where $K_t$ are odd integers. (Such $K_t$ exist because $M_t$ and $M_{t+p}$ are odd, making $M_{t+p}M_t^{-1} \equiv 1 \pmod{2^{m+1}}$; the quotient $K_t = (M_{t+p}M_t^{-1} - 1)/2^{m+1} \pmod 2$ is thus well-defined and odd.)
3. $p = 2^m$.
4. $S'_p \equiv S'_0(1 + \alpha 2^m) \pmod{2^{m+1}}$ and $L'_p \equiv L'_0 + \beta 2^m \pmod{2^{m+1}}$.
5. $m \ge 2$.
6. $S'_0$ is odd.

Then:

- $S'_{2p} \equiv S'_0(1 + \alpha 2^{m+1}) \pmod{2^{m+2}}$.
- $L'_{2p} \equiv L'_0 + \beta 2^{m+1} \pmod{2^{m+2}}$.
- If at least one of $\alpha, \beta$ is odd, the minimal period modulo $2^{m+1}$ is exactly $2p$.

#### Proof

Since $p = 2^m$ and $m \ge 2$, $p$ is a multiple of 4. Write $S'_p = S'_0(1 + \alpha 2^m + \gamma 2^{m+1})$. By hypothesis (2), expanding the product $\prod_{i=0}^{j-1} M_{p+i}$ modulo $2^{m+2}$, the first-order cross-terms yield $\prod_{i=0}^{j-1} M_{p+i} \equiv \prod_{i=0}^{j-1} M_i (1 + (\sum_{i=0}^{j-1} K_i) \cdot 2^{m+1}) \pmod{2^{m+2}}$. Thus:
$$S'_{p+j} \equiv S'_j(1 + \alpha 2^m + \gamma 2^{m+1})(1 + (\sum_{i=0}^{j-1} K_i) \cdot 2^{m+1}) \pmod{2^{m+2}}$$
For $j=p$, since each $K_i$ is odd, $\sum_{i=0}^{p-1} K_i \equiv p \pmod 2$. Because $p = 2^m$ with $m \ge 2$, $p \equiv 0 \pmod 2$, so $(\sum_{i=0}^{p-1} K_i) \cdot 2^{m+1} \equiv 0 \pmod{2^{m+2}}$. Therefore $S'_{2p} \equiv S'_0(1 + \alpha 2^m + \gamma 2^{m+1})^2 \pmod{2^{m+2}}$. Since $2m \ge m+2$ for $m \ge 2$, higher-order terms vanish, yielding $S'_{2p} \equiv S'_0(1 + \alpha 2^{m+1}) \pmod{2^{m+2}}$.

For $L'$, let $\Sigma = L'_p - L'_0 = \sum_{j=1}^{p} S'_j \equiv \beta 2^m \pmod{2^{m+1}}$. Expanding the product relation for $S'_{p+j}$ and summing over $j \in [1, p]$ yields:
$$L'_{2p} - L'_0 \equiv 2\Sigma + \Sigma(\alpha 2^m + \gamma 2^{m+1}) + 2^{m+1} \sum_{j=1}^p S'_j \sum_{i=0}^{j-1} K_i \pmod{2^{m+2}}$$
Writing $\Sigma = \beta 2^m + \delta 2^{m+1}$, we have $2\Sigma \equiv \beta 2^{m+1} \pmod{2^{m+2}}$. Since $2m \ge m+2$ for $m \ge 2$, $\Sigma(\alpha 2^m + \gamma 2^{m+1}) \equiv 0 \pmod{2^{m+2}}$. Because $M_t$ are odd, their lifts $S'_j$ are odd, satisfying $S'_j \equiv 1 \pmod 2$. Since each $K_i$ is odd, $\sum_{i=0}^{j-1} K_i \equiv j \pmod 2$. The double sum modulo 2 evaluates to $\sum_{j=1}^p S'_j \sum_{i=0}^{j-1} K_i \equiv \sum_{j=1}^p j = \frac{p(p+1)}{2} \pmod 2$. Because $p = 2^m$ with $m \ge 2$, $p \equiv 0 \pmod 4$, making $\frac{p(p+1)}{2} \equiv 0 \pmod 2$. Thus the double sum term vanishes modulo $2^{m+2}$, leaving $L'_{2p} - L'_0 \equiv \beta 2^{m+1} \pmod{2^{m+2}}$.

If at least one of $\alpha, \beta$ is odd, $(S'_p, L'_p) \not\equiv (S'_0, L'_0) \pmod{2^{m+1}}$, excluding period $p$. By T-function monotonicity, the period modulo $2^{m+1}$ divides $2p$ and is a multiple of $p$, hence it is exactly $2p$. $\blacksquare$

---

### Lemma 3 (Scaled System Period Growth)

Let $S_0 = 2^k u$ with $u$ odd, $k \ge 1$, and let $S_t = 2^k S'_t \pmod{2^w}$ and $L_t = L_0 + t C_2 + 2^k L'_t \pmod{2^w}$ define the integer quotients $S'_t, L'_t \in \mathbb{Z}_{2^{w-k}}$. The sequences $S'_t, L'_t$ are well-defined as the unique integer lifts of the full-width recurrence modulo $2^{w-k}$. Let the scaled system modulo $2^m$ ($1 \le m \le w-k$) be defined by the state $(S'_t, L'_t)$ with initial state $(u, 0)$ and update rules:

$$S'_{t+1} \equiv S'_t M_t \pmod{2^m}, \quad L'_{t+1} \equiv L'_t + S'_{t+1} \pmod{2^m}$$

where $M_t = 2^{k+1} L'_t + 2L_0 + 2tC_2 + 1$. The exact period $\tau'_m$ of this scaled system is $2^m$ for all $m \ge 2$, and $\tau'_1 = 2$. The full system period $\tau_w$ is exactly $2^w$.

#### Proof

**Base Case ($m=1$).** $S'_0 = u \equiv 1 \pmod{2}$ implies $S'_t \equiv 1 \pmod{2}$ and $M_t \equiv 1 \pmod{2}$. Thus $L'_{t+1} \equiv L'_t + 1 \pmod{2}$ has period 2, so $\tau'_1 = 2$.

**Base Case ($m=2$).** Since $k \ge 1$, $2^{k+1} \equiv 0 \pmod 4$. Modulo 4, $M_t \equiv 2L_0 + 2t + 1 \pmod 4$, giving $M_0 M_1 \equiv 3 \pmod 4$. Thus $S'_2 \not\equiv S'_0 \pmod 4$, ruling out periods 1 and 2. 

Modulo 8, we analyze $M_t \pmod 8$. Since $C_2 = \text{0x55}\dots\text{55}$, for $w \ge 3$ we have $C_2 \equiv 5 \pmod 8$, and thus $2tC_2 \equiv 10t \equiv 2t \pmod 8$. For $k \ge 2$, $2^{k+1} \equiv 0 \pmod 8$, so $M_t \equiv 2L_0 + 2tC_2 + 1 \equiv 2L_0 + 2t + 1 \pmod 8$. As $t$ ranges over $0,1,2,3$, this yields the sequence $2L_0 + 1, 2L_0 + 3, 2L_0 + 5, 2L_0 + 7 \pmod 8$, which is a permutation of $\{1, 3, 5, 7\}$. For $k = 1$, $M_t \equiv 4(L'_t \bmod 2) + 2L_0 + 2tC_2 + 1 \pmod 8$. Since $L'_0 = 0$ and $S'_t \equiv 1 \pmod 2$ implies $L'_{t+1} \equiv L'_t + 1 \pmod 2$, we have $L'_t \equiv t \pmod 2$. Thus $M_t \equiv 4t + 2L_0 + 2tC_2 + 1 \equiv 4t + 2L_0 + 2t + 1 \equiv 6t + 2L_0 + 1 \pmod 8$. For $t = 0,1,2,3$, this yields $2L_0 + 1, 2L_0 + 7, 2L_0 + 5, 2L_0 + 3 \pmod 8$, again a permutation of $\{1, 3, 5, 7\}$.

Since the product of all elements in $\{1, 3, 5, 7\}$ is $1 \cdot 3 \cdot 5 \cdot 7 = 105 \equiv 1 \pmod 8$, we have $S'_4 \equiv u \cdot 1 \equiv u \pmod 8$, yielding $\alpha = 0$. The partial products modulo 8 sum to $12u \equiv 4u \pmod 8$. Thus $\beta = 1$ and $\tau'_2 = 4$.

**Inductive step ($m \to m+1$ for $m \ge 2$):** Assume $\tau'_m = 2^m$, $S'_{2^m} \equiv S'_0 \pmod{2^{m+1}}$ ($\alpha=0$), and $L'_{2^m} \equiv L'_0 + 2^m \pmod{2^{m+1}}$ ($\beta=1$). We invoke Lemma 3a with $p = 2^m$.
- **(i) Multiplier periodicity:** $M_{t+2^m} - M_t = 2^{k+1}(L'_{t+2^m} - L'_t) + 2^{m+1} C_2$. By hypothesis, $L'_{t+2^m} \equiv L'_t \pmod{2^m}$. Since $k \ge 1$, $k+m+1 \ge m+2$, so the $2^{k+1}$ term vanishes modulo $2^{m+2}$. Thus $M_{t+2^m} \equiv M_t + 2^{m+1} C_2 \pmod{2^{m+2}}$. Letting $K_t \equiv C_2 \cdot M_t^{-1} \pmod 2$ (which is well-defined and odd since both $C_2$ and $M_t$ are odd), we have $M_{t+2^m} \equiv M_t(1 + K_t \cdot 2^{m+1}) \pmod{2^{m+2}}$. This verifies Hypotheses (2) and (3) of Lemma 3a.
- **(ii) Lemma 3a invocation:** The induction hypothesis provides Hypothesis (4). For $m \ge 2$, Hypothesis (5) holds. Since $u$ is odd, Hypothesis (6) holds. Because $\beta = 1$ is odd, Lemma 3a yields $\tau'_{m+1} = 2^{m+1}$.

Since the scaled system has exact period $2^{w-k}$, $L'_{2^{w-1}} \equiv 0 \pmod{2^{w-k}}$ for $k \ge 1$. The full state update yields $L_{2^{w-1}} \equiv L_0 + 2^{w-1} C_2 \pmod{2^w}$. Because $C_2$ is odd, $L_{2^{w-1}} \not\equiv L_0 \pmod{2^w}$, so the full system period does not divide $2^{w-1}$. By Lemma 1, the period is exactly $2^w$. $\blacksquare$

---

### Theorem 3 (Cycle Bounds and Maximality Condition)

Let $\mathcal{O}$ be an orbit of the generator under the full word width transition $f: \mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w} \to \mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w}$. The exact period $\tau_w$ satisfies:

1. If $S_0 = 0$, then $\tau_w = 2^w$.
2. If $S_0 \equiv 1 \pmod 2$, then $\tau_1 = 1$. The period doubling fails at $m=2$ for states with $S_0 \equiv 1 \pmod 2$ and $L_0$ even. For these states, $L_t$ remains even for all $t$, and if $S_0 \equiv 3 \pmod 4$, then $S_{t+1} + C_2 \equiv 0 \pmod 4$ yielding fixed points of the state vector modulo 4; otherwise the orbit has period 2 modulo 4. The exact period does not universally reach $2^w$.
3. If $S_0 \neq 0$ and $\nu_2(S_0) = k \ge 1$, let $S_0 = 2^k u$ with $u$ odd. The period is exactly $2^w$.

#### Proof

1. If $S_0 = 0$, $S_t = 0$ for all $t$, reducing the update to $L_{t+1} \equiv L_t + C_2 \pmod{2^w}$. Since $\gcd(C_2, 2^w) = 1$, $L_t$ is a Weyl sequence with exact period $2^w$.
2. If $S_0 \equiv 1 \pmod 2$, $\tau_1 = 1$ by Lemma 1. Modulo 4 with $C_2 \equiv 1 \pmod 4$, if $L_0$ is odd, $S_{t+1} \equiv 3S_t \pmod 4$ and $L$ increments alternate between $0$ and $2 \pmod 4$, yielding maximal period 4. If $L_0$ is even, $S_t$ is constant modulo 4 and $L_{t+1} \equiv L_t + S_0 + 1 \pmod 4$. If $S_0 \equiv 1 \pmod 4$, this yields a period-2 orbit. If $S_0 \equiv 3 \pmod 4$, it yields fixed points modulo 4. The exact period does not universally reach $2^w$.
3. If $S_0 = 2^k u$ with $k \ge 1$, $[S_t]_k = 0$ and $[L_{t+1}]_k \equiv [L_t]_k + C_2 \pmod{2^k}$. Because $C_2$ is odd, $[L_t]_k$ has exact period $2^k$. Factoring out $2^k$ from higher-order bits maps the dynamics to the scaled system of Lemma 3, which has period $2^{w-k}$. Combined with the lower-$k$ bit period $2^k$, the full system period is exactly $2^w$. $\blacksquare$

---

### State-Space Volume Consistency

This calculation verifies that the case split by initial-state type in Theorem 3 partitions the full state space. For a fixed valuation $k = \nu_2(S_0) \ge 1$, there are $2^{w-k-1}$ possible values of $S_0$ and $2^w$ possible values of $L_0$. Summing the states for a fixed $k$ yields:

$$\text{States}(k) = 2^{w-k-1} \times 2^w = 2^{2w-k-1}$$

Summing over all possible valuations $k$ from $1$ to $w-1$, plus the $2^w$ states where $S_0 = 0$ and the $2^{2w-1}$ states where $S_0$ is odd:

$$\Sigma = 2^w + \left( \sum_{k=1}^{w-1} 2^{2w-k-1} \right) + 2^{2w-1} = 2^w + (2^{2w-1} - 2^w) + 2^{2w-1} = 2^{2w-1} + 2^{2w-1} = 2^{2w}$$

The total count matches $|\mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w}| = 2^{2w}$, confirming that the cycle classification partitions the state space.

---

### Corollary 1 (LSB Orbit Partition)

For $m=1$, the state space $\mathbb{Z}_2^2$ is partitioned into exactly one cycle of length 2 where $\tau = 2$, and two cycles of length 1 where $\tau = 1$.

#### Proof

This follows as a direct application of Theorem 3. If $S_0 = 0$, the update is $L_{t+1} \equiv L_t + 1 \pmod 2$. This forms a single 2-cycle containing states $(0,0)$ and $(0,1)$, yielding $\tau_1 = 2$. If $S_0 \equiv 1 \pmod 2$, the update is $L_{t+1} \equiv L_t \pmod 2$. This yields two fixed points corresponding to $L_0 \in \{0, 1\}$ with $\tau_1 = 1$. $\blacksquare$

---

### Corollary 2 (Extension to $m=2$)

For $m=2$, the state space $\mathbb{Z}_4^2$ consists of two cycles of length 1, one cycle of length 2, and three cycles of length 4.

#### Proof

This is a direct consequence of the dynamics for $w=2$ with $C_2 \equiv 1 \pmod 4$:

1. For $S_0 = 0$, the sequence $L_{t+1} \equiv L_t + 1 \pmod 4$ has period 4, forming one 4-cycle: $\{(0,0), (0,1), (0,2), (0,3)\}$.
2. For $S_0 = 2$, the orbit traces $(2,0) \to (2,3) \to (2,2) \to (2,1) \to (2,0)$, forming one 4-cycle.
3. For $S_0$ odd ($S_0 \in \{1, 3\}$):
   - States $(3,0)$ and $(3,2)$ are fixed points (period 1).
   - States $(1,0)$ and $(1,2)$ form a 2-cycle: $(1,0) \to (1,2) \to (1,0)$.
   - States $(1,1), (3,1), (1,3), (3,3)$ form a 4-cycle: $(1,1) \to (3,1) \to (1,3) \to (3,3) \to (1,1)$.

Summing these gives 2 cycles of length 1, 1 cycle of length 2, and 3 cycles of length 4, exhausting the 16 states. $\blacksquare$

---

## 3. Low-Order Projection and Two-Sample Correlation Analysis

For an initial state with $S_0 \neq 0$ and $\nu_2(S_0) = v \ge 1$, let $s_t = S_t^{[v+1]}$ and $\ell_t = L_t^{[v+1]}$ denote the bits of the period-4 orbit projection modulo $2^{v+2}$. The following quantities are averages over the full orbit:

### Theorem 4

1. The 1-step autocorrelation of the state bit $S_t^{[v+1]}$ averaged over the 4-step period of the projected state orbit is:
   $$\epsilon_S(v+1, 1) = 0 \quad \text{for } v \ge 1$$
2. The state bit $L_t^{[v+1]}$ over the full orbit modulo $2^{v+2}$ is perfectly balanced:
   $$\mathbb{P}(L_t^{[v+1]} = 0) = \mathbb{P}(L_t^{[v+1]} = 1) = \frac{1}{2} \quad \text{for } v \ge 1$$
3. The parity balance over the period-4 orbit of $S_t^{[v+1]}$ satisfies:
   $$\sum_{t=0}^3 (-1)^{S_t^{[v+1]}} = 0$$

#### Proof

Since $\nu_2(S_0) = v \ge 1$, $S_t \equiv 2^v(2s_t+1) \pmod{2^{v+2}}$. Dividing $S_{t+1} \equiv S_t(2L_t+1) \pmod{2^{v+2}}$ by $2^v$ yields $2s_{t+1}+1 \equiv (2s_t+1)(2L_t+1) \pmod 4$. Since $v \ge 1$, $L_{t+1} \equiv L_t + 1 \pmod 2$, so $2L_t+1 \equiv 2(L_0^{[0]} \oplus t)+1 \pmod 4$. This implies $s_{t+1} = s_t \oplus L_0^{[0]} \oplus t$, generating a period-4 orbit. The step differences over this 4-cycle are $L_0^{[0]}, L_0^{[0]} \oplus 1, L_0^{[0]}, L_0^{[0]} \oplus 1$. The 1-step autocorrelation is $\epsilon_S = \frac{1}{4} \sum_{t=0}^3 (-1)^{s_{t+1} \oplus s_t} = \frac{1}{4} \left( 2(-1)^{L_0^{[0]}} + 2(-1)^{L_0^{[0]} \oplus 1} \right) = 0$. The parity sum is zero because the orbit contains exactly two instances of $s_0$ and two of $s_0 \oplus 1$.

For $L_t^{[v+1]}$, let $K_t = S_{t+1} + C_2$. The increment over $2^{v+1}$ steps is $L_{t+2^{v+1}} - L_t \equiv \sum_{j=1}^{2^{v+1}} K_j \pmod{2^{v+2}}$. Since $S_{t+1}$ has period 4 and $2^{v+1}$ is a multiple of 4, the sum is independent of $t$. With $S_{t+1} \equiv 2^v u_t \pmod{2^{v+2}}$ and $u_t$ odd, $\sum K_j \equiv 2^v \sum u_j + 2^{v+1} C_2 \pmod{2^{v+2}}$. Since $S_t^{[v+1]}$ is balanced over its period-4 orbit, $u_t \pmod 4 = 1 + 2S_t^{[v+1]}$ sums to $8$ per cycle, giving $\sum u_j = 2^{v+2}$. The increment becomes $2^{v+1} C_2 \equiv 2^{v+1} \pmod{2^{v+2}}$ (since $C_2$ is odd). Thus $L_{t+2^{v+1}} \equiv L_t + 2^{v+1} \pmod{2^{v+2}}$, flipping bit $v+1$ in the second half of the period. The occurrences of $0$ and $1$ for $L_t^{[v+1]}$ are symmetrized, making the bit perfectly balanced over the full period $2^{v+2}$. $\blacksquare$

---

## 4. Carry Propagation and Triangular Dynamics

The update equations of the generator form a T-function system. The state mapping is strictly triangular: bit $i$ of the next state vector $(S_{t+1}, L_{t+1})$ depends exclusively on the lower input state bits at positions $0, \dots, i$ of $(S_t, L_t)$. Consequently, high-order bit components cannot influence lower-order bit positions within a single step.

Conversely, low-to-high influence can propagate across intermediate bit positions within a single step through multiplication and addition carry chains. For example, when $L_t = 2^w - 1$, changing $S_t$ from $0$ to $1$ modifies the next state coordinate from $S_{t+1} = 0$ to $S_{t+1} = 1 \cdot (2(2^w - 1) + 1) \equiv -1 \pmod{2^w}$, flipping all higher bits in a single execution step. This indicates that while a change in $S_t$ can immediately propagate carries through the multiplication to all higher bits of $S_{t+1}$, the propagation of these carries to $L_{t+1}$ is mediated by the addition carry chain of $L_t + C_2$. The structural diffusion limitations of the generator are therefore defined by the linear correlations and subspace period bounds induced by its triangular T-function structure, rather than a sequential avalanche bit-delay bound.

---

## 5. Cross-Correlations

### Theorem 5 (Trajectory Bit-Layer Asymptotic Cross-Correlations)

Let $X_t = (S_t, L_t)$ be the state at step $t$ over word bit-size $w \ge 2$. Define the asymptotic time-averaged cross-correlation at bit position $i \ge 1$ as:

$$\rho_i = \lim_{T \to \infty} \frac{1}{T} \sum_{t=0}^{T-1} (-1)^{S_t^{[i]} \oplus L_t^{[i]}}$$

For an arbitrary initial state $X_0 = (S_0, L_0)$, the value of $\rho_i$ is determined for the stationary and dyadic regimes, and partially characterized for the odd-seed regime, as follows:

1. Stationary Regime ($S_0 = 0$)

  $$\rho_i = 0 \quad \text{for } 1 \le i < w$$

2. Odd-Seed Regime ($S_0 \equiv 1 \pmod 2$)

**(a) Base layer ($i = 1$):**
The exact value of $\rho_1$ depends on the period of the orbit modulo 4. If the orbit achieves the maximal period of 4, the bits $S_t^{[1]}$ and $L_t^{[1]}$ are balanced over the cycle, yielding $\rho_1 = 0$. For period-2 orbits, $\rho_1 = 0$. For fixed points (period 1), $\rho_1 = (-1)^{S_0^{[1]} \oplus L_0^{[1]}}$.

**(b) Higher layers ($i \ge 2$):** Let $H = 2^i$. By T-function monotonicity, the period modulo $2^{i+1}$ is bounded. The average $\rho_i$ does not vanish identically for all initial states.

---

#### 3. Dyadic Regime ($\nu_2(S_0) = v \ge 1$)

For all bit layers $i \le v$, the exact value is:

| Layer | Formula |
|-------|---------|
| **$i < v$** | $\rho_i = 0$ |
| **$i = v$** | $\rho_v = 0$ |

For layers $i \ge v+1$, the correlation $\rho_i$ is governed by the scaled-system orbit at bit $i-v$ and does not admit a simple closed form without explicit enumeration.

---

#### Proof

Because the state space is finite, every trajectory enters a cycle. By T-function monotonicity, $\rho_i$ equals the average over one period of the orbit projected modulo $2^{i+1}$.

1. **Stationary Regime ($S_0 = 0$)**. By Theorem 3, $\tau_w = 2^w$. $S_t = 0$ and $L_t = L_0 + t C_2 \pmod{2^w}$. Because $C_2$ is odd, $t C_2$ toggles bits identically to $t$. Averaging over $2^w$, $L_t^{[i]}$ evaluates equally to 0 and 1, yielding $\rho_i = 0$.

2. **Base Odd Layer ($i=1$, $S_0$ odd)**. Modulo 4, write $S_t = 2s_t + 1$ and $L_t = 2\ell_t + y_t$ with $y_t = L_t^{[0]}$. The updates are $s_{t+1} = s_t \oplus y_t$, $y_{t+1} = y_t$, $\ell_{t+1} = \ell_t \oplus s_{t+1} \oplus 1$. 
If $L_0$ is odd ($y_0 = 1$), maximal period 4 is achieved. Unrolling over the 4-step period:

| $t$ | $s_t$ | $\ell_t$ | $y_t$ | $\Phi_t = s_t \oplus \ell_t$ |
|-----|-------|----------|-------|------------------------------|
| 0 | $s_0$ | $\ell_0$ | $1$ | $s_0 \oplus \ell_0$ |
| 1 | $s_0 \oplus 1$ | $\ell_0 \oplus s_0$ | $1$ | $\ell_0 \oplus 1$ |
| 2 | $s_0$ | $\ell_0 \oplus 1$ | $1$ | $s_0 \oplus \ell_0 \oplus 1$ |
| 3 | $s_0 \oplus 1$ | $\ell_0 \oplus s_0 \oplus 1$ | $1$ | $\ell_0$ |

The sum is $(-1)^{s_0 \oplus \ell_0} + (-1)^{\ell_0 \oplus 1} + (-1)^{s_0 \oplus \ell_0 \oplus 1} + (-1)^{\ell_0} = 0$.
If $L_0$ is even ($y_0 = 0$), $s_t = s_0$ is constant. If the orbit is a fixed point, $\rho_1 = (-1)^{s_0 \oplus \ell_0}$. If the orbit has period 2, $\ell_{t+1} = \ell_t \oplus 1$, giving a sum of $(-1)^{s_0 \oplus \ell_0} + (-1)^{s_0 \oplus \ell_0 \oplus 1} = 0$.
Thus:
$$\rho_1 = \begin{cases} 0 & \text{if period } \ge 2 \\ (-1)^{S_0^{[1]} \oplus L_0^{[1]}} & \text{if period } = 1 \end{cases}$$

3. **Higher Odd Layers ($i \ge 2$, $S_0$ odd)**. The period modulo $2^{i+1}$ is bounded by $2^i$. For $(S_0, L_0) = (3, 0)$ modulo 8, the state forms a fixed point, yielding $\rho_2 = (-1)^{S_0^{[2]} \oplus L_0^{[2]}} \neq 0$. Thus, $\rho_i$ does not vanish identically.

4. **Dyadic Regime ($\nu_2(S_0) = v \ge 1$)**. Write $S_0 = 2^v u$ with $u$ odd. Bits $0, \dots, v-1$ of $S_t$ are zero, and bit $v$ is 1.
**Layer $i < v$.** $L_{t+1} \equiv L_t + C_2 \pmod{2^v}$ forms a strict Weyl sequence. $L_t^{[i]}$ is uniformly distributed over the full period $2^v$. With $S_t^{[i]} = 0$, $\rho_i = 0$.
**Layer $i = v$.** Modulo $2^{v+1}$, $L_{t+1} \equiv L_t + 2^v + C_2 \pmod{2^{v+1}}$. Over $2^v$ iterations, the sum of steps is $2^v(2^v + C_2) \equiv 2^v C_2 \equiv 2^v \pmod{2^{v+1}}$ (since $C_2$ is odd). The period is exactly $2^{v+1}$, making $L_t \pmod{2^{v+1}}$ a permutation of $\mathbb{Z}_{2^{v+1}}$. With $S_t^{[v]} = 1$:
$$\rho_v = \frac{1}{\tau} \sum_{t=0}^{\tau-1} (-1)^{1 \oplus L_t^{[v]}} = -\frac{1}{\tau} \sum_{t=0}^{\tau-1} (-1)^{L_t^{[v]}} = 0 \quad \blacksquare$$

---

## 6. Non-Homogenous Weyl Sequence Decomposition

### Theorem 6 (Weyl Sequence Perturbation)

Given an initial state $X_0 \sim \mathcal{U}(\mathbb{Z}_{2^w} \times \mathbb{Z}_{2^w})$, the sequence $L_t$ represents a non-homogenous Weyl sequence perturbed by deterministic noise.

#### Proof

By unrolling the update for $L$ over $t$ steps:
$$L_t \equiv L_0 + t C_2 + \sum_{j=1}^t S_j \pmod{2^w}$$
Let $W_t = L_0 + t C_2 \pmod{2^w}$ be the non-homogenous Weyl sequence, and $N_t = \sum_{j=1}^t S_j \pmod{2^w}$ be the cumulative noise. $N_t$ is a deterministic function of $X_0$ and does not strictly vanish or remain uncorrelated with $W_t$ (e.g., $N_t \equiv t S_0 \pmod 2$). However, the global bijectivity of $f$ guarantees that the marginal distribution of $L_t$ remains exactly uniform, as established in Theorem 1. $W_t$ and $N_t$ interact to preserve the uniform measure on $\mathbb{Z}_{2^w}$. $\blacksquare$