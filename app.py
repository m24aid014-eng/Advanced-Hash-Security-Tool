import streamlit as st
import hashlib


# --- Rotate right function ---
def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

# --- Standard SHA-256 Sigma functions ---
def Sigma0_std(x): return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)
def Sigma1_std(x): return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)
def sigma0_std(x): return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)
def sigma1_std(x): return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

# --- Modified SHA-256 Sigma functions (co-prime rotations) ---
def Sigma0_mod(x): return rotr(x, 3) ^ rotr(x, 11) ^ rotr(x, 23)
def Sigma1_mod(x): return rotr(x, 5) ^ rotr(x, 14) ^ rotr(x, 27)
def sigma0_mod(x): return rotr(x, 9) ^ rotr(x, 21) ^ (x >> 4)
def sigma1_mod(x): return rotr(x, 13) ^ rotr(x, 20) ^ (x >> 8)

# --- Step 4.1: Constants ---
H = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# --- Step 4.2: Padding ---
def pad_message(message: bytes) -> bytes:
    length = len(message) * 8
    message += b'\x80'
    while (len(message) * 8) % 512 != 448:
        message += b'\x00'
    message += length.to_bytes(8, 'big')
    return message

# --- Message schedule expansion ---
def message_schedule_std(block: bytes):
    W = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = sigma0_std(W[i-15])
        s1 = sigma1_std(W[i-2])
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
    return W

def message_schedule_mod(block: bytes):
    W = [int.from_bytes(block[i:i+4], 'big') for i in range(0, 64, 4)]
    for i in range(16, 64):
        s0 = sigma0_mod(W[i-15])
        s1 = sigma1_mod(W[i-2])
        W.append((W[i-16] + s0 + W[i-7] + s1) & 0xFFFFFFFF)
    return W

# --- SHA-256 Original ---
def sha256_original(message: bytes, rounds=64):
    padded = pad_message(message)
    blocks = [padded[i:i+64] for i in range(0, len(padded), 64)]
    H_values = H.copy()

    for block in blocks:
        W = message_schedule_std(block)
        a, b, c, d, e, f, g, h = H_values

        for i in range(rounds):
            S1 = Sigma1_std(e)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
            S0 = Sigma0_std(a)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

        H_values = [(x + y) & 0xFFFFFFFF for x, y in zip(H_values, [a, b, c, d, e, f, g, h])]

    return ''.join(f'{value:08x}' for value in H_values)

# --- SHA-256 Modified ---
def sha256_modified(message: bytes, rounds=64):
    padded = pad_message(message)
    blocks = [padded[i:i+64] for i in range(0, len(padded), 64)]
    H_values = H.copy()

    for block in blocks:
        W = message_schedule_mod(block)
        a, b, c, d, e, f, g, h = H_values

        for i in range(rounds):
            S1 = Sigma1_mod(e)
            ch = (e & f) ^ (~e & g)
            temp1 = (h + S1 + ch + K[i] + W[i]) & 0xFFFFFFFF
            S0 = Sigma0_mod(a)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF

            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF

        H_values = [(x + y) & 0xFFFFFFFF for x, y in zip(H_values, [a, b, c, d, e, f, g, h])]

    return ''.join(f'{value:08x}' for value in H_values)
#---SHA-512 Original---
import hashlib

def sha512_original(message: bytes, rounds=80):
    return hashlib.sha512(message).hexdigest()


#--- SHA-3 (Keccak) constants and helpers ---

# Initialize Keccak state (5x5 of 64-bit words)
def keccak_state():
    return [0] * 25

# Round constants for Keccak (24 rounds)
ROUND_CONSTANTS = [
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
]
# --- SHA-3 (Keccak) round function ---
def keccak_round(state, rc):
    # θ step
    C = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
    D = [C[(x-1) % 5] ^ ((C[(x+1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) for x in range(5)]
    for x in range(5):
        for y in range(5):
            state[x + 5*y] ^= D[x]

    # ρ and π steps
    x, y = 1, 0
    current = state[1]
    for t in range(24):
        new_x, new_y = y, (2*x + 3*y) % 5
        shift = ((t+1)*(t+2)//2) % 64
        state[new_x + 5*new_y], current = (
            ((current << shift) & 0xFFFFFFFFFFFFFFFF) | (current >> (64 - shift)),
            state[new_x + 5*new_y]
        )
        x, y = new_x, new_y

    # χ step
    for y in range(5):
        row = [state[x + 5*y] for x in range(5)]
        for x in range(5):
            state[x + 5*y] ^= (~row[(x+1)%5]) & row[(x+2)%5]

    # ι step
    state[0] ^= rc

    return state

# --- SHA-3 Original (Keccak) ---
def sha3_original(message: bytes, rounds=24):
    # Initialize state
    state = keccak_state()

    # Absorb message into state (simplified: XOR into first lanes)
    for i in range(0, len(message), 8):
        state[i // 8] ^= int.from_bytes(message[i:i+8].ljust(8, b'\x00'), 'little')

    # Apply rounds (up to 24)
    for i in range(rounds):
        state = keccak_round(state, ROUND_CONSTANTS[i])

    # Squeeze output (take first 256 bits = 32 bytes)
    digest = b''.join(state[i].to_bytes(8, 'little') for i in range(4))
    return digest.hex()

# --- SHA-3 Modified (Keccak with tweaked Chi step) ---
def keccak_round_modified(state, rc):
    # θ step
    C = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
    D = [C[(x-1) % 5] ^ ((C[(x+1) % 5] << 1) & 0xFFFFFFFFFFFFFFFF) for x in range(5)]
    for x in range(5):
        for y in range(5):
            state[x + 5*y] ^= D[x]

    # ρ and π steps
    x, y = 1, 0
    current = state[1]
    for t in range(24):
        new_x, new_y = y, (2*x + 3*y) % 5
        shift = ((t+1)*(t+2)//2) % 64
        state[new_x + 5*new_y], current = (
            ((current << shift) & 0xFFFFFFFFFFFFFFFF) | (current >> (64 - shift)),
            state[new_x + 5*new_y]
        )
        x, y = new_x, new_y

    # χ step (modified: A[x,y] ⊕ (A[x+1,y] ∧ ¬A[x+2,y]))
    for y in range(5):
        row = [state[x + 5*y] for x in range(5)]
        for x in range(5):
            state[x + 5*y] ^= (row[(x+1)%5]) & (~row[(x+2)%5])

    # ι step
    state[0] ^= rc

    return state

# SHA-3  Modified SHA-3 Wrapper
def sha3_modified(message: bytes, rounds=24):
    # Initialize state
    state = keccak_state()

    # Absorb message
    for i in range(0, len(message), 8):
        state[i // 8] ^= int.from_bytes(message[i:i+8].ljust(8, b'\x00'), 'little')

    # Apply modified rounds
    for i in range(rounds):
        state = keccak_round_modified(state, ROUND_CONSTANTS[i])

    # Squeeze output (first 256 bits)
    digest = b''.join(state[i].to_bytes(8, 'little') for i in range(4))
    return digest.hex()

# --- Avalanche Effect Metric ---
def avalanche_effect(hash_func, message: bytes, rounds: int):
    # Compute original digest
    original = hash_func(message, rounds)

    # Flip one bit in the input (lowest bit of first byte)
    flipped = bytearray(message)
    flipped[0] ^= 0x01  # toggle bit
    modified = hash_func(bytes(flipped), rounds)

    # Count bit differences between original and modified digests
    diff = sum(bin(a ^ b).count("1")
               for a, b in zip(bytes.fromhex(original), bytes.fromhex(modified)))

    return original, modified, diff
# --- Entropy Calculation ---


def calculate_entropy(hash_output: str) -> float:
    # Count frequency of each hex character
    freq = {}
    for ch in hash_output:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(hash_output)
    entropy = 0
    for count in freq.values():
        p = count / length
        entropy -= p * log2(p)
    return round(entropy, 3)  # rounded for neat display
# --- Hamming Distance ---
def hamming_distance(hash1: str, hash2: str) -> int:
    # Compare two hex strings bit by bit
    b1 = bin(int(hash1, 16))[2:].zfill(len(hash1) * 4)
    b2 = bin(int(hash2, 16))[2:].zfill(len(hash2) * 4)
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))
# --- Bit Distribution ---
def bit_distribution(hash_output: str) -> float:
    # Convert hex string to binary
    binary_str = bin(int(hash_output, 16))[2:].zfill(len(hash_output) * 4)
    zeros = binary_str.count("0")
    ones = binary_str.count("1")
    total = zeros + ones
    balance = abs(zeros - ones) / total  # imbalance ratio
    return round(100 - (balance * 100), 2)  # percentage balance (closer to 100 = more even)
# --- Performance Measurement ---
import time

def measure_time(func, data, rounds: int) -> float:
    start = time.perf_counter()
    func(data, rounds=rounds)
    end = time.perf_counter()
    return round((end - start) * 1000, 3)  # milliseconds

# --- Collision Resistance Test ---
import random, string

def collision_test(hash_func, rounds=64, trials=5000):
    seen = set()
    collisions = 0
    for _ in range(trials):
        msg = ''.join(random.choices(string.ascii_letters + string.digits, k=16)).encode()
        digest = hash_func(msg, rounds)
        if digest in seen:
            collisions += 1
        else:
            seen.add(digest)
    return collisions, collisions/trials
# --- Preimage Resistance Test ---
import random, string

def preimage_test(hash_func, target_message: bytes, rounds=64, max_attempts=5000):
    target_hash = hash_func(target_message, rounds)
    attempts = 0
    while attempts < max_attempts:
        candidate = ''.join(random.choices(string.ascii_letters + string.digits, k=8)).encode()
        if hash_func(candidate, rounds) == target_hash:
            return True, attempts  # Found a preimage
        attempts += 1
    return False, attempts  # Not found within limit



# --- UI ---
import streamlit as st
import pandas as pd
import numpy as np
from math import log2
import matplotlib.pyplot as plt
import io
from docx import Document

# import your hash functions here

st.title("Advanced Hash Security Tool")

# Sidebar for algorithm selection
st.sidebar.header("Algorithm Selection")

# Multi-select for algorithms
algorithms_selected = st.sidebar.multiselect(
    "Choose algorithms:",
    ["SHA-256 Original", "SHA-256 Modified", "SHA-512 Original","SHA-3 Original", "SHA-3 Modified"]
)

# Dictionary to store slider values
rounds_map = {}

# Show sliders for each selected algorithm
for algo in algorithms_selected:
    if "SHA-256" in algo:
        rounds_map[algo] = st.sidebar.slider(
            f"Rounds for {algo}", min_value=1, max_value=64, value=64
        )
    elif "SHA-3" in algo:
        rounds_map[algo] = st.sidebar.slider(
            f"Rounds for {algo}", min_value=1, max_value=24, value=24
        )
    elif "SHA-512" in algo:
        rounds_map[algo] = st.sidebar.slider(
            f"Rounds for {algo}", min_value=1, max_value=80, value=80
        )

# Input type selection
input_type = st.radio("Choose input type:", ["Text", "File"])
user_text = ""
uploaded_file = None

if input_type == "Text":
    user_text = st.text_input("Enter text:")

elif input_type == "File":
    uploaded_file = st.file_uploader("Upload file", type=["txt", "docx"])
    if uploaded_file is not None:
        if uploaded_file.name.endswith(".txt"):
            # Safely decode plain text
            user_text = uploaded_file.read().decode("utf-8", errors="ignore")

        elif uploaded_file.name.endswith(".docx"):
            # Extract text from Word documents
            doc = Document(uploaded_file)
            user_text = "\n".join([para.text for para in doc.paragraphs])

        else:
            st.error("Unsupported file type. Please upload a .txt or .docx file.")

# Results section

def compute_metrics(user_text, algorithms_selected, rounds_map):
    metrics_data = []
    avalanche_data, entropy_data, time_data, collision_data, preimage_data = {}, {}, {}, {}, {}

    # Input sizes for charts
    input_sizes = [64, 128, 256, 512]

    for algo_name, algo_func in [
        ("SHA-256 Original", sha256_original),
        ("SHA-256 Modified", sha256_modified),
        ("SHA-512 Original", sha512_original),
        ("SHA-3 Original", sha3_original),
        ("SHA-3 Modified", sha3_modified),
    ]:
        if algo_name in algorithms_selected:
            rounds = 80 if "SHA-512" in algo_name else rounds_map.get(algo_name, 64)
            hash_val = algo_func(user_text.encode(), rounds=rounds)

            # Table metrics (single values)
            entropy_val = calculate_entropy(hash_val)
            balance_val = bit_distribution(hash_val)
            exec_time = measure_time(algo_func, user_text.encode(), rounds)
            collisions, coll_prob = collision_test(algo_func, rounds=rounds, trials=1000)
            found, attempts = preimage_test(algo_func, user_text.encode(), rounds=rounds, max_attempts=1000)

            if "SHA-512" not in algo_name:
                orig, mod, diff = avalanche_effect(algo_func, user_text.encode(), rounds)
                hamming_val = hamming_distance(orig, mod)
            else:
                diff, hamming_val = np.nan, np.nan

            metrics_data.append([
                algo_name, rounds, diff, entropy_val, hamming_val,
                balance_val, exec_time, collisions, coll_prob,
                "Found" if found else "Not Found", attempts
            ])

            # --- Chart data (lists) ---
            avalanche_data[algo_name] = []
            entropy_data[algo_name] = []
            time_data[algo_name] = []

            for size in input_sizes:
                test_input = user_text.encode()[:size]

                # Avalanche
                if "SHA-512" not in algo_name:
                    _, _, diff_val = avalanche_effect(algo_func, test_input, rounds)
                    avalanche_data[algo_name].append(diff_val)

                # Entropy
                hash_val = algo_func(test_input, rounds=rounds)
                entropy_data[algo_name].append(calculate_entropy(hash_val))

                # Execution Time
                exec_time_val = measure_time(algo_func, test_input, rounds)
                time_data[algo_name].append(exec_time_val)

            # Resistance metrics
            collision_data[algo_name] = collisions
            preimage_data[algo_name] = attempts

    df = pd.DataFrame(metrics_data, columns=[
        "Algorithm", "Rounds", "Avalanche Bits", "Entropy",
        "Hamming Distance", "Bit Distribution (%)", "Execution Time (ms)",
        "Collisions", "Collision Probability", "Preimage Found", "Attempts"
    ])
    # Ensure numeric columns are numeric (coerce non-numeric placeholders to NaN)
    for col in ["Avalanche Bits", "Hamming Distance", "Rounds", "Execution Time (ms)",
                "Collisions", "Collision Probability", "Attempts"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')
    return df, avalanche_data, entropy_data, time_data, collision_data, preimage_data, input_sizes


if (input_type == "Text" and user_text) or (input_type == "File" and uploaded_file is not None):
    st.subheader("Results")

    # Compute metrics once and reuse everywhere
    df, avalanche_data, entropy_data, time_data, collision_data, preimage_data, input_sizes = compute_metrics(
        user_text, algorithms_selected, rounds_map
    )

    # Now define tabs
    tabHashes, tabMetrics, tabVisuals, tabReports = st.tabs(["Hashes", "Metrics", "Visualizations", "Reports"]) 

    # --- Hashes Tab ---
    with tabHashes:
        st.write("### Hash Outputs")
        col1, col2 = st.columns(2)

        with col1:
            st.write("#### SHA-256 / SHA-512")
            if "SHA-256 Original" in algorithms_selected:
                rounds = rounds_map["SHA-256 Original"]
                st.write(f"SHA-256 Original ({rounds} rounds): `{sha256_original(user_text.encode(), rounds=rounds)}`")

            if "SHA-256 Modified" in algorithms_selected:
                rounds = rounds_map["SHA-256 Modified"]
                st.write(f"SHA-256 Modified ({rounds} rounds): `{sha256_modified(user_text.encode(), rounds=rounds)}`")

            if "SHA-512 Original" in algorithms_selected:
                st.write(f"SHA-512 Original (80 rounds): `{sha512_original(user_text.encode(), rounds=80)}`")

        with col2:
            st.write("#### SHA-3")
            if "SHA-3 Original" in algorithms_selected:
                rounds = rounds_map["SHA-3 Original"]
                st.write(f"SHA-3 Original ({rounds} rounds): `{sha3_original(user_text.encode(), rounds=rounds)}`")

            if "SHA-3 Modified" in algorithms_selected:
                rounds = rounds_map["SHA-3 Modified"]
                st.write(f"SHA-3 Modified ({rounds} rounds): `{sha3_modified(user_text.encode(), rounds=rounds)}`")

    # --- Metrics Tab ---
    with tabMetrics:
        st.write("### Security & Performance Metrics Comparison")

        # Split into two smaller tables
        core_df = df[["Algorithm", "Rounds", "Avalanche Bits", "Entropy",
                      "Hamming Distance", "Bit Distribution (%)", "Execution Time (ms)"]]
        resistance_df = df[["Algorithm", "Collisions", "Collision Probability",
                            "Preimage Found", "Attempts"]]

        st.write("#### Core Security Metrics")
        st.dataframe(core_df, use_container_width=True)

        st.write("#### Resistance Metrics")
        st.dataframe(resistance_df, use_container_width=True)

    # --- Visualizations Tab ---
    with tabVisuals:
        st.write("### Core Charts")

        import matplotlib.pyplot as plt

        # Avalanche Histogram
        st.write("### Figure 7.1: Avalanche Histogram Comparison")
        if avalanche_data:
         fig, ax = plt.subplots()
         for algo, values in avalanche_data.items():
            if len(values) == len(input_sizes):
                ax.plot(input_sizes, values, label=algo)
         ax.set_xlabel("Input Size Scale")
         ax.set_ylabel("Average Bit Flips")
         ax.set_title("Avalanche Histogram Comparison")
         ax.legend()
         plt.tight_layout()
         st.pyplot(fig)
        else:
         st.info("No avalanche data available for the selected algorithms.")

        # Entropy vs Input Size
        st.write("### Figure 7.2: Entropy vs Input Size Comparison")
        if entropy_data:
         fig, ax = plt.subplots()
         for algo, values in entropy_data.items():
            if len(values) == len(input_sizes):
                ax.plot(input_sizes, values, label=algo)
         ax.set_xlabel("Input Size Scale")
         ax.set_ylabel("Entropy")
         ax.set_title("Entropy vs Input Size Comparison")
         ax.legend()
         plt.tight_layout()
         st.pyplot(fig)
        else:
         st.info("No entropy data available for the selected algorithms.")

        # Execution Time Scaling
        st.write("### Figure 7.5: Execution Time Scaling Comparison")
        if time_data:
         fig, ax = plt.subplots()
         for algo, values in time_data.items():
            if len(values) == len(input_sizes):
                ax.plot(input_sizes, values, label=algo)
         ax.set_xlabel("Input Size Scale")
         ax.set_ylabel("Execution Time (ms)")
         ax.set_title("Execution Time Scaling Comparison")
         ax.legend()
         plt.tight_layout()
         st.pyplot(fig)
        else:
         st.info("No execution time data available for the selected algorithms.")

        st.write("### Resistance Charts")

        # Collision Resistance
        st.write("### Figure 7.3: Collision Resistance")
        if collision_data:
         fig, ax = plt.subplots()
         collision_df = pd.DataFrame.from_dict(collision_data, orient="index", columns=["Collisions"])
         ax.bar(collision_df.index, collision_df["Collisions"], color="skyblue")
         ax.set_xlabel("Algorithm Variants")
         ax.set_ylabel("Collisions")
         ax.set_title("Collision Resistance")
         ax.set_xticklabels(collision_df.index, rotation=30, ha="right")
         plt.tight_layout()
         st.pyplot(fig)
        else:
         st.info("No collision data available for the selected algorithms.")

        # Preimage Resistance
        st.write("### Figure 7.4: Preimage Resistance")
        if preimage_data:
         fig, ax = plt.subplots()
         preimage_df = pd.DataFrame.from_dict(preimage_data, orient="index", columns=["Attempts"])
         ax.bar(preimage_df.index, preimage_df["Attempts"], color="lightgreen")
         ax.set_xlabel("Algorithm Variants")
         ax.set_ylabel("Attempts")
         ax.set_title("Preimage Resistance")
         ax.set_xticklabels(preimage_df.index, rotation=30, ha="right")
         plt.tight_layout()
         st.pyplot(fig)
        else:
         st.info("No preimage data available for the selected algorithms.")

    # --- Reports Tab ---
    with tabReports:
     st.write("### Download Reports")

     # Metrics CSVs
     if not df.empty:
        # Core Metrics CSV
        core_df = df[["Algorithm", "Rounds", "Avalanche Bits", "Entropy",
                      "Hamming Distance", "Bit Distribution (%)", "Execution Time (ms)"]]
        core_csv = core_df.to_csv(index=False).encode("utf-8")
        st.download_button("Download Core Metrics as CSV", core_csv,
                           "core_metrics_report.csv", "text/csv")

        # Resistance Metrics CSV
        resistance_df = df[["Algorithm", "Collisions", "Collision Probability",
                            "Preimage Found", "Attempts"]]
        resistance_csv = resistance_df.to_csv(index=False).encode("utf-8")
        st.download_button("Download Resistance Metrics as CSV", resistance_csv,
                           "resistance_metrics_report.csv", "text/csv")

     # Avalanche Chart
     st.write("#### Avalanche Histogram Report")
     fig1, ax1 = plt.subplots()
     for algo, values in avalanche_data.items():
        if values and len(values) == len(input_sizes):
            ax1.plot(input_sizes, values, label=algo)
     ax1.set_xlabel("Input Size Scale")
     ax1.set_ylabel("Average Bit Flips")
     ax1.set_title("Avalanche Histogram Comparison")
     ax1.legend()
     plt.tight_layout()
     buf1 = io.BytesIO()
     fig1.savefig(buf1, format="png")
     st.download_button("Download Avalanche Chart", buf1.getvalue(),
                       "avalanche_comparison.png", "image/png")

     # Entropy Chart
     st.write("#### Entropy vs Input Size Report")
     fig2, ax2 = plt.subplots()
     for algo, values in entropy_data.items():
        if values and len(values) == len(input_sizes):
            ax2.plot(input_sizes, values, label=algo)
     ax2.set_xlabel("Input Size Scale")
     ax2.set_ylabel("Entropy")
     ax2.set_title("Entropy vs Input Size Comparison")
     ax2.legend()
     plt.tight_layout()
     buf2 = io.BytesIO()
     fig2.savefig(buf2, format="png")
     st.download_button("Download Entropy Chart", buf2.getvalue(),
                       "entropy_comparison.png", "image/png")

     # Collision Chart
     st.write("#### Collision Resistance Report")
     if collision_data:
        fig3, ax3 = plt.subplots()
        collision_df = pd.DataFrame.from_dict(collision_data, orient="index", columns=["Collisions"])
        ax3.bar(collision_df.index, collision_df["Collisions"], color="skyblue")
        ax3.set_xlabel("Algorithm Variants")
        ax3.set_ylabel("Collisions")
        ax3.set_title("Collision Resistance")
        ax3.set_xticklabels(collision_df.index, rotation=30, ha="right")
        plt.tight_layout()
        buf3 = io.BytesIO()
        fig3.savefig(buf3, format="png")
        st.download_button("Download Collision Chart", buf3.getvalue(),
                           "collision_comparison.png", "image/png")
     else:
        st.info("No collision data available for the selected algorithms.")

     # Preimage Chart
     st.write("#### Preimage Resistance Report")
     if preimage_data:
        fig4, ax4 = plt.subplots()
        preimage_df = pd.DataFrame.from_dict(preimage_data, orient="index", columns=["Attempts"])
        ax4.bar(preimage_df.index, preimage_df["Attempts"], color="lightgreen")
        ax4.set_xlabel("Algorithm Variants")
        ax4.set_ylabel("Attempts")
        ax4.set_title("Preimage Resistance")
        ax4.set_xticklabels(preimage_df.index, rotation=30, ha="right")
        plt.tight_layout()
        buf4 = io.BytesIO()
        fig4.savefig(buf4, format="png")
        st.download_button("Download Preimage Chart", buf4.getvalue(),
                           "preimage_comparison.png", "image/png")
     else:
        st.info("No preimage data available for the selected algorithms.")

     # Execution Time Chart
     st.write("#### Execution Time Scaling Report")
     fig5, ax5 = plt.subplots()
     for algo, values in time_data.items():
        if values and len(values) == len(input_sizes):
            ax5.plot(input_sizes, values, label=algo)
     ax5.set_xlabel("Input Size Scale")
     ax5.set_ylabel("Execution Time (ms)")
     ax5.set_title("Execution Time Scaling Comparison")
     ax5.legend()
     plt.tight_layout()
     buf5 = io.BytesIO()
     fig5.savefig(buf5, format="png")
     st.download_button("Download Execution Time Chart", buf5.getvalue(),
                       "execution_time_comparison.png", "image/png")
